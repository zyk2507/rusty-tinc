use super::*;

#[test]
fn runtime_forwarded_sptps_udp_relay_applies_next_hop_tcp_fallback_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    let relay_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay runtime listener: {error}"),
    };
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    beta_socket
        .udp
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();
    let alpha_addr = alpha_socket.info().address;
    let relay_addr = relay_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let relay_server = config_tree(&[("Name", "relay"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let relay_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let relay_beta_host = config_tree(&[("Address", &beta_address), ("TCPOnly", "yes")]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);

    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
    )
    .unwrap();
    let relay_config = RuntimeConfig::from_config_tree_with_hosts(
        &relay_server,
        [("alpha", &relay_alpha_host), ("beta", &relay_beta_host)],
    )
    .unwrap();
    let beta_config =
        RuntimeConfig::from_config_tree_with_hosts(&beta_server, [("alpha", &beta_alpha_host)])
            .unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let relay_keys = RuntimeKeys {
        private_key: Some(relay_key.clone()),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key.clone()),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", relay_key, beta_key)
    else {
        return;
    };
    beta_connection.id = 1;
    beta_connection.options = ((PROT_MINOR as u32) << 24) | OPTION_TCPONLY;

    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut relay = RuntimeDaemonState::new(vec![relay_socket], &relay_config, relay_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);
    relay.meta_connections.push(beta_connection);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    let options = (PROT_MINOR as u32) << 24;
    {
        let relay_node = alpha.state.graph.node_mut("relay").unwrap();
        relay_node.status.reachable = true;
        relay_node.options = options;
        relay_node.min_mtu = DEFAULT_MTU;
    }
    {
        let beta_node = alpha.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.options = options;
        beta_node.route.next_hop = Some("relay".to_owned());
        beta_node.route.via = Some("relay".to_owned());
        beta_node.route.distance = Some(2);
        beta_node.route.weighted_distance = Some(2);
    }
    {
        let beta_node = relay.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.options = options | OPTION_TCPONLY;
        beta_node.min_mtu = DEFAULT_MTU;
        beta_node.route.next_hop = Some("beta".to_owned());
        beta_node.route.via = Some("beta".to_owned());
        beta_node.route.distance = Some(1);
        beta_node.route.weighted_distance = Some(1);
    }

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    relay.poll_once().unwrap();

    let events = flush_then_read_meta_events_until(
        &mut relay,
        &mut beta_stream,
        &mut beta_driver,
        is_sptps_tcp_packet,
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, MetaConnectionEvent::TcpPacket(_)))
    );
    let tcp_payload = events
        .iter()
        .find_map(|event| match event {
            MetaConnectionEvent::SptpsPacket(payload) => Some(payload.as_slice()),
            _ => None,
        })
        .expect("expected forwarded SPTPS TCP packet fallback for TCPOnly next hop");
    let envelope = RelayEnvelope::decode(tcp_payload).unwrap();
    assert_eq!(NodeId::from_name("beta"), envelope.destination);
    assert_eq!(NodeId::from_name("alpha"), envelope.source);
    let record = beta
        .packet_codec
        .decode_record("alpha", tcp_payload)
        .unwrap();
    assert_eq!(SPTPS_UDP_ROUTER_PACKET_TYPE, record.record_type);
    assert_eq!(test_ipv4_payload([10, 2, 0, 42]), record.payload);

    let mut buffer = [0u8; 4096];
    match beta.listen_sockets[0].udp.recv_from(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok((len, source)) => {
            panic!("unexpected UDP relay datagram after TCP fallback to {source}: len={len}")
        }
        Err(error) => panic!("failed checking beta UDP socket: {error}"),
    }
}

#[test]
fn runtime_forwarded_sptps_udp_relay_uses_next_hop_when_static_via_mtu_is_too_small_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let relay_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay runtime listener: {error}"),
    };
    let next_hop_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind next-hop UDP receiver: {error}"),
    };
    let static_via_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind static-via UDP receiver: {error}"),
    };
    next_hop_receiver
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    static_via_receiver
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();

    let relay_addr = relay_socket.info().address;
    let next_hop_addr = next_hop_receiver.local_addr().unwrap();
    let static_via_addr = static_via_receiver.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let alpha_beta_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let relay_server = config_tree(&[("Name", "relay"), ("AddressFamily", "IPv4")]);
    let next_hop_address = format!("{} {}", next_hop_addr.ip(), next_hop_addr.port());
    let static_via_address = format!("{} {}", static_via_addr.ip(), static_via_addr.port());
    let relay_next_hop_host = config_tree(&[("Address", &next_hop_address)]);
    let relay_static_via_host = config_tree(&[("Address", &static_via_address)]);
    let relay_beta_host = config_tree(&[]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);

    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
    )
    .unwrap();
    let relay_config = RuntimeConfig::from_config_tree_with_hosts(
        &relay_server,
        [
            ("beta", &relay_beta_host),
            ("next-hop", &relay_next_hop_host),
            ("static-via", &relay_static_via_host),
        ],
    )
    .unwrap();
    let beta_config = RuntimeConfig::from_config_tree(&beta_server).unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let relay_keys = RuntimeKeys {
        private_key: Some(relay_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &alpha_config, alpha_keys);
    let mut relay = RuntimeDaemonState::new(vec![relay_socket], &relay_config, relay_keys);
    let mut beta = RuntimeDaemonState::new(Vec::new(), &beta_config, beta_keys);

    alpha.state.graph.ensure_node("beta");
    *alpha.packet_codec.ids_mut() = NodeIdTable::from_network_state(&alpha.state);
    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    let record = alpha
        .packet_codec
        .encode_relayed(
            "beta",
            &VpnPacket::new(test_ipv4_ethernet_packet([10, 2, 0, 42])).unwrap(),
        )
        .unwrap();
    let options = (PROT_MINOR as u32) << 24;
    {
        let beta_node = relay.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.options = options;
        beta_node.route.next_hop = Some("next-hop".to_owned());
        beta_node.route.via = Some("static-via".to_owned());
        beta_node.route.distance = Some(2);
        beta_node.route.weighted_distance = Some(2);
    }
    {
        let next_hop = relay.state.graph.node_mut("next-hop").unwrap();
        next_hop.status.reachable = true;
        next_hop.options = options;
        next_hop.min_mtu = DEFAULT_MTU;
    }
    {
        let static_via = relay.state.graph.node_mut("static-via").unwrap();
        static_via.status.reachable = true;
        static_via.options = options;
        static_via.min_mtu = test_ipv4_payload([10, 2, 0, 42]).len() - 1;
    }

    relay
        .forward_sptps_tcp_payload("beta", "alpha", &record)
        .unwrap();

    let mut buffer = [0u8; 4096];
    let (len, source) = next_hop_receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(relay.listen_sockets[0].info().address, source);
    let envelope = RelayEnvelope::decode(&buffer[..len]).unwrap();
    assert_eq!(NodeId::from_name("beta"), envelope.destination);
    assert_eq!(NodeId::from_name("alpha"), envelope.source);

    match static_via_receiver.recv_from(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok((len, source)) => {
            panic!("unexpected UDP relay datagram to static via {source}: len={len}")
        }
        Err(error) => panic!("failed checking static-via UDP socket: {error}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_forwarded_sptps_udp_relay_emsgsize_reduces_relay_mtu_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let relay_socket = match test_runtime_ipv6_listen_socket_with_mtu(1280) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping SPTPS relay EMSGSIZE MTU test: {error}");
            return;
        }
    };
    let beta_receiver = match UdpSocket::bind("[::1]:0") {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping SPTPS relay EMSGSIZE MTU test: {error}");
            return;
        }
    };
    beta_receiver.set_nonblocking(true).unwrap();

    let beta_addr = beta_receiver.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();
    let alpha_config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let relay_server = config_tree(&[("Name", "relay"), ("AddressFamily", "IPv6")]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let relay_beta_host = config_tree(&[("Address", &beta_address)]);
    let relay_config =
        RuntimeConfig::from_config_tree_with_hosts(&relay_server, [("beta", &relay_beta_host)])
            .unwrap();
    let beta_config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "beta")])).unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let relay_keys = RuntimeKeys {
        private_key: Some(relay_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &alpha_config, alpha_keys);
    let mut relay = RuntimeDaemonState::new(vec![relay_socket], &relay_config, relay_keys);
    let mut beta = RuntimeDaemonState::new(Vec::new(), &beta_config, beta_keys);

    alpha.state.graph.ensure_node("beta");
    *alpha.packet_codec.ids_mut() = NodeIdTable::from_network_state(&alpha.state);
    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    let mut packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    packet.resize(DEFAULT_MTU, 0x55);
    let record = alpha
        .packet_codec
        .encode_relayed("beta", &VpnPacket::new(packet).unwrap())
        .unwrap();
    let raw_record = RelayEnvelope::decode(&record).unwrap().payload;
    let owner_packet_len = raw_record.len().saturating_sub(SPTPS_DATAGRAM_OVERHEAD);
    let options = (PROT_MINOR as u32) << 24;
    {
        let beta_node = relay.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.options = options;
        beta_node.min_mtu = DEFAULT_MTU;
        beta_node.max_mtu = DEFAULT_MTU;
        beta_node.mtu = DEFAULT_MTU;
        beta_node.route.next_hop = Some("beta".to_owned());
        beta_node.route.via = Some("beta".to_owned());
        beta_node.route.distance = Some(1);
        beta_node.route.weighted_distance = Some(1);
    }

    relay
        .forward_sptps_relay_record("beta", "alpha", &raw_record)
        .unwrap();

    let beta = relay.state.graph.node("beta").unwrap();
    assert_eq!(
        owner_packet_len - 1,
        beta.max_mtu,
        "C send_sptps_data() reduces relay MTU to origlen - 1 on EMSGSIZE"
    );
    assert_eq!(owner_packet_len - 1, beta.mtu);
    assert_eq!(
        -1, beta.mtu_probes,
        "C try_fix_mtu() fixes MTU when reducing below the current minmtu"
    );

    let mut buffer = [0u8; 4096];
    assert!(matches!(
        beta_receiver.recv_from(&mut buffer),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
}

#[test]
fn runtime_legacy_udp_probe_waits_for_outgoing_key_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    let beta_addr = beta_socket.info().address;
    let server = config_tree(&[("Name", "alpha"), ("ExperimentalProtocol", "no")]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let beta_host = config_tree(&[("Address", &beta_address)]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: None,
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &config, keys);
    let beta = alpha.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());

    alpha
        .generate_legacy_answer_key_message_with("beta", |bytes| {
            bytes.fill(0x42);
            Ok(())
        })
        .unwrap();
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key_in);
    assert!(!alpha.state.graph.node("beta").unwrap().status.valid_key);

    alpha.try_udp_for_peer("beta").unwrap();

    assert!(!alpha.state.graph.node("beta").unwrap().status.ping_sent);
    assert!(!alpha.udp_probe.contains_key("beta"));
}

#[test]
fn runtime_sptps_direct_over_min_mtu_uses_plain_meta_tcp_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    alpha_socket
        .udp
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let beta_server = config_tree(&[
        ("Name", "beta"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address), ("Subnet", "10.1.0.0/16")]);
    let alpha_config =
        RuntimeConfig::from_config_tree_with_hosts(&alpha_server, [("beta", &alpha_beta_host)])
            .unwrap();
    let beta_config =
        RuntimeConfig::from_config_tree_with_hosts(&beta_server, [("alpha", &beta_alpha_host)])
            .unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key.clone()),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((_stale_stream, _stale_driver, mut stale_beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        return;
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    stale_beta_connection.id = 1;
    stale_beta_connection.close_requested = true;
    stale_beta_connection.options = (PROT_MINOR as u32) << 24;
    alpha.meta_connections.push(stale_beta_connection);

    beta_connection.id = 2;
    beta_connection.options = (PROT_MINOR as u32) << 24;
    beta_connection.edge_peer = Some("beta".to_owned());
    alpha.local_edge_connections.insert("beta".to_owned(), 2);
    alpha.meta_connections.push(beta_connection);

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    {
        let beta_node = alpha.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.options = (PROT_MINOR as u32) << 24;
        beta_node.min_mtu = packet.len() - 1;
        beta_node.route.next_hop = Some("beta".to_owned());
        beta_node.route.via = Some("beta".to_owned());
        beta_node.route.distance = Some(1);
        beta_node.route.weighted_distance = Some(1);
    }

    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let events = flush_then_read_meta_events_until(
        &mut alpha,
        &mut beta_stream,
        &mut beta_driver,
        |event| matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet),
    );

    assert!(events.iter().any(|event| {
        matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
    }));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, MetaConnectionEvent::SptpsPacket(_)))
    );
    let mut buffer = [0u8; 4096];
    match alpha.listen_sockets[0].udp.recv_from(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok((len, source)) => panic!("unexpected UDP datagram to {source}: len={len}"),
        Err(error) => panic!("failed checking direct UDP socket: {error}"),
    }
}

#[test]
fn runtime_sptps_direct_uses_static_via_udp_when_packet_fits_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    alpha_socket
        .udp
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    let static_via_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind static-via UDP receiver: {error}"),
    };
    static_via_receiver
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let static_via_addr = static_via_receiver.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let static_via_address = format!("{} {}", static_via_addr.ip(), static_via_addr.port());
    let alpha_static_via_host = config_tree(&[("Address", &static_via_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address), ("Subnet", "10.1.0.0/16")]);
    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [
            ("beta", &alpha_beta_host),
            ("static-via", &alpha_static_via_host),
        ],
    )
    .unwrap();
    let beta_config =
        RuntimeConfig::from_config_tree_with_hosts(&beta_server, [("alpha", &beta_alpha_host)])
            .unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key.clone()),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    beta_connection.id = 1;
    beta_connection.options = (PROT_MINOR as u32) << 24;
    alpha.meta_connections.push(beta_connection);

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    {
        let beta_node = alpha.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.options = (PROT_MINOR as u32) << 24;
        beta_node.min_mtu = DEFAULT_MTU;
        beta_node.route.next_hop = Some("beta".to_owned());
        beta_node.route.via = Some("static-via".to_owned());
        beta_node.route.distance = Some(1);
        beta_node.route.weighted_distance = Some(1);
    }
    {
        let static_via = alpha.state.graph.node_mut("static-via").unwrap();
        static_via.status.reachable = true;
        static_via.status.sptps = true;
        static_via.options = (PROT_MINOR as u32) << 24;
        static_via.min_mtu = test_ipv4_payload([10, 2, 0, 42]).len();
    }

    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        matches!(event, MetaConnectionEvent::TcpPacket(_))
    });
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, MetaConnectionEvent::TcpPacket(_)))
    );

    let mut buffer = [0u8; 4096];
    let (len, source) = static_via_receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(alpha.listen_sockets[0].info().address, source);
    let envelope = RelayEnvelope::decode(&buffer[..len]).unwrap();
    assert_eq!(NodeId::from_name("beta"), envelope.destination);
    assert_eq!(NodeId::from_name("alpha"), envelope.source);
    let record = beta
        .packet_codec
        .decode_record("alpha", &buffer[..len])
        .unwrap();
    assert_eq!(SPTPS_UDP_ROUTER_PACKET_TYPE, record.record_type);
    assert_eq!(test_ipv4_payload([10, 2, 0, 42]), record.payload);
    assert_eq!(
        VpnPacket::new(test_ipv4_router_packet([10, 2, 0, 42])).unwrap(),
        sptps_packet_from_payload(record.record_type, record.payload).unwrap()
    );
}

#[test]
fn runtime_sptps_direct_uses_next_hop_when_static_via_mtu_is_too_small_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    let next_hop_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind next-hop UDP receiver: {error}"),
    };
    let static_via_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind static-via UDP receiver: {error}"),
    };
    next_hop_receiver
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    static_via_receiver
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();
    let alpha_addr = alpha_socket.info().address;
    let next_hop_addr = next_hop_receiver.local_addr().unwrap();
    let static_via_addr = static_via_receiver.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let next_hop_address = format!("{} {}", next_hop_addr.ip(), next_hop_addr.port());
    let static_via_address = format!("{} {}", static_via_addr.ip(), static_via_addr.port());
    let alpha_beta_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let alpha_next_hop_host = config_tree(&[("Address", &next_hop_address)]);
    let alpha_static_via_host = config_tree(&[("Address", &static_via_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address), ("Subnet", "10.1.0.0/16")]);
    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [
            ("beta", &alpha_beta_host),
            ("next-hop", &alpha_next_hop_host),
            ("static-via", &alpha_static_via_host),
        ],
    )
    .unwrap();
    let beta_config =
        RuntimeConfig::from_config_tree_with_hosts(&beta_server, [("alpha", &beta_alpha_host)])
            .unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(Vec::new(), &beta_config, beta_keys);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    let payload_len = test_ipv4_payload([10, 2, 0, 42]).len();
    {
        let beta_node = alpha.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.options = (PROT_MINOR as u32) << 24;
        beta_node.min_mtu = DEFAULT_MTU;
        beta_node.route.next_hop = Some("next-hop".to_owned());
        beta_node.route.via = Some("static-via".to_owned());
        beta_node.route.distance = Some(3);
        beta_node.route.weighted_distance = Some(3);
    }
    {
        let next_hop = alpha.state.graph.node_mut("next-hop").unwrap();
        next_hop.status.reachable = true;
        next_hop.status.sptps = true;
        next_hop.options = (PROT_MINOR as u32) << 24;
        next_hop.min_mtu = DEFAULT_MTU;
        next_hop.route.next_hop = Some("next-hop".to_owned());
        next_hop.route.via = Some("next-hop".to_owned());
    }
    {
        let static_via = alpha.state.graph.node_mut("static-via").unwrap();
        static_via.status.reachable = true;
        static_via.status.sptps = true;
        static_via.options = (PROT_MINOR as u32) << 24;
        static_via.min_mtu = payload_len - 1;
        static_via.route.next_hop = Some("static-via".to_owned());
        static_via.route.via = Some("static-via".to_owned());
    }

    alpha
        .push_device_packet(VpnPacket::new(packet).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let mut buffer = [0u8; 4096];
    let (len, source) = next_hop_receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(alpha.listen_sockets[0].info().address, source);
    let envelope = RelayEnvelope::decode(&buffer[..len]).unwrap();
    assert_eq!(NodeId::from_name("beta"), envelope.destination);
    assert_eq!(NodeId::from_name("alpha"), envelope.source);
    let record = beta
        .packet_codec
        .decode_record("alpha", &buffer[..len])
        .unwrap();
    assert_eq!(SPTPS_UDP_ROUTER_PACKET_TYPE, record.record_type);
    assert_eq!(test_ipv4_payload([10, 2, 0, 42]), record.payload);

    match static_via_receiver.recv_from(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok((len, source)) => {
            panic!("unexpected UDP datagram to static via {source}: len={len}")
        }
        Err(error) => panic!("failed checking static-via UDP socket: {error}"),
    }
}

#[test]
fn runtime_sptps_direct_over_min_mtu_uses_plain_meta_tcp_even_with_static_via_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    alpha_socket
        .udp
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    let static_via_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind static-via UDP receiver: {error}"),
    };
    static_via_receiver
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let static_via_addr = static_via_receiver.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let static_via_address = format!("{} {}", static_via_addr.ip(), static_via_addr.port());
    let alpha_static_via_host = config_tree(&[("Address", &static_via_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address), ("Subnet", "10.1.0.0/16")]);
    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [
            ("beta", &alpha_beta_host),
            ("static-via", &alpha_static_via_host),
        ],
    )
    .unwrap();
    let beta_config =
        RuntimeConfig::from_config_tree_with_hosts(&beta_server, [("alpha", &beta_alpha_host)])
            .unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key.clone()),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    beta_connection.id = 1;
    beta_connection.options = (PROT_MINOR as u32) << 24;
    alpha.meta_connections.push(beta_connection);

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    {
        let beta_node = alpha.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.options = (PROT_MINOR as u32) << 24;
        beta_node.min_mtu = packet.len() - 1;
        beta_node.route.next_hop = Some("beta".to_owned());
        beta_node.route.via = Some("static-via".to_owned());
        beta_node.route.distance = Some(1);
        beta_node.route.weighted_distance = Some(1);
    }
    {
        let static_via = alpha.state.graph.node_mut("static-via").unwrap();
        static_via.status.reachable = true;
        static_via.status.sptps = true;
        static_via.options = (PROT_MINOR as u32) << 24;
        static_via.min_mtu = test_ipv4_payload([10, 2, 0, 42]).len();
    }

    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let events = flush_then_read_meta_events_until(
        &mut alpha,
        &mut beta_stream,
        &mut beta_driver,
        |event| matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet),
    );
    assert!(events.iter().any(|event| {
        matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
    }));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, MetaConnectionEvent::SptpsPacket(_)))
    );

    let mut buffer = [0u8; 4096];
    match static_via_receiver.recv_from(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok((len, source)) => {
            panic!("unexpected UDP datagram to static via {source}: len={len}")
        }
        Err(error) => panic!("failed checking static-via UDP socket: {error}"),
    }
}

#[cfg(unix)]
#[test]
fn systemd_two_listen_fds_are_reused_and_get_matching_udp_sockets_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let first_listener = bind_systemd_test_tcp_listener(2);
    let second_listener = bind_systemd_test_tcp_listener(3);
    let first_address = first_listener.local_addr().unwrap();
    let second_address = second_listener.local_addr().unwrap();
    let first_fd = unsafe { libc::fcntl(first_listener.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    assert!(first_fd >= 0, "failed to duplicate first listener fd");
    let second_fd = unsafe {
        libc::fcntl(
            second_listener.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            first_fd + 1,
        )
    };
    assert_eq!(first_fd + 1, second_fd, "systemd fds must be consecutive");
    drop(first_listener);
    drop(second_listener);

    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
    ]))
    .unwrap();
    let sockets = bind_runtime_listeners_from_systemd_fds(&config, 2, first_fd).unwrap();

    assert_eq!(2, sockets.len());
    assert_eq!(first_address, sockets[0].info().address);
    assert_eq!(second_address, sockets[1].info().address);

    assert_systemd_socket_pair_accepts_tcp_and_udp(&sockets[0], first_address, b"a");
    assert_systemd_socket_pair_accepts_tcp_and_udp(&sockets[1], second_address, b"b");
}
