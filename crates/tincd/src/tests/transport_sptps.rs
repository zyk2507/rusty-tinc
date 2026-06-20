use super::*;

#[test]
fn runtime_drops_udp_datagrams_without_secure_state_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-udp-no-key-drop");
    let sender = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind UDP sender: {error}"),
    };
    let sender_addr = sender.local_addr().unwrap();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!("Address = {} {}\n", sender_addr.ip(), sender_addr.port()),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let sockets = match bind_runtime_listeners(&config) {
        Ok(sockets) => sockets,
        Err(TincdError::ListenIo(error))
            if error.contains("Operation not permitted") || error.contains("Permission denied") =>
        {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind runtime UDP listener: {error}"),
    };
    let target = sockets[0].info().address;
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);
    runtime.set_debug_level(DEBUG_TRAFFIC);
    runtime
        .state
        .graph
        .node_mut("beta")
        .unwrap()
        .status
        .reachable = true;

    let packet = test_ipv4_ethernet_packet([10, 0, 0, 42]);
    sender.send_to(&packet, target).unwrap();
    runtime.poll_once().unwrap();

    assert!(runtime.device_writes().is_empty());
    assert!(runtime.pcap_subscribers.is_empty());
    assert_eq!(
        Some(&1),
        runtime.packet_diag_counts.get("udp-drop:no-key:beta")
    );

    let mut stop = false;
    let traffic =
        handle_control_request_line("18 13", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    assert!(traffic.contains("18 13 beta 0 0 0 0\n"));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_unkeyed_sptps_udp_from_identified_peer_requests_key_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let listen_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    let sender = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta UDP sender: {error}"),
    };
    let target = listen_socket.info().address;
    let sender_addr = sender.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_server = config_tree(&[("Name", "alpha"), ("AddressFamily", "IPv4")]);
    let beta_address = format!("{} {}", sender_addr.ip(), sender_addr.port());
    let beta_host = config_tree(&[("Address", &beta_address)]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&alpha_server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(vec![listen_socket], &config, keys);
    runtime.set_debug_level(DEBUG_TRAFFIC);
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    {
        let beta = runtime.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = true;
        beta.options = (PROT_MINOR as u32) << 24;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
    }

    let datagram = RelayEnvelope::direct(NodeId::from_name("beta"), b"no-sptps-state").encode();
    sender.send_to(&datagram, target).unwrap();
    runtime.poll_once().unwrap();

    assert!(runtime.device_writes().is_empty());
    assert_eq!(
        Some(&1),
        runtime.packet_diag_counts.get("udp-drop:no-key:beta")
    );
    assert!(
        runtime
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .waiting_for_key,
        "C receive_udppacket() calls send_req_key() after an identified SPTPS peer sends UDP before keys exist"
    );
    assert!(runtime.sptps_last_req_key.contains_key("beta"));
    runtime.flush_meta_outputs().unwrap();
    let events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        is_sptps_initial_req_key(event, "alpha", "beta")
    });
    assert!(
        events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta")),
        "unkeyed SPTPS UDP from an identified peer should trigger C-style REQ_KEY"
    );

    let written_after_first = runtime.meta_connections[0].bytes_written;
    sender.send_to(&datagram, target).unwrap();
    runtime.poll_once().unwrap();
    assert_eq!(
        written_after_first, runtime.meta_connections[0].bytes_written,
        "C receive_udppacket() does not send another REQ_KEY while waitingforkey is set"
    );

    let mut short = vec![0; RELAY_HEADER_LEN - 1];
    runtime.sptps_last_req_key.clear();
    runtime
        .state
        .graph
        .node_mut("beta")
        .unwrap()
        .status
        .waiting_for_key = false;
    sender.send_to(&short, target).unwrap();
    runtime.poll_once().unwrap();
    assert!(
        !runtime.sptps_last_req_key.contains_key("beta"),
        "C handle_incoming_vpn_packet() rejects pre-17.4 SPTPS UDP packets shorter than the relay header before send_req_key()"
    );
    let destination = NodeId::from_name("gamma");
    let source = NodeId::from_name("beta");
    let node_id_len = destination.as_bytes().len();
    short.resize(RELAY_HEADER_LEN, 0);
    short[..node_id_len].copy_from_slice(destination.as_bytes());
    short[node_id_len..RELAY_HEADER_LEN].copy_from_slice(source.as_bytes());
    sender.send_to(&short, target).unwrap();
    runtime.poll_once().unwrap();
    assert!(
        !runtime.sptps_last_req_key.contains_key("beta"),
        "C only reaches receive_udppacket() for direct SPTPS UDP packets to myself"
    );
}

#[test]
fn runtime_relayed_unkeyed_sptps_udp_to_local_requests_origin_key_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let listen_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    let relay_sender = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay UDP sender: {error}"),
    };
    let target = listen_socket.info().address;
    let relay_addr = relay_sender.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let alpha_server = config_tree(&[("Name", "alpha"), ("AddressFamily", "IPv4")]);
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let beta_host = config_tree(&[]);
    let relay_host = config_tree(&[("Address", &relay_address)]);
    let config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &beta_host), ("relay", &relay_host)],
    )
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("relay".to_owned(), relay_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(vec![listen_socket], &config, keys);
    runtime.set_debug_level(DEBUG_TRAFFIC);
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    let options = (PROT_MINOR as u32) << 24;
    {
        let relay = runtime.state.graph.node_mut("relay").unwrap();
        relay.status.reachable = true;
        relay.status.sptps = true;
        relay.status.udp_confirmed = true;
        relay.options = options;
        relay.route.next_hop = Some("relay".to_owned());
        relay.route.via = Some("relay".to_owned());
    }
    {
        let beta = runtime.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = true;
        beta.options = options;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
    }
    *runtime.packet_codec.ids_mut() = NodeIdTable::from_network_state(&runtime.state);

    let datagram = RelayEnvelope::relayed(
        NodeId::from_name("alpha"),
        NodeId::from_name("beta"),
        b"no-sptps-state",
    )
    .encode();
    relay_sender.send_to(&datagram, target).unwrap();
    runtime.poll_once().unwrap();

    assert_eq!(
        Some(&1),
        runtime.packet_diag_counts.get("udp-drop:no-key:beta")
    );
    assert!(
        runtime
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .waiting_for_key,
        "C receive_udppacket(from) triggers send_req_key(from) after a relayed-to-local SPTPS UDP packet without keys"
    );
    assert!(runtime.sptps_last_req_key.contains_key("beta"));
    runtime.flush_meta_outputs().unwrap();
    let events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        is_sptps_initial_req_key(event, "alpha", "beta")
    });
    assert!(
        events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta")),
        "relayed-to-local unkeyed SPTPS UDP should trigger C-style REQ_KEY to the origin"
    );

    let written_after_first = runtime.meta_connections[0].bytes_written;
    relay_sender.send_to(&datagram, target).unwrap();
    runtime.poll_once().unwrap();
    assert_eq!(
        written_after_first, runtime.meta_connections[0].bytes_written,
        "C receive_udppacket() does not send another REQ_KEY while origin waitingforkey is set"
    );
}

#[test]
fn runtime_routes_udp_packets_through_established_sptps_sessions() {
    tinc_test_support::assert_can_create_netns();
    let alpha_confbase = temp_confbase("runtime-sptps-alpha");
    let beta_confbase = temp_confbase("runtime-sptps-beta");
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(alpha_confbase).unwrap();
            fs::remove_dir_all(beta_confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(alpha_confbase).unwrap();
            fs::remove_dir_all(beta_confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    fs::write(
        alpha_confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nStrictSubnets = yes\nReplayWindow = 7\n",
    )
    .unwrap();
    fs::write(
        alpha_confbase.join("hosts").join("alpha"),
        format!(
            "Subnet = 10.1.0.0/16\nEd25519PublicKey = {}\n",
            alpha_public_key.to_base64()
        ),
    )
    .unwrap();
    fs::write(
        alpha_confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nSubnet = 10.2.0.0/16\nEd25519PublicKey = {}\n",
            beta_addr.ip(),
            beta_addr.port(),
            beta_public_key.to_base64()
        ),
    )
    .unwrap();
    fs::write(
        beta_confbase.join("tinc.conf"),
        "Name = beta\nAddressFamily = IPv4\nStrictSubnets = yes\nReplayWindow = 7\n",
    )
    .unwrap();
    fs::write(
        beta_confbase.join("hosts").join("beta"),
        format!(
            "Subnet = 10.2.0.0/16\nEd25519PublicKey = {}\n",
            beta_public_key.to_base64()
        ),
    )
    .unwrap();
    fs::write(
        beta_confbase.join("hosts").join("alpha"),
        format!(
            "Address = {} {}\nSubnet = 10.1.0.0/16\nEd25519PublicKey = {}\n",
            alpha_addr.ip(),
            alpha_addr.port(),
            alpha_public_key.to_base64()
        ),
    )
    .unwrap();

    let mut alpha_options = TincdOptions::new("tincd".to_owned());
    alpha_options.confbase = Some(alpha_confbase.clone());
    let alpha_config = load_runtime_config(&alpha_options).unwrap();
    let mut beta_options = TincdOptions::new("tincd".to_owned());
    beta_options.confbase = Some(beta_confbase.clone());
    let beta_config = load_runtime_config(&beta_options).unwrap();
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
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    alpha.state.graph.node_mut("beta").unwrap().status.reachable = true;
    beta.state.graph.node_mut("alpha").unwrap().status.reachable = true;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    assert_eq!(
        7,
        alpha
            .packet_codec
            .peer("beta")
            .unwrap()
            .codec()
            .in_replay()
            .window_bytes()
    );
    assert_eq!(
        7,
        beta.packet_codec
            .peer("alpha")
            .unwrap()
            .codec()
            .in_replay()
            .window_bytes()
    );

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    beta.poll_once().unwrap();

    assert_eq!(1, beta.device_writes().len());
    assert_eq!(
        test_ipv4_router_packet([10, 2, 0, 42]),
        beta.device_writes()[0].data
    );

    let alpha_traffic =
        handle_control_request_line("18 13", &mut false, Some(&alpha_config), Some(&mut alpha))
            .unwrap();
    assert!(alpha_traffic.contains(&format!("18 13 beta 0 0 1 {}\n", packet.len())));
    let beta_traffic =
        handle_control_request_line("18 13", &mut false, Some(&beta_config), Some(&mut beta))
            .unwrap();
    assert!(beta_traffic.contains(&format!("18 13 alpha 1 {} 0 0\n", packet.len())));

    fs::remove_dir_all(alpha_confbase).unwrap();
    fs::remove_dir_all(beta_confbase).unwrap();
}

#[test]
fn runtime_accepts_direct_sptps_udp_from_unknown_address_via_source_id_like_tinc() {
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
    let sender = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alternate UDP sender: {error}"),
    };
    sender
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let sender_addr = sender.local_addr().unwrap();
    assert_ne!(alpha_addr, sender_addr);

    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();
    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
        ("Mode", "switch"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let beta_self_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let beta_server = config_tree(&[
        ("Name", "beta"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
        ("Mode", "switch"),
    ]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address), ("Subnet", "10.1.0.0/16")]);
    let alpha_config =
        RuntimeConfig::from_config_tree_with_hosts(&alpha_server, [("beta", &alpha_beta_host)])
            .unwrap();
    let beta_config = RuntimeConfig::from_config_tree_with_hosts(
        &beta_server,
        [("beta", &beta_self_host), ("alpha", &beta_alpha_host)],
    )
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
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    alpha.state.graph.node_mut("beta").unwrap().status.reachable = true;
    beta.state.graph.node_mut("alpha").unwrap().status.reachable = true;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    assert!(beta.udp_source_node(sender_addr).is_none());

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    let datagram = alpha
        .packet_codec
        .encode_direct("beta", &VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    sender.send_to(&datagram, beta_addr).unwrap();
    beta.poll_once().unwrap();

    assert_eq!(Some(&0), beta.udp_socket_by_peer.get("alpha"));
    assert_eq!(1, beta.device_writes().len());
    assert_eq!(packet, beta.device_writes()[0].data);
    assert_eq!(1, beta.traffic["alpha"].in_packets);
    assert_eq!(packet.len() as u64, beta.traffic["alpha"].in_bytes);
}

#[test]
fn runtime_updates_direct_udp_source_address_after_authenticated_packet_like_tinc() {
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
    let sender = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alternate UDP sender: {error}"),
    };
    sender
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    alpha_socket.udp.set_nonblocking(true).unwrap();
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let sender_addr = sender.local_addr().unwrap();
    assert_ne!(alpha_addr, sender_addr);

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
    let beta_self_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
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
    let beta_config = RuntimeConfig::from_config_tree_with_hosts(
        &beta_server,
        [("beta", &beta_self_host), ("alpha", &beta_alpha_host)],
    )
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
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    alpha.state.graph.node_mut("beta").unwrap().status.reachable = true;
    beta.state.graph.node_mut("alpha").unwrap().status.reachable = true;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    assert!(beta.udp_source_node(sender_addr).is_none());

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    let datagram = alpha
        .packet_codec
        .encode_direct("beta", &VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    sender.send_to(&datagram, beta_addr).unwrap();
    beta.poll_once().unwrap();
    let mut stale = [0u8; 2048];
    while matches!(alpha.listen_sockets[0].udp.recv_from(&mut stale), Ok(_)) {}

    let alpha_node = beta.state.graph.node("alpha").unwrap();
    assert_eq!(
        Some(sender_addr),
        alpha_node
            .udp_address
            .as_ref()
            .and_then(edge_endpoint_socket_addr),
        "C handle_incoming_vpn_packet() updates n->address after a direct authenticated UDP packet"
    );
    assert!(
        !alpha_node.status.udp_confirmed,
        "C update_node_udp() clears udp_confirmed after changing the address"
    );
    assert_eq!(Some("alpha".to_owned()), beta.udp_source_node(sender_addr));

    let reply_packet = test_ipv4_ethernet_packet([10, 1, 0, 42]);
    beta.route_udp_packet_from_source("beta", VpnPacket::new(reply_packet).unwrap())
        .unwrap();
    let mut reply = [0u8; 2048];
    let (reply_len, reply_source) = sender.recv_from(&mut reply).unwrap();
    assert_eq!(beta_addr, reply_source);
    assert!(reply_len > 0);
    assert!(matches!(
        alpha.listen_sockets[0].udp.recv_from(&mut reply),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
}

#[test]
fn runtime_sptps_udp_relay_encodes_for_owner_and_sends_to_relay_like_tinc() {
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
    let relay_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay UDP receiver: {error}"),
    };
    relay_receiver
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let relay_addr = relay_receiver.local_addr().unwrap();
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
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
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
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    let options = (PROT_MINOR as u32) << 24;
    {
        let relay = alpha.state.graph.node_mut("relay").unwrap();
        relay.status.reachable = true;
        relay.options = options;
        relay.min_mtu = DEFAULT_MTU;
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

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let mut buffer = [0u8; 4096];
    let (len, source) = relay_receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(alpha.listen_sockets[0].info().address, source);
    let datagram = &buffer[..len];
    let envelope = RelayEnvelope::decode(datagram).unwrap();
    assert_eq!(NodeId::from_name("beta"), envelope.destination);
    assert_eq!(NodeId::from_name("alpha"), envelope.source);

    let record = beta.packet_codec.decode_record("alpha", datagram).unwrap();
    assert_eq!(SPTPS_UDP_ROUTER_PACKET_TYPE, record.record_type);
    assert_eq!(test_ipv4_payload([10, 2, 0, 42]), record.payload);
    assert_eq!(
        VpnPacket::new(test_ipv4_router_packet([10, 2, 0, 42])).unwrap(),
        sptps_packet_from_payload(record.record_type, record.payload).unwrap()
    );
    assert_eq!(1, alpha.traffic["beta"].out_packets);
}

#[test]
fn runtime_sptps_send_tries_owner_and_dynamic_relay_like_tinc() {
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
    let relay_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay runtime listener: {error}"),
    };

    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let relay_addr = relay_socket.info().address;
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();
    let relay_public_key = relay_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let relay_server = config_tree(&[("Name", "relay"), ("AddressFamily", "IPv4")]);
    let relay_alpha_host = config_tree(&[("Address", &alpha_address)]);

    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
    )
    .unwrap();
    let beta_config =
        RuntimeConfig::from_config_tree_with_hosts(&beta_server, [("alpha", &beta_alpha_host)])
            .unwrap();
    let relay_config =
        RuntimeConfig::from_config_tree_with_hosts(&relay_server, [("alpha", &relay_alpha_host)])
            .unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_public_key),
            ("relay".to_owned(), relay_public_key),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key.clone())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let relay_keys = RuntimeKeys {
        private_key: Some(relay_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };

    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);
    let mut relay = RuntimeDaemonState::new(vec![relay_socket], &relay_config, relay_keys);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    complete_sptps_udp_exchange_between(&mut alpha, "relay", &mut relay, "alpha");

    let options = (PROT_MINOR as u32) << 24;
    {
        let relay_node = alpha.state.graph.node_mut("relay").unwrap();
        relay_node.status.reachable = true;
        relay_node.status.sptps = true;
        relay_node.options = options;
        relay_node.min_mtu = DEFAULT_MTU;
        relay_node.route.next_hop = Some("relay".to_owned());
        relay_node.route.via = Some("relay".to_owned());
        relay_node.route.distance = Some(1);
        relay_node.route.weighted_distance = Some(1);
    }
    {
        let beta_node = alpha.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.status.udp_confirmed = false;
        beta_node.options = options;
        beta_node.route.next_hop = Some("relay".to_owned());
        beta_node.route.via = Some("beta".to_owned());
        beta_node.route.distance = Some(2);
        beta_node.route.weighted_distance = Some(2);
    }

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    assert_eq!(
        Some(&1),
        alpha
            .traffic
            .get("beta")
            .map(|traffic| &traffic.out_packets)
    );
    assert!(
        alpha.state.graph.node("beta").unwrap().status.ping_sent,
        "C try_tx_sptps() tries UDP for the final owner before falling back to a dynamic relay"
    );
    assert!(
        alpha.udp_probe["beta"].udp_ping_sent.is_some(),
        "final owner UDP probe should be scheduled like C try_udp(n)"
    );
    assert!(
        alpha.state.graph.node("relay").unwrap().status.ping_sent,
        "unconfirmed final owner should also trigger C try_tx(n->nexthop)"
    );
    assert!(
        alpha.udp_probe["relay"].udp_ping_sent.is_some(),
        "dynamic relay UDP probe should be scheduled like C try_tx(n->nexthop)"
    );
}

#[test]
fn runtime_udp_send_reuses_peer_socket_index_like_tinc_node_sock() {
    tinc_test_support::assert_can_create_netns();
    let alpha_first_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind first alpha runtime listener: {error}"),
    };
    let alpha_second_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind second alpha runtime listener: {error}"),
    };
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    let relay_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay UDP receiver: {error}"),
    };
    relay_receiver
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let alpha_first_addr = alpha_first_socket.info().address;
    let alpha_second_addr = alpha_second_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let relay_addr = relay_receiver.local_addr().unwrap();
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
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_first_addr.ip(), alpha_first_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
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
    let mut alpha = RuntimeDaemonState::new(
        vec![alpha_first_socket, alpha_second_socket],
        &alpha_config,
        alpha_keys,
    );
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    alpha.udp_socket_by_peer.insert("relay".to_owned(), 1);
    let options = (PROT_MINOR as u32) << 24;
    {
        let relay = alpha.state.graph.node_mut("relay").unwrap();
        relay.status.reachable = true;
        relay.options = options;
        relay.min_mtu = DEFAULT_MTU;
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

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let mut buffer = [0u8; 4096];
    let (_, source) = relay_receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(alpha_second_addr, source);
}

#[test]
fn runtime_sptps_relay_without_version_seven_uses_req_key_sptps_packet_like_tinc() {
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
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let relay_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
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
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut relay_stream, mut relay_driver, mut relay_connection)) =
        active_runtime_connection("relay", alpha_key, relay_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);
    relay_connection.id = 1;
    relay_connection.options = 3 << 24;
    alpha.meta_connections.push(relay_connection);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    {
        let relay = alpha.state.graph.node_mut("relay").unwrap();
        relay.status.reachable = true;
        relay.options = 3 << 24;
        relay.route.next_hop = Some("relay".to_owned());
        relay.route.via = Some("relay".to_owned());
    }
    {
        let beta_node = alpha.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.options = (PROT_MINOR as u32) << 24;
        beta_node.route.next_hop = Some("relay".to_owned());
        beta_node.route.via = Some("relay".to_owned());
        beta_node.route.distance = Some(2);
        beta_node.route.weighted_distance = Some(2);
    }

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    alpha.flush_meta_outputs().unwrap();

    let events = read_meta_events_until(&mut relay_stream, &mut relay_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha"
                    && request.to == "beta"
                    && request.extension.as_ref().is_some_and(|extension|
                        extension.request == Request::SptpsPacket.number())
        )
    });
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, MetaConnectionEvent::TcpPacket(_)))
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, MetaConnectionEvent::SptpsPacket(_)))
    );
    let tcp_payload = events
        .iter()
        .find_map(|event| match event {
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request)) => {
                Some(request.decode_sptps_payload().unwrap().data)
            }
            _ => None,
        })
        .expect("expected extended REQ_KEY SPTPS_PACKET fallback");
    assert_eq!(
        SPTPS_DATAGRAM_OVERHEAD + test_ipv4_payload([10, 2, 0, 42]).len(),
        tcp_payload.len(),
        "pre-17.7 REQ_KEY SPTPS_PACKET carries the raw SPTPS record without relay IDs like C tinc"
    );

    let record = beta
        .packet_codec
        .decode_record(
            "alpha",
            &RelayEnvelope::direct(NodeId::from_name("alpha"), tcp_payload.clone()).encode(),
        )
        .unwrap();
    assert_eq!(SPTPS_UDP_ROUTER_PACKET_TYPE, record.record_type);
    assert_eq!(test_ipv4_payload([10, 2, 0, 42]), record.payload);
    assert_eq!(
        VpnPacket::new(test_ipv4_router_packet([10, 2, 0, 42])).unwrap(),
        sptps_packet_from_payload(record.record_type, record.payload).unwrap()
    );
    assert_eq!(1, alpha.traffic["beta"].out_packets);

    let mut buffer = [0u8; 4096];
    match alpha.listen_sockets[0].udp.recv_from(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok((len, source)) => panic!("unexpected UDP relay datagram to {source}: len={len}"),
        Err(error) => panic!("failed checking relay UDP socket: {error}"),
    }
}

#[test]
fn runtime_sptps_relay_tcponly_falls_back_to_sptps_tcp_not_plain_packet_like_tinc() {
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
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let relay_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
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
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut relay_stream, mut relay_driver, mut relay_connection)) =
        active_runtime_connection("relay", alpha_key, relay_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);
    relay_connection.id = 1;
    relay_connection.options = ((PROT_MINOR as u32) << 24) | OPTION_TCPONLY;
    alpha.meta_connections.push(relay_connection);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    let options = (PROT_MINOR as u32) << 24;
    {
        let relay = alpha.state.graph.node_mut("relay").unwrap();
        relay.status.reachable = true;
        relay.options = options | OPTION_TCPONLY;
        relay.min_mtu = DEFAULT_MTU;
        relay.route.next_hop = Some("relay".to_owned());
        relay.route.via = Some("relay".to_owned());
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

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    alpha.flush_meta_outputs().unwrap();

    let events = read_meta_events_until(&mut relay_stream, &mut relay_driver, is_sptps_tcp_packet);
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
        .expect("expected SPTPS TCP packet fallback for TCPOnly relay");
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
    match alpha.listen_sockets[0].udp.recv_from(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok((len, source)) => panic!("unexpected UDP relay datagram to {source}: len={len}"),
        Err(error) => panic!("failed checking relay UDP socket: {error}"),
    }
}

#[test]
fn runtime_sptps_relay_over_min_mtu_falls_back_to_sptps_tcp_like_tinc() {
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
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let relay_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
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
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut stale_relay_stream, mut stale_relay_driver, mut stale_relay_connection)) =
        active_runtime_connection("relay", alpha_key.clone(), relay_key.clone())
    else {
        return;
    };
    let Some((mut relay_stream, mut relay_driver, mut relay_connection)) =
        active_runtime_connection("relay", alpha_key, relay_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);
    stale_relay_connection.id = 1;
    stale_relay_connection.options = (PROT_MINOR as u32) << 24;
    stale_relay_connection.close_requested = true;
    stale_relay_connection.edge_peer = Some("relay".to_owned());
    alpha.meta_connections.push(stale_relay_connection);

    relay_connection.id = 2;
    relay_connection.options = (PROT_MINOR as u32) << 24;
    relay_connection.edge_peer = Some("relay".to_owned());
    alpha.local_edge_connections.insert("relay".to_owned(), 2);
    alpha.meta_connections.push(relay_connection);

    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    let options = (PROT_MINOR as u32) << 24;
    {
        let relay = alpha.state.graph.node_mut("relay").unwrap();
        relay.status.reachable = true;
        relay.options = options;
        relay.min_mtu = test_ipv4_payload([10, 2, 0, 42]).len() - 1;
        relay.route.next_hop = Some("relay".to_owned());
        relay.route.via = Some("relay".to_owned());
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

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    alpha.flush_meta_outputs().unwrap();

    let stale_events = read_meta_events_until(
        &mut stale_relay_stream,
        &mut stale_relay_driver,
        is_sptps_tcp_packet,
    );
    assert!(
        !stale_events
            .iter()
            .any(|event| matches!(event, MetaConnectionEvent::SptpsPacket(_))),
        "SPTPS TCP fallback must skip a closing duplicate relay connection and use the current edge"
    );

    let events = read_meta_events_until(&mut relay_stream, &mut relay_driver, is_sptps_tcp_packet);
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
        .expect("expected SPTPS TCP packet fallback for packet above relay minmtu");
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
    match alpha.listen_sockets[0].udp.recv_from(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Ok((len, source)) => panic!("unexpected UDP relay datagram to {source}: len={len}"),
        Err(error) => panic!("failed checking relay UDP socket: {error}"),
    }
}

#[test]
fn runtime_indirect_udp_without_owner_session_uses_relay_session() {
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
    let alpha_addr = alpha_socket.info().address;
    let relay_addr = relay_socket.info().address;
    let alpha_key = test_key(1);
    let relay_key = test_key(2);
    let beta_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let relay_public_key = relay_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let alpha_beta_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let relay_server = config_tree(&[("Name", "relay"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let relay_alpha_host = config_tree(&[("Address", &alpha_address)]);

    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("relay", &alpha_relay_host), ("beta", &alpha_beta_host)],
    )
    .unwrap();
    let relay_config =
        RuntimeConfig::from_config_tree_with_hosts(&relay_server, [("alpha", &relay_alpha_host)])
            .unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([
            ("relay".to_owned(), relay_public_key),
            ("beta".to_owned(), beta_public_key),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let relay_keys = RuntimeKeys {
        private_key: Some(relay_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut relay = RuntimeDaemonState::new(vec![relay_socket], &relay_config, relay_keys);

    complete_sptps_udp_exchange_between(&mut alpha, "relay", &mut relay, "alpha");
    assert!(alpha.packet_codec.peer("beta").is_none());
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

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let len = loop {
        match relay.listen_sockets[0].udp.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(alpha.listen_sockets[0].info().address, source);
                break len;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive relay fallback UDP datagram: {error}"),
        }
    };
    let datagram = &buffer[..len];
    let envelope = RelayEnvelope::decode(datagram).unwrap();
    assert!(envelope.destination.is_null());
    assert_eq!(NodeId::from_name("alpha"), envelope.source);
    let record = relay.packet_codec.decode_record("alpha", datagram).unwrap();
    assert_eq!(SPTPS_UDP_ROUTER_PACKET_TYPE, record.record_type);
    assert_eq!(test_ipv4_payload([10, 2, 0, 42]), record.payload);
    assert_eq!(
        VpnPacket::new(test_ipv4_router_packet([10, 2, 0, 42])).unwrap(),
        sptps_packet_from_payload(record.record_type, record.payload).unwrap()
    );
    assert_eq!(1, alpha.traffic["beta"].out_packets);
}

#[test]
fn runtime_forwards_sptps_udp_relay_datagram_without_decrypting_like_tinc() {
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
    let alpha_addr = alpha_socket.info().address;
    let relay_addr = relay_socket.info().address;
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
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let alpha_relay_host = config_tree(&[("Address", &relay_address)]);
    let relay_server = config_tree(&[("Name", "relay"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let relay_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let relay_beta_host = config_tree(&[("Address", &beta_address)]);
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
        private_key: Some(test_key(3)),
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
    let mut relay = RuntimeDaemonState::new(vec![relay_socket], &relay_config, relay_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

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
        let alpha_node = relay.state.graph.node_mut("alpha").unwrap();
        alpha_node.status.reachable = true;
        alpha_node.options = options;
        alpha_node.route.next_hop = Some("alpha".to_owned());
        alpha_node.route.via = Some("alpha".to_owned());
        alpha_node.route.distance = Some(1);
        alpha_node.route.weighted_distance = Some(1);
    }
    beta.state.graph.ensure_node("alpha");
    *beta.packet_codec.ids_mut() = NodeIdTable::from_network_state(&beta.state);
    {
        let beta_node = relay.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.options = options;
        beta_node.min_mtu = DEFAULT_MTU;
        beta_node.route.next_hop = Some("beta".to_owned());
        beta_node.route.via = Some("beta".to_owned());
        beta_node.route.distance = Some(1);
        beta_node.route.weighted_distance = Some(1);
    }
    assert!(!relay.sptps_last_req_key.contains_key("beta"));
    assert!(
        !relay
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .waiting_for_key
    );

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    relay.poll_once().unwrap();

    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let len = loop {
        match beta.listen_sockets[0].udp.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(relay.listen_sockets[0].info().address, source);
                break len;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive relayed UDP datagram: {error}"),
        }
    };
    let datagram = &buffer[..len];
    let envelope = RelayEnvelope::decode(datagram).unwrap();
    assert_eq!(NodeId::from_name("beta"), envelope.destination);
    assert_eq!(NodeId::from_name("alpha"), envelope.source);
    let record = beta.packet_codec.decode_record("alpha", datagram).unwrap();
    assert_eq!(SPTPS_UDP_ROUTER_PACKET_TYPE, record.record_type);
    assert_eq!(test_ipv4_payload([10, 2, 0, 42]), record.payload);
    assert_eq!(
        VpnPacket::new(test_ipv4_router_packet([10, 2, 0, 42])).unwrap(),
        sptps_packet_from_payload(record.record_type, record.payload).unwrap()
    );
    assert!(
        relay.sptps_last_req_key.contains_key("beta"),
        "C req_key_ext_h()/handle_incoming_vpn_packet() calls try_tx(to, true) after forwarding relay data"
    );
    assert!(
        relay
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .waiting_for_key,
        "forwarded relay data should kick the C try_sptps() state machine for the destination"
    );
}

#[test]
fn runtime_raw_sptps_tcp_packet_forwards_before_destination_valid_key_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha runtime listener: {error}"),
    };
    let beta_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta UDP receiver: {error}"),
    };
    beta_receiver
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();

    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let beta_addr = beta_receiver.local_addr().unwrap();
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let gamma_host = config_tree(&[]);
    let config = RuntimeConfig::from_config_tree_with_hosts(
        &server,
        [("beta", &beta_host), ("gamma", &gamma_host)],
    )
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    beta_connection.id = 1;

    let mut runtime = RuntimeDaemonState::new(vec![alpha_socket], &config, keys);
    runtime.meta_connections.push(beta_connection);
    {
        let beta = runtime.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = true;
        beta.status.valid_key = false;
        beta.options = (PROT_MINOR as u32) << 24;
        beta.min_mtu = DEFAULT_MTU;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
    }
    {
        let gamma = runtime.state.graph.node_mut("gamma").unwrap();
        gamma.status.reachable = true;
        gamma.status.sptps = true;
        gamma.options = (PROT_MINOR as u32) << 24;
    }
    *runtime.packet_codec.ids_mut() = NodeIdTable::from_network_state(&runtime.state);

    let payload = RelayEnvelope::relayed(
        NodeId::from_name("beta"),
        NodeId::from_name("gamma"),
        b"raw-sptps-record".to_vec(),
    )
    .encode();
    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::SptpsPacket(payload)],
                ..Default::default()
            },
        )
        .unwrap();
    runtime.flush_meta_outputs().unwrap();

    let events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        is_sptps_initial_req_key(event, "alpha", "beta")
    });
    assert!(
        events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta")),
        "C req_key_ext_h() calls try_tx(to, true) after forwarding SPTPS_PACKET data"
    );
    assert!(
        runtime.sptps_last_req_key.contains_key("beta"),
        "C try_tx_sptps() starts a fresh SPTPS key request for the destination"
    );
    assert!(
        runtime
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .waiting_for_key
    );

    let mut buffer = [0u8; 4096];
    let (len, source) = beta_receiver
        .recv_from(&mut buffer)
        .expect("C req_key_ext_h() forwards SPTPS_PACKET data before destination validkey is set");
    assert_eq!(runtime.listen_sockets[0].info().address, source);
    let envelope = RelayEnvelope::decode(&buffer[..len]).unwrap();
    assert_eq!(NodeId::from_name("beta"), envelope.destination);
    assert_eq!(NodeId::from_name("gamma"), envelope.source);
    assert_eq!(b"raw-sptps-record", envelope.payload.as_slice());
}

#[test]
fn runtime_raw_sptps_tcp_packet_to_local_sends_udp_info_before_decode_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let server = config_tree(&[("Name", "alpha"), ("AddressFamily", "IPv4")]);
    let beta_host = config_tree(&[]);
    let gamma_host = config_tree(&[]);
    let config = RuntimeConfig::from_config_tree_with_hosts(
        &server,
        [("beta", &beta_host), ("gamma", &gamma_host)],
    )
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    beta_connection.id = 1;

    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.meta_connections.push(beta_connection);
    {
        let beta = runtime.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.options = (PROT_MINOR as u32) << 24;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
    }
    runtime.state.graph.ensure_node("gamma");
    {
        let gamma = runtime.state.graph.node_mut("gamma").unwrap();
        gamma.status.reachable = true;
        gamma.status.sptps = true;
        gamma.options = (PROT_MINOR as u32) << 24;
        gamma.route.next_hop = Some("delta".to_owned());
        gamma.route.via = Some("alpha".to_owned());
        gamma.route.distance = Some(2);
        gamma.route.weighted_distance = Some(2);
    }
    runtime.state.graph.ensure_node("delta");
    {
        let delta = runtime.state.graph.node_mut("delta").unwrap();
        delta.status.reachable = true;
        delta.options = (PROT_MINOR as u32) << 24;
        delta.route.next_hop = Some("beta".to_owned());
        delta.route.via = Some("delta".to_owned());
        delta.route.distance = Some(2);
        delta.route.weighted_distance = Some(2);
    }
    *runtime.packet_codec.ids_mut() = NodeIdTable::from_network_state(&runtime.state);

    let payload = RelayEnvelope::relayed(
        NodeId::from_name("alpha"),
        NodeId::from_name("gamma"),
        b"invalid-raw-sptps-record".to_vec(),
    )
    .encode();
    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::SptpsPacket(payload)],
                ..Default::default()
            },
        )
        .unwrap();
    runtime.flush_meta_outputs().unwrap();

    let events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                if message.from == "alpha" && message.to == "delta"
        )
    });
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                if message.from == "alpha"
                    && message.to == "delta"
                    && message.endpoint.port != "unspec"
        )),
        "C receive_tcppacket_sptps() calls send_udp_info(myself, from) before decoding raw TCP SPTPS data for the local node"
    );
    let gamma = runtime.state.graph.node("gamma").unwrap();
    assert!(
        gamma.status.waiting_for_key,
        "C receive_tcppacket_sptps() treats bad local raw TCP SPTPS data as handled and restarts SPTPS when req_key is due"
    );
    assert!(runtime.sptps_last_req_key.contains_key("gamma"));
}

#[test]
fn runtime_short_raw_sptps_tcp_packet_closes_connection_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    beta_connection.id = 1;

    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.meta_connections.push(beta_connection);

    let short_payload = vec![0; RELAY_HEADER_LEN - 1];
    let mut wire = Vec::new();
    for chunk in beta_driver.send_sptps_packet(&short_payload).unwrap() {
        wire.extend(chunk);
    }
    beta_stream.write_all(&wire).unwrap();

    runtime.poll_once().unwrap();

    assert!(
        runtime.meta_connections.is_empty(),
        "C receive_tcppacket_sptps() returns false for too-short raw TCP SPTPS packets, closing only that meta connection"
    );
}

#[test]
fn runtime_relayed_sptps_udp_to_local_sends_mtu_info_without_updating_origin_address_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    let relay_socket = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay UDP sender: {error}"),
    };
    let beta_addr = beta_socket.info().address;
    let relay_addr = relay_socket.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();
    let relay_public_key = relay_key.public_key();

    let alpha_config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let beta_server = config_tree(&[
        ("Name", "beta"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
    ]);
    let sender_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let beta_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let alpha_host = config_tree(&[("Subnet", "10.1.0.0/16")]);
    let relay_host = config_tree(&[]);
    let sender_host = config_tree(&[("Address", &sender_address)]);
    let beta_config = RuntimeConfig::from_config_tree_with_hosts(
        &beta_server,
        [
            ("beta", &beta_host),
            ("alpha", &alpha_host),
            ("relay", &relay_host),
            ("sender", &sender_host),
        ],
    )
    .unwrap();

    let mut alpha = RuntimeDaemonState::new(
        Vec::new(),
        &alpha_config,
        RuntimeKeys {
            private_key: Some(alpha_key),
            peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    alpha.state.graph.ensure_node("beta");
    let alpha_beta = alpha.state.graph.node_mut("beta").unwrap();
    alpha_beta.status.reachable = true;
    alpha_beta.status.sptps = true;
    alpha_beta.options = (PROT_MINOR as u32) << 24;
    alpha_beta.route.next_hop = Some("beta".to_owned());
    alpha_beta.route.via = Some("beta".to_owned());
    *alpha.packet_codec.ids_mut() = NodeIdTable::from_network_state(&alpha.state);
    let Some((mut relay_stream, mut relay_driver, mut relay_connection)) =
        active_runtime_connection("relay", beta_key.clone(), relay_key.clone())
    else {
        return;
    };
    let mut beta = RuntimeDaemonState::new(
        vec![beta_socket],
        &beta_config,
        RuntimeKeys {
            private_key: Some(beta_key),
            peer_public_keys: BTreeMap::from([
                ("alpha".to_owned(), alpha_public_key),
                ("relay".to_owned(), relay_public_key),
            ]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );

    beta.state
        .subnets
        .add("10.1.0.0/16".parse::<Subnet>().unwrap().with_owner("alpha"));
    beta.state.graph.ensure_node("alpha");
    {
        let alpha_node = beta.state.graph.node_mut("alpha").unwrap();
        alpha_node.status.reachable = true;
        alpha_node.status.sptps = true;
        alpha_node.options = (PROT_MINOR as u32) << 24;
        alpha_node.route.next_hop = Some("relay".to_owned());
        alpha_node.route.via = Some("alpha".to_owned());
        alpha_node.udp_address = Some(EdgeEndpoint::new("198.51.100.10", "655"));
    }
    beta.state.graph.ensure_node("relay");
    {
        let relay_node = beta.state.graph.node_mut("relay").unwrap();
        relay_node.status.reachable = true;
        relay_node.status.sptps = true;
        relay_node.options = (PROT_MINOR as u32) << 24;
        relay_node.route.next_hop = Some("relay".to_owned());
        relay_node.route.via = Some("relay".to_owned());
    }
    beta.state.graph.ensure_node("sender");
    {
        let sender_node = beta.state.graph.node_mut("sender").unwrap();
        sender_node.status.reachable = true;
        sender_node.status.sptps = true;
        sender_node.options = (PROT_MINOR as u32) << 24;
        sender_node.route.next_hop = Some("relay".to_owned());
        sender_node.route.via = Some("sender".to_owned());
    }
    relay_connection.id = 1;
    beta.meta_connections.push(relay_connection);
    *beta.packet_codec.ids_mut() = NodeIdTable::from_network_state(&beta.state);

    complete_sptps_udp_exchange_between(&mut alpha, "beta", &mut beta, "alpha");

    let datagram = alpha
        .packet_codec
        .encode_relayed(
            "beta",
            &VpnPacket::new(test_ipv4_router_packet([10, 2, 0, 42])).unwrap(),
        )
        .unwrap();
    relay_socket.send_to(&datagram, beta_addr).unwrap();
    beta.poll_once().unwrap();

    let alpha_node = beta.state.graph.node("alpha").unwrap();
    assert_eq!(
        Some(&EdgeEndpoint::new("198.51.100.10", "655")),
        alpha_node.udp_address.as_ref(),
        "C handle_incoming_vpn_packet() only calls update_node_udp() for direct packets"
    );
    beta.flush_meta_outputs().unwrap();

    let events = read_meta_events_until(&mut relay_stream, &mut relay_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                if message.from == "beta"
                    && message.to == "sender"
                    && message.mtu == DEFAULT_MTU
        )
    });
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                    if message.from == "beta"
                        && message.to == "sender"
                        && message.mtu == DEFAULT_MTU
            )
        }),
        "C handle_incoming_vpn_packet() sends MTU_INFO to the actual UDP sender after relayed delivery"
    );
}

#[test]
fn runtime_relayed_sptps_udp_probe_to_local_does_not_update_origin_address_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta runtime listener: {error}"),
    };
    let relay_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay UDP receiver: {error}"),
    };
    relay_receiver.set_nonblocking(true).unwrap();
    let sender_socket = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind sender UDP socket: {error}"),
    };
    sender_socket.set_nonblocking(true).unwrap();

    let beta_addr = beta_socket.info().address;
    let relay_addr = relay_receiver.local_addr().unwrap();
    let sender_addr = sender_socket.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();
    let relay_public_key = relay_key.public_key();
    let options = (PROT_MINOR as u32) << 24;

    let alpha_config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let sender_address = format!("{} {}", sender_addr.ip(), sender_addr.port());
    let beta_config = RuntimeConfig::from_config_tree_with_hosts(
        &beta_server,
        [
            ("alpha", &config_tree(&[])),
            ("relay", &config_tree(&[("Address", &relay_address)])),
            ("sender", &config_tree(&[("Address", &sender_address)])),
        ],
    )
    .unwrap();

    let mut alpha = RuntimeDaemonState::new(
        Vec::new(),
        &alpha_config,
        RuntimeKeys {
            private_key: Some(alpha_key),
            peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_public_key)]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    alpha.state.graph.ensure_node("beta");
    {
        let beta_node = alpha.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.options = options;
        beta_node.route.next_hop = Some("beta".to_owned());
        beta_node.route.via = Some("beta".to_owned());
    }
    *alpha.packet_codec.ids_mut() = NodeIdTable::from_network_state(&alpha.state);

    let mut beta = RuntimeDaemonState::new(
        vec![beta_socket],
        &beta_config,
        RuntimeKeys {
            private_key: Some(beta_key),
            peer_public_keys: BTreeMap::from([
                ("alpha".to_owned(), alpha_public_key),
                ("relay".to_owned(), relay_public_key),
            ]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    beta.state.graph.ensure_node("alpha");
    {
        let alpha_node = beta.state.graph.node_mut("alpha").unwrap();
        alpha_node.status.reachable = true;
        alpha_node.status.sptps = true;
        alpha_node.options = options;
        alpha_node.route.next_hop = Some("relay".to_owned());
        alpha_node.route.via = Some("relay".to_owned());
        alpha_node.udp_address = Some(EdgeEndpoint::new("198.51.100.10", "655"));
    }
    beta.state.graph.ensure_node("relay");
    {
        let relay_node = beta.state.graph.node_mut("relay").unwrap();
        relay_node.status.reachable = true;
        relay_node.status.sptps = true;
        relay_node.status.udp_confirmed = true;
        relay_node.options = options;
        relay_node.route.next_hop = Some("relay".to_owned());
        relay_node.route.via = Some("relay".to_owned());
        relay_node.udp_address = Some(EdgeEndpoint::new(
            relay_addr.ip().to_string(),
            relay_addr.port().to_string(),
        ));
    }
    beta.state.graph.ensure_node("sender");
    {
        let sender_node = beta.state.graph.node_mut("sender").unwrap();
        sender_node.status.reachable = true;
        sender_node.status.sptps = true;
        sender_node.status.udp_confirmed = true;
        sender_node.options = options;
        sender_node.route.next_hop = Some("sender".to_owned());
        sender_node.route.via = Some("sender".to_owned());
        sender_node.udp_address = Some(EdgeEndpoint::new(
            sender_addr.ip().to_string(),
            sender_addr.port().to_string(),
        ));
    }
    *beta.packet_codec.ids_mut() = NodeIdTable::from_network_state(&beta.state);

    complete_sptps_udp_exchange_between(&mut alpha, "beta", &mut beta, "alpha");

    let probe = vec![0u8; UDP_PROBE_MIN_SIZE];
    let datagram = alpha
        .packet_codec
        .encode_relayed_record("beta", SPTPS_UDP_PROBE_TYPE, &probe)
        .unwrap();
    sender_socket.send_to(&datagram, beta_addr).unwrap();
    beta.poll_once().unwrap();

    assert_eq!(
        Some(&EdgeEndpoint::new("198.51.100.10", "655")),
        beta.state.graph.node("alpha").unwrap().udp_address.as_ref(),
        "C handle_incoming_vpn_packet() only calls update_node_udp() for direct SPTPS probes"
    );

    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let (len, reply_source) = loop {
        match relay_receiver.recv_from(&mut buffer) {
            Ok(received) => break received,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive relayed probe reply: {error}"),
        }
    };
    assert_eq!(beta_addr, reply_source);
    let record = alpha
        .packet_codec
        .decode_record("beta", &buffer[..len])
        .unwrap();
    assert_eq!(SPTPS_UDP_PROBE_TYPE, record.record_type);
    assert_eq!(2, record.payload[0]);

    match sender_socket.recv_from(&mut buffer) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok((len, source)) => panic!("unexpected direct probe reply from {source}: len={len}"),
        Err(error) => panic!("failed checking sender UDP socket: {error}"),
    }
    assert_ne!(
        sender_addr, relay_addr,
        "test must use separate relay and sender UDP sockets"
    );
}

#[test]
fn runtime_sptps_udp_relay_sends_udp_info_only_for_dynamic_relay_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let relay_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay runtime listener: {error}"),
    };
    let beta_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta UDP receiver: {error}"),
    };
    beta_receiver
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();

    let beta_addr = beta_receiver.local_addr().unwrap();
    let alpha_key = test_key(1);
    let relay_key = test_key(3);
    let alpha_public_key = alpha_key.public_key();
    let relay_server = config_tree(&[("Name", "relay"), ("AddressFamily", "IPv4")]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let relay_beta_host = config_tree(&[("Address", &beta_address)]);
    let relay_config =
        RuntimeConfig::from_config_tree_with_hosts(&relay_server, [("beta", &relay_beta_host)])
            .unwrap();

    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", relay_key.clone(), test_key(4))
    else {
        return;
    };
    let mut relay = RuntimeDaemonState::new(
        vec![relay_socket],
        &relay_config,
        RuntimeKeys {
            private_key: Some(relay_key),
            peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_public_key)]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    gamma_connection.id = 1;
    relay.meta_connections.push(gamma_connection);

    let options = (PROT_MINOR as u32) << 24;
    relay.state.graph.ensure_node("alpha");
    {
        let alpha = relay.state.graph.node_mut("alpha").unwrap();
        alpha.status.reachable = true;
        alpha.status.sptps = true;
        alpha.options = options;
        alpha.route.next_hop = Some("gamma".to_owned());
        alpha.route.via = Some("alpha".to_owned());
        alpha.udp_address = Some(EdgeEndpoint::new("198.51.100.7", "655"));
    }
    relay.state.graph.ensure_node("beta");
    {
        let beta = relay.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = true;
        beta.options = options;
        beta.min_mtu = DEFAULT_MTU;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("relay".to_owned());
    }
    relay.state.graph.ensure_node("gamma");
    {
        let gamma = relay.state.graph.node_mut("gamma").unwrap();
        gamma.status.reachable = true;
        gamma.status.sptps = true;
        gamma.options = options;
        gamma.route.next_hop = Some("gamma".to_owned());
        gamma.route.via = Some("gamma".to_owned());
    }
    *relay.packet_codec.ids_mut() = NodeIdTable::from_network_state(&relay.state);

    let mut alpha = RuntimeDaemonState::new(
        Vec::new(),
        &RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap(),
        RuntimeKeys {
            private_key: Some(alpha_key),
            peer_public_keys: BTreeMap::from([("relay".to_owned(), test_key(3).public_key())]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    alpha.state.graph.ensure_node("relay");
    {
        let relay_node = alpha.state.graph.node_mut("relay").unwrap();
        relay_node.status.reachable = true;
        relay_node.status.sptps = true;
        relay_node.options = options;
        relay_node.route.next_hop = Some("relay".to_owned());
        relay_node.route.via = Some("relay".to_owned());
    }
    *alpha.packet_codec.ids_mut() = NodeIdTable::from_network_state(&alpha.state);
    complete_sptps_udp_exchange_between(&mut alpha, "relay", &mut relay, "alpha");

    let relayed_packet = VpnPacket::new(test_ipv4_router_packet([10, 2, 0, 42])).unwrap();
    let mut datagram = alpha
        .packet_codec
        .encode_relayed("relay", &relayed_packet)
        .unwrap();
    let mut envelope = RelayEnvelope::decode(&datagram).unwrap();
    envelope.destination = NodeId::from_name("beta");
    datagram = envelope.encode();

    let first_pending = relay.meta_connections[0].pending_output_len();
    let relay_addr = relay.listen_sockets[0].info().address;
    relay
        .handle_sptps_udp_envelope("alpha", relay_addr, 0, &datagram)
        .unwrap();
    let after_static_relay = relay.meta_connections[0].pending_output_len();
    assert_eq!(
        first_pending, after_static_relay,
        "C handle_incoming_vpn_packet() does not send UDP_INFO when the UDP sender is from->via"
    );

    relay
        .handle_sptps_udp_envelope("gamma", relay_addr, 0, &datagram)
        .unwrap();
    let after_dynamic_relay = relay.meta_connections[0].pending_output_len();
    assert!(
        after_dynamic_relay > after_static_relay,
        "C handle_incoming_vpn_packet() sends UDP_INFO only when n != from->via and to->via == myself"
    );

    let udp_info_endpoint = relay.meta_connections[0].local;
    relay.flush_meta_outputs().unwrap();
    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                if message.from == "relay"
                    && message.to == "alpha"
                    && message.endpoint.address == udp_info_endpoint.ip().to_string()
                    && message.endpoint.port == udp_info_endpoint.port().to_string()
        )
    });
    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
            if message.from == "relay"
                && message.to == "alpha"
                && message.endpoint.address == udp_info_endpoint.ip().to_string()
                && message.endpoint.port == udp_info_endpoint.port().to_string()
    )));

    relay.udp_info_sent.clear();
    let local_packet = VpnPacket::new(test_ipv4_router_packet([10, 2, 0, 42])).unwrap();
    let local_datagram = alpha
        .packet_codec
        .encode_relayed("relay", &local_packet)
        .unwrap();
    assert_eq!(
        NodeId::from_name("relay"),
        RelayEnvelope::decode(&local_datagram).unwrap().destination
    );
    relay
        .handle_sptps_udp_envelope("gamma", relay_addr, 0, &local_datagram)
        .unwrap();
    relay.flush_meta_outputs().unwrap();

    let local_events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                if message.from == "relay"
                    && message.to == "alpha"
                    && message.endpoint.address == udp_info_endpoint.ip().to_string()
                    && message.endpoint.port == udp_info_endpoint.port().to_string()
        )
    });
    assert!(
        local_events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                if message.from == "relay"
                    && message.to == "alpha"
                    && message.endpoint.address == udp_info_endpoint.ip().to_string()
                    && message.endpoint.port == udp_info_endpoint.port().to_string()
        )),
        "C handle_incoming_vpn_packet() runs the same UDP_INFO gate before the to == myself branch"
    );
}

#[test]
fn runtime_relay_req_key_sptps_packet_redecides_udp_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let relay_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay runtime listener: {error}"),
    };
    let beta_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta UDP receiver: {error}"),
    };
    beta_receiver
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();

    let relay_addr = relay_socket.info().address;
    let beta_addr = beta_receiver.local_addr().unwrap();
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
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let relay_beta_host = config_tree(&[("Address", &beta_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);

    let alpha_config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &alpha_beta_host), ("relay", &alpha_relay_host)],
    )
    .unwrap();
    let relay_config =
        RuntimeConfig::from_config_tree_with_hosts(&relay_server, [("beta", &relay_beta_host)])
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

    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    let record = alpha
        .packet_codec
        .encode_relayed(
            "beta",
            &VpnPacket::new(test_ipv4_ethernet_packet([10, 2, 0, 42])).unwrap(),
        )
        .unwrap();
    let raw_record = RelayEnvelope::decode(&record).unwrap().payload;
    let request = RequestKeyMessage::sptps_tcp_packet("alpha", "beta", &raw_record);
    assert_eq!(
        Some(Request::SptpsPacket),
        request
            .extension
            .as_ref()
            .and_then(|extension| Request::try_from(extension.request).ok())
    );
    assert_eq!(raw_record, request.decode_sptps_payload().unwrap().data);
    let options = (PROT_MINOR as u32) << 24;
    relay.state.graph.ensure_node("alpha");
    {
        let alpha_node = relay.state.graph.node_mut("alpha").unwrap();
        alpha_node.status.reachable = true;
        alpha_node.options = options;
        alpha_node.route.next_hop = Some("alpha".to_owned());
        alpha_node.route.via = Some("alpha".to_owned());
        alpha_node.route.distance = Some(1);
        alpha_node.route.weighted_distance = Some(1);
    }
    beta.state.graph.ensure_node("alpha");
    *beta.packet_codec.ids_mut() = NodeIdTable::from_network_state(&beta.state);
    {
        let beta_node = relay.state.graph.node_mut("beta").unwrap();
        beta_node.status.reachable = true;
        beta_node.status.sptps = true;
        beta_node.options = options;
        beta_node.min_mtu = DEFAULT_MTU;
        beta_node.route.next_hop = Some("beta".to_owned());
        beta_node.route.via = Some("beta".to_owned());
        beta_node.route.distance = Some(1);
        beta_node.route.weighted_distance = Some(1);
    }
    assert_eq!(Some(beta_addr), relay.addresses.address("beta"));
    assert_eq!(
        Some(0),
        relay.listen_socket_index_for_peer("beta", beta_addr)
    );
    assert_eq!(
        Some(NodeId::from_name("beta")),
        relay.state.graph.node("beta").map(|node| node.id)
    );
    let relay_beta = relay.state.graph.node("beta").unwrap();
    assert!(relay_beta.status.reachable);
    assert_eq!(options, relay_beta.options);
    assert_eq!(DEFAULT_MTU, relay_beta.min_mtu);
    assert_eq!(Some("beta"), relay_beta.route.next_hop.as_deref());
    assert_eq!(Some("beta"), relay_beta.route.via.as_deref());
    assert!(!relay.local_tcp_only);
    assert!(raw_record.len().saturating_sub(SPTPS_DATAGRAM_OVERHEAD) <= DEFAULT_MTU);
    assert!(!relay.sptps_last_req_key.contains_key("beta"));

    let forwards = relay.handle_extended_request_key_message(&request).unwrap();

    assert!(forwards.is_empty());
    let mut buffer = [0u8; 4096];
    let (len, source) = beta_receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(relay.listen_sockets[0].info().address, source);
    let envelope = RelayEnvelope::decode(&buffer[..len]).unwrap();
    assert_eq!(NodeId::from_name("beta"), envelope.destination);
    assert_eq!(NodeId::from_name("alpha"), envelope.source);
    assert_eq!(raw_record, envelope.payload);

    let record = beta
        .packet_codec
        .decode_record("alpha", &buffer[..len])
        .unwrap();
    assert_eq!(SPTPS_UDP_ROUTER_PACKET_TYPE, record.record_type);
    assert_eq!(test_ipv4_payload([10, 2, 0, 42]), record.payload);
    assert!(
        relay.sptps_last_req_key.contains_key("beta"),
        "C req_key_ext_h() calls try_tx(to, true) after SPTPS_PACKET forwarding"
    );
    assert!(
        relay
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .waiting_for_key,
        "REQ_KEY SPTPS_PACKET forwarding should also kick try_sptps() for the destination"
    );
}

#[test]
fn runtime_req_key_sptps_packet_respects_forwarding_off_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let relay_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay runtime listener: {error}"),
    };
    let beta_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta UDP receiver: {error}"),
    };
    beta_receiver.set_nonblocking(true).unwrap();

    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let beta_addr = beta_receiver.local_addr().unwrap();
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let relay_server = config_tree(&[
        ("Name", "relay"),
        ("AddressFamily", "IPv4"),
        ("Forwarding", "off"),
    ]);
    let relay_beta_host = config_tree(&[("Address", &beta_address)]);
    let relay_config =
        RuntimeConfig::from_config_tree_with_hosts(&relay_server, [("beta", &relay_beta_host)])
            .unwrap();
    let mut relay = RuntimeDaemonState::new(
        vec![relay_socket],
        &relay_config,
        RuntimeKeys {
            private_key: Some(relay_key),
            peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );

    let options = (PROT_MINOR as u32) << 24;
    relay.state.graph.ensure_node("alpha");
    {
        let alpha = relay.state.graph.node_mut("alpha").unwrap();
        alpha.status.reachable = true;
        alpha.status.sptps = true;
        alpha.options = options;
        alpha.route.next_hop = Some("alpha".to_owned());
        alpha.route.via = Some("alpha".to_owned());
    }
    {
        let beta = relay.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = true;
        beta.options = options;
        beta.min_mtu = DEFAULT_MTU;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
    }
    assert_eq!(Some(beta_addr), relay.addresses.address("beta"));

    let request = RequestKeyMessage::sptps_tcp_packet("alpha", "beta", b"raw-sptps-record");
    relay.handle_extended_request_key_message(&request).unwrap();

    let mut buffer = [0u8; 4096];
    assert!(
        matches!(
            beta_receiver.recv_from(&mut buffer),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ),
        "C req_key_ext_h() only forwards SPTPS_PACKET when forwarding_mode == FMODE_INTERNAL"
    );
    assert!(
        !relay.sptps_last_req_key.contains_key("beta"),
        "C req_key_ext_h() does not call try_tx(to, true) after suppressing forwarding"
    );
    assert!(
        !relay
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .waiting_for_key
    );
}

#[test]
fn runtime_replies_to_sptps_udp_probe_like_tinc() {
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
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[("Name", "alpha"), ("AddressFamily", "IPv4")]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let alpha_config =
        RuntimeConfig::from_config_tree_with_hosts(&alpha_server, [("beta", &alpha_beta_host)])
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
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    let options = (PROT_MINOR as u32) << 24;
    let alpha_peer = alpha.state.graph.node_mut("beta").unwrap();
    alpha_peer.status.reachable = true;
    alpha_peer.options = options;
    let beta_peer = beta.state.graph.node_mut("alpha").unwrap();
    beta_peer.status.reachable = true;
    beta_peer.options = options;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    let probe = vec![0u8; UDP_PROBE_MIN_SIZE];
    let datagram = alpha
        .packet_codec
        .encode_direct_record("beta", SPTPS_UDP_PROBE_TYPE, &probe)
        .unwrap();
    alpha.listen_sockets[0]
        .udp
        .send_to(&datagram, beta_addr)
        .unwrap();

    beta.poll_once().unwrap();

    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let len = loop {
        match alpha.listen_sockets[0].udp.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(beta_addr, source);
                break len;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive UDP probe reply: {error}"),
        }
    };
    let record = alpha
        .packet_codec
        .decode_record("beta", &buffer[..len])
        .unwrap();

    assert_eq!(SPTPS_UDP_PROBE_TYPE, record.record_type);
    assert_eq!(UDP_PROBE_MIN_SIZE, record.payload.len());
    assert_eq!(2, record.payload[0]);
    assert_eq!(
        UDP_PROBE_MIN_SIZE as u16,
        u16::from_be_bytes([record.payload[1], record.payload[2]])
    );
    assert!(beta.device_writes().is_empty());
}
