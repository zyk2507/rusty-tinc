use super::*;

#[test]
fn runtime_routes_udp_packets_through_legacy_sessions_from_answer_key() {
    tinc_test_support::assert_can_create_netns();
    let alpha_confbase = temp_confbase("runtime-legacy-alpha");
    let beta_confbase = temp_confbase("runtime-legacy-beta");
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(alpha_confbase).unwrap();
            fs::remove_dir_all(beta_confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind alpha legacy listener: {error}"),
    };
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(alpha_confbase).unwrap();
            fs::remove_dir_all(beta_confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind beta legacy listener: {error}"),
    };
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let alpha_key = test_key(1);
    let beta_key = test_key(2);

    fs::write(
        alpha_confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nStrictSubnets = yes\n",
    )
    .unwrap();
    fs::write(
        alpha_confbase.join("hosts").join("alpha"),
        "Subnet = 10.1.0.0/16\n",
    )
    .unwrap();
    fs::write(
        alpha_confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nSubnet = 10.2.0.0/16\n",
            beta_addr.ip(),
            beta_addr.port()
        ),
    )
    .unwrap();
    fs::write(
        beta_confbase.join("tinc.conf"),
        "Name = beta\nAddressFamily = IPv4\nStrictSubnets = yes\n",
    )
    .unwrap();
    fs::write(
        beta_confbase.join("hosts").join("beta"),
        "Subnet = 10.2.0.0/16\n",
    )
    .unwrap();
    fs::write(
        beta_confbase.join("hosts").join("alpha"),
        format!(
            "Address = {} {}\nSubnet = 10.1.0.0/16\n",
            alpha_addr.ip(),
            alpha_addr.port()
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
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);
    alpha.state.graph.node_mut("beta").unwrap().status.reachable = true;
    beta.state.graph.node_mut("alpha").unwrap().status.reachable = true;

    let beta_key_message = match parse_meta_message("16 beta alpha 00 0 0 0 0").unwrap() {
        MetaMessage::AnswerKey(message) => message,
        _ => panic!("expected legacy ANS_KEY"),
    };
    alpha
        .apply_legacy_answer_key_message(&beta_key_message)
        .unwrap();
    assert!(alpha.legacy_codec.peer("beta").is_some());

    let alpha_key_message = match parse_meta_message("16 alpha beta 00 0 0 0 0").unwrap() {
        MetaMessage::AnswerKey(message) => message,
        _ => panic!("expected legacy ANS_KEY"),
    };
    beta.apply_legacy_answer_key_message(&alpha_key_message)
        .unwrap();
    assert!(beta.legacy_codec.peer("alpha").is_some());

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    assert_eq!(2, alpha.legacy_codec.peer("beta").unwrap().sent_seqno());
    assert!(alpha.state.graph.node("beta").unwrap().status.ping_sent);

    beta.poll_once().unwrap();
    assert_eq!(1, beta.device_writes().len());
    assert_eq!(packet, beta.device_writes()[0].data);

    fs::remove_dir_all(alpha_confbase).unwrap();
    fs::remove_dir_all(beta_confbase).unwrap();
}

#[test]
fn runtime_accepts_legacy_udp_from_unknown_address_via_try_harder_mac_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_confbase = temp_confbase("runtime-legacy-try-harder-alpha");
    let beta_confbase = temp_confbase("runtime-legacy-try-harder-beta");
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(alpha_confbase).unwrap();
            fs::remove_dir_all(beta_confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind alpha legacy listener: {error}"),
    };
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(alpha_confbase).unwrap();
            fs::remove_dir_all(beta_confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind beta legacy listener: {error}"),
    };
    let sender = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(alpha_confbase).unwrap();
            fs::remove_dir_all(beta_confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind alternate legacy UDP sender: {error}"),
    };
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let sender_addr = sender.local_addr().unwrap();
    assert_ne!(beta_addr, sender_addr);

    fs::write(
        alpha_confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nStrictSubnets = yes\n",
    )
    .unwrap();
    fs::write(
        alpha_confbase.join("hosts").join("alpha"),
        "Subnet = 10.1.0.0/16\n",
    )
    .unwrap();
    fs::write(
        alpha_confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nSubnet = 10.2.0.0/16\n",
            beta_addr.ip(),
            beta_addr.port()
        ),
    )
    .unwrap();
    fs::write(
        beta_confbase.join("tinc.conf"),
        "Name = beta\nAddressFamily = IPv4\nStrictSubnets = yes\n",
    )
    .unwrap();
    fs::write(
        beta_confbase.join("hosts").join("beta"),
        "Subnet = 10.2.0.0/16\n",
    )
    .unwrap();
    fs::write(
        beta_confbase.join("hosts").join("alpha"),
        format!(
            "Address = {} {}\nSubnet = 10.1.0.0/16\n",
            alpha_addr.ip(),
            alpha_addr.port()
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
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(test_key(2)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);
    alpha.state.graph.node_mut("beta").unwrap().status.reachable = true;
    beta.state.graph.node_mut("alpha").unwrap().status.reachable = true;

    let beta_key_message = match beta
        .generate_legacy_answer_key_message_with("alpha", |bytes| {
            bytes.fill(0x42);
            Ok(())
        })
        .unwrap()
    {
        MetaMessage::AnswerKey(message) => message,
        _ => panic!("expected legacy ANS_KEY"),
    };
    alpha
        .apply_legacy_answer_key_message(&beta_key_message)
        .unwrap();
    assert!(beta.state.graph.node("alpha").unwrap().status.valid_key_in);
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key);
    assert!(beta.udp_source_node(sender_addr).is_none());

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    let datagram = alpha
        .legacy_codec
        .encode("beta", &VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    sender.send_to(&datagram, beta_addr).unwrap();
    beta.poll_once().unwrap();

    assert_eq!(Some(&0), beta.udp_socket_by_peer.get("alpha"));
    assert_eq!(1, beta.device_writes().len());
    assert_eq!(packet, beta.device_writes()[0].data);
    assert_eq!(1, beta.traffic["alpha"].in_packets);
    assert_eq!(packet.len() as u64, beta.traffic["alpha"].in_bytes);
    let alpha_node = beta.state.graph.node("alpha").unwrap();
    assert_eq!(
        Some(sender_addr),
        alpha_node
            .udp_address
            .as_ref()
            .and_then(edge_endpoint_socket_addr),
        "C handle_incoming_vpn_packet() updates legacy n->address after receive_udppacket() succeeds"
    );
    assert!(
        !alpha_node.status.udp_confirmed,
        "C update_node_udp() clears udp_confirmed for legacy peers too"
    );
    assert_eq!(Some("alpha".to_owned()), beta.udp_source_node(sender_addr));

    fs::remove_dir_all(alpha_confbase).unwrap();
    fs::remove_dir_all(beta_confbase).unwrap();
}

#[test]
fn runtime_legacy_try_harder_hard_scan_is_rate_limited_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let server = config_tree(&[
        ("Name", "beta"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]);
    let alpha_host = config_tree(&[("Subnet", "10.1.0.0/16")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("alpha", &alpha_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: None,
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut beta = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let alpha = beta.state.graph.node_mut("alpha").unwrap();
    alpha.status.reachable = true;
    alpha.route.next_hop = Some("alpha".to_owned());

    let answer = match beta
        .generate_legacy_answer_key_message_with("alpha", |bytes| {
            bytes.fill(0x42);
            Ok(())
        })
        .unwrap()
    {
        MetaMessage::AnswerKey(message) => message,
        _ => panic!("expected legacy ANS_KEY"),
    };
    let mut alpha_codec = LegacyUdpCodec::default();
    alpha_codec.insert_peer(
        "beta",
        LegacyPeerState::from_legacy_answer_key(&answer, beta.legacy_codec.replay_window_bytes())
            .unwrap(),
    );
    let packet = VpnPacket::new(test_ipv4_ethernet_packet([10, 2, 0, 42])).unwrap();
    let datagram = alpha_codec.encode("beta", &packet).unwrap();
    let unknown_source = "127.0.0.1:49152".parse::<SocketAddr>().unwrap();
    let now_secs = 123_456;

    assert_eq!(
        Some("alpha".to_owned()),
        beta.legacy_udp_try_harder_at(unknown_source, &datagram, now_secs)
    );
    assert_eq!(
        None,
        beta.legacy_udp_try_harder_at(unknown_source, &datagram, now_secs),
        "C try_harder() only performs one hard MAC scan per second"
    );
    assert_eq!(
        Some("alpha".to_owned()),
        beta.legacy_udp_try_harder_at(unknown_source, &datagram, now_secs + 1)
    );
}

#[test]
fn runtime_sptps_try_tx_recurses_to_legacy_relay_key_exchange_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let relay_key = test_key(3);
    let server = config_tree(&[("Name", "alpha"), ("StrictSubnets", "yes")]);
    let beta_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let relay_host = config_tree(&[]);
    let config = RuntimeConfig::from_config_tree_with_hosts(
        &server,
        [("beta", &beta_host), ("relay", &relay_host)],
    )
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut relay_stream, mut relay_driver, mut relay_connection)) =
        active_runtime_connection("relay", alpha_key, relay_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &config, keys);
    relay_connection.id = 1;
    alpha.meta_connections.push(relay_connection);
    {
        let beta = alpha.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = true;
        beta.status.valid_key = true;
        beta.status.udp_confirmed = false;
        beta.route.next_hop = Some("relay".to_owned());
        beta.route.via = Some("beta".to_owned());
        beta.options = (PROT_MINOR as u32) << 24;
    }
    {
        let relay = alpha.state.graph.node_mut("relay").unwrap();
        relay.status.reachable = true;
        relay.status.sptps = false;
        relay.status.valid_key = false;
        relay.status.valid_key_in = false;
        relay.route.next_hop = Some("relay".to_owned());
        relay.route.via = Some("relay".to_owned());
        relay.options = (PROT_MINOR as u32) << 24;
    }

    alpha.try_tx_like_tinc("beta", false).unwrap();

    let events = read_meta_events_until(&mut relay_stream, &mut relay_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha" && request.to == "relay" && request.extension.is_none()
        )
    });
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha" && answer.to == "relay" && !answer.is_sptps_handshake()
        )),
        "C try_tx_sptps() recurses into try_tx_legacy(relay) and sends ANS_KEY first"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha" && request.to == "relay" && request.extension.is_none()
        )),
        "C try_tx_sptps() recurses into try_tx_legacy(relay) and sends legacy REQ_KEY"
    );
    assert!(alpha.state.graph.node("relay").unwrap().status.valid_key_in);
    assert!(alpha.legacy_last_req_key.contains_key("relay"));
}

#[test]
fn runtime_legacy_udp_data_uses_reverse_edge_before_latest_guess_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha legacy listener: {error}"),
    };
    let edge_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind edge UDP receiver: {error}"),
    };
    let latest_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind latest UDP receiver: {error}"),
    };
    edge_receiver.set_nonblocking(true).unwrap();
    latest_receiver.set_nonblocking(true).unwrap();
    let edge_addr = edge_receiver.local_addr().unwrap();
    let latest_addr = latest_receiver.local_addr().unwrap();

    let server = config_tree(&[
        ("Name", "alpha"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &config, keys);
    alpha.state.graph.ensure_node("beta");
    alpha.state.graph.ensure_node("relay");
    alpha
        .state
        .graph
        .add_edge(Edge::new("beta", "relay", 1))
        .unwrap();
    alpha
        .state
        .graph
        .add_edge(
            Edge::new("relay", "beta", 1).with_address(EdgeEndpoint::new(
                edge_addr.ip().to_string(),
                edge_addr.port().to_string(),
            )),
        )
        .unwrap();
    let beta = alpha.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());
    beta.udp_address = Some(EdgeEndpoint::new(
        latest_addr.ip().to_string(),
        latest_addr.port().to_string(),
    ));
    alpha
        .state
        .graph
        .node_mut("relay")
        .unwrap()
        .status
        .reachable = true;

    alpha
        .apply_legacy_answer_key_message(&AnswerKeyMessage {
            from: "beta".to_owned(),
            to: "alpha".to_owned(),
            key: "42".repeat(48),
            cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
            digest: LegacyDigest::Sha256 { length: 4 }.nid(),
            mac_length: 4,
            compression: 0,
            address: None,
        })
        .unwrap();
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key);
    alpha
        .state
        .graph
        .node_mut("beta")
        .unwrap()
        .status
        .valid_key_in = true;

    let peer_options = alpha.peer_options_snapshot();
    let udp_target_snapshots = alpha.udp_target_snapshot();
    let legacy_key_snapshots = alpha.legacy_key_snapshot();
    let mut packet_codec = runtime_sptps_packet_codec(&config, &alpha.state);
    let mut legacy_codec = alpha.legacy_codec.clone();
    let mut meta_connections = Vec::new();
    let mut legacy_last_req_key = BTreeMap::new();
    let mut legacy_key_actions = Vec::new();
    let mut sptps_key_actions = Vec::new();
    let mut mtu_reductions = Vec::new();
    let mut traffic = BTreeMap::new();
    let mut pcap_packets = VecDeque::new();
    #[cfg(unix)]
    let mut pcap_subscribers = Vec::new();
    let udp_socket_by_peer = BTreeMap::new();
    let sptps_route_snapshots = alpha.sptps_route_snapshot();
    let mut udp_unconfirmed_guess_counter = 0;
    let mut transport = RuntimeUdpPacketTransport {
        local_name: &alpha.local_name,
        sockets: &alpha.listen_sockets,
        addresses: &alpha.addresses,
        udp_socket_by_peer: &udp_socket_by_peer,
        modern_peer_keys: &alpha.keys.peer_public_keys,
        meta_connections: &mut meta_connections,
        experimental: alpha.state.experimental,
        local_tcp_only: alpha.local_tcp_only,
        max_output_buffer_size: alpha.max_output_buffer_size,
        peer_options,
        packet_codec: &mut packet_codec,
        legacy_codec: &mut legacy_codec,
        udp_target_snapshots,
        udp_unconfirmed_guess_counter: &mut udp_unconfirmed_guess_counter,
        sptps_route_snapshots,
        legacy_key_snapshots,
        legacy_last_req_key: &mut legacy_last_req_key,
        legacy_key_actions: &mut legacy_key_actions,
        sptps_key_actions: &mut sptps_key_actions,
        mtu_reductions: &mut mtu_reductions,
        traffic: &mut traffic,
        pcap_packets: &mut pcap_packets,
        #[cfg(unix)]
        pcap_subscribers: &mut pcap_subscribers,
        priority_inheritance: false,
    };

    let packet = VpnPacket::new(test_ipv4_ethernet_packet([10, 2, 0, 42])).unwrap();
    transport.send_packet_to("beta", "beta", &packet).unwrap();

    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let edge_len = loop {
        match edge_receiver.recv_from(&mut buffer) {
            Ok((len, _)) => break len,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                panic!("timed out waiting for edge UDP packet")
            }
            Err(error) => panic!("failed to receive edge UDP packet: {error}"),
        }
    };
    assert!(edge_len > 0);
    assert!(matches!(
        latest_receiver.recv_from(&mut buffer),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));

    transport.send_packet_to("beta", "beta", &packet).unwrap();
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let edge_len = loop {
        match edge_receiver.recv_from(&mut buffer) {
            Ok((len, _)) => break len,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                panic!("timed out waiting for repeated edge UDP packet")
            }
            Err(error) => panic!("failed to receive repeated edge UDP packet: {error}"),
        }
    };
    assert!(edge_len > 0);

    transport.send_packet_to("beta", "beta", &packet).unwrap();
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let latest_len = loop {
        match latest_receiver.recv_from(&mut buffer) {
            Ok((len, _)) => break len,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                panic!("timed out waiting for latest UDP packet")
            }
            Err(error) => panic!("failed to receive latest UDP packet: {error}"),
        }
    };
    assert!(latest_len > 0);

    assert_eq!(0, udp_unconfirmed_guess_counter);
    assert_eq!(3, traffic["beta"].out_packets);
}

#[test]
fn runtime_legacy_over_min_mtu_uses_plain_meta_tcp_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let server = config_tree(&[
        ("Name", "alpha"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    let mut meta_connections = vec![beta_connection];
    let beta = alpha.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());
    beta.options = ((PROT_MINOR as u32) << 24) | OPTION_PMTU_DISCOVERY;
    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    beta.min_mtu = packet.len() - 1;

    let key_hex = "42".repeat(48);
    let answer = AnswerKeyMessage {
        from: "beta".to_owned(),
        to: "alpha".to_owned(),
        key: key_hex,
        cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
        digest: LegacyDigest::Sha256 { length: 4 }.nid(),
        mac_length: 4,
        compression: 0,
        address: None,
    };
    alpha.apply_legacy_answer_key_message(&answer).unwrap();
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key);

    let peer_options = alpha.peer_options_snapshot();
    let legacy_key_snapshots = alpha.legacy_key_snapshot();
    let mut packet_codec = runtime_sptps_packet_codec(&config, &alpha.state);
    let mut legacy_codec = alpha.legacy_codec.clone();
    let mut legacy_last_req_key = BTreeMap::new();
    let mut legacy_key_actions = Vec::new();
    let mut sptps_key_actions = Vec::new();
    let mut mtu_reductions = Vec::new();
    let mut traffic = BTreeMap::new();
    let mut pcap_packets = VecDeque::new();
    #[cfg(unix)]
    let mut pcap_subscribers = Vec::new();
    let addresses = NodeAddressTable::new();
    let modern_peer_keys = BTreeMap::new();
    let udp_socket_by_peer = BTreeMap::new();
    let udp_target_snapshots = alpha.udp_target_snapshot();
    let mut udp_unconfirmed_guess_counter = 0;
    let sptps_route_snapshots = alpha.sptps_route_snapshot();
    let sockets: Vec<RuntimeListenSocket> = Vec::new();
    let mut transport = RuntimeUdpPacketTransport {
        local_name: &alpha.local_name,
        sockets: &sockets,
        addresses: &addresses,
        udp_socket_by_peer: &udp_socket_by_peer,
        modern_peer_keys: &modern_peer_keys,
        meta_connections: &mut meta_connections,
        experimental: alpha.state.experimental,
        local_tcp_only: alpha.local_tcp_only,
        max_output_buffer_size: alpha.max_output_buffer_size,
        peer_options,
        packet_codec: &mut packet_codec,
        legacy_codec: &mut legacy_codec,
        udp_target_snapshots,
        udp_unconfirmed_guess_counter: &mut udp_unconfirmed_guess_counter,
        sptps_route_snapshots,
        legacy_key_snapshots,
        legacy_last_req_key: &mut legacy_last_req_key,
        legacy_key_actions: &mut legacy_key_actions,
        sptps_key_actions: &mut sptps_key_actions,
        mtu_reductions: &mut mtu_reductions,
        traffic: &mut traffic,
        pcap_packets: &mut pcap_packets,
        #[cfg(unix)]
        pcap_subscribers: &mut pcap_subscribers,
        priority_inheritance: false,
    };

    transport
        .send_packet_to("beta", "beta", &VpnPacket::new(packet.clone()).unwrap())
        .unwrap();

    let events = read_meta_events_until(
        &mut beta_stream,
        &mut beta_driver,
        |event| matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet),
    );
    assert!(events.iter().any(|event| {
        matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
    }));
    assert_eq!(1, traffic["beta"].out_packets);
    assert_eq!(packet.len() as u64, traffic["beta"].out_bytes);
}

#[test]
fn runtime_legacy_tcponly_packet_does_not_try_udp_or_mtu_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let beta_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta UDP receiver: {error}"),
    };
    beta_receiver.set_nonblocking(true).unwrap();

    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let beta_addr = beta_receiver.local_addr().unwrap();
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_host = config_tree(&[
        ("Address", &beta_address),
        ("Subnet", "10.2.0.0/16"),
        ("TCPOnly", "yes"),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    alpha.meta_connections.push(beta_connection);
    alpha
        .apply_legacy_answer_key_message(&AnswerKeyMessage {
            from: "beta".to_owned(),
            to: "alpha".to_owned(),
            key: "42".repeat(48),
            cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
            digest: LegacyDigest::Sha256 { length: 4 }.nid(),
            mac_length: 4,
            compression: 0,
            address: None,
        })
        .unwrap();
    {
        let beta = alpha.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = false;
        beta.status.valid_key_in = true;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
        beta.options = ((PROT_MINOR as u32) << 24) | OPTION_TCPONLY | OPTION_PMTU_DISCOVERY;
        beta.min_mtu = MIN_MTU;
        beta.max_mtu = DEFAULT_MTU;
    }

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let events = read_meta_events_until(
        &mut beta_stream,
        &mut beta_driver,
        |event| matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet),
    );
    assert!(events.iter().any(|event| {
        matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
    }));
    assert!(!events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha" && request.to == "beta"
        ) || matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha" && answer.to == "beta"
        )
    }));
    assert!(
        alpha
            .udp_probe
            .get("beta")
            .and_then(|state| state.udp_ping_sent)
            .is_none(),
        "C send_packet() returns after TCPOnly legacy PACKET and does not call try_tx()"
    );
    let beta = alpha.state.graph.node("beta").unwrap();
    assert_eq!(
        MIN_MTU, beta.min_mtu,
        "C TCPOnly legacy PACKET return must not run try_mtu()"
    );
    assert_eq!(DEFAULT_MTU, beta.max_mtu);

    let mut buffer = [0u8; 2048];
    assert!(matches!(
        beta_receiver.recv_from(&mut buffer),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_legacy_udp_emsgsize_reduces_mtu_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_ipv6_listen_socket_with_mtu(1280) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping legacy EMSGSIZE MTU test: {error}");
            return;
        }
    };
    let beta_receiver = match UdpSocket::bind("[::1]:0") {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping legacy EMSGSIZE MTU test: {error}");
            return;
        }
    };
    let beta_addr = beta_receiver.local_addr().unwrap();
    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv6"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&alpha_server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: None,
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &config, keys);
    alpha
        .apply_legacy_answer_key_message(&AnswerKeyMessage {
            from: "beta".to_owned(),
            to: "alpha".to_owned(),
            key: "42".repeat(48),
            cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
            digest: LegacyDigest::Sha256 { length: 4 }.nid(),
            mac_length: 4,
            compression: 0,
            address: None,
        })
        .unwrap();
    {
        let beta = alpha.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = false;
        beta.status.valid_key_in = true;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
        beta.min_mtu = MIN_MTU;
        beta.max_mtu = DEFAULT_MTU;
        beta.mtu = DEFAULT_MTU;
    }

    let mut packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    packet.resize(DEFAULT_MTU, 0x55);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let beta = alpha.state.graph.node("beta").unwrap();
    assert_eq!(
        packet.len() - 1,
        beta.max_mtu,
        "C send_udppacket() reduces MTU to origlen - 1 on EMSGSIZE"
    );
    assert_eq!(packet.len() - 1, beta.mtu);
    assert_eq!(
        0, beta.mtu_probes,
        "C try_fix_mtu() keeps discovery active until minmtu >= maxmtu or 20 probes"
    );
    assert_eq!(1, alpha.traffic["beta"].out_packets);
    assert_eq!(packet.len() as u64, alpha.traffic["beta"].out_bytes);
}

#[test]
fn runtime_legacy_multihop_prefers_owner_via_udp_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha legacy listener: {error}"),
    };
    let beta_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta legacy receiver: {error}"),
    };
    let relay_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind relay legacy receiver: {error}"),
    };
    beta_receiver.set_nonblocking(true).unwrap();
    relay_receiver.set_nonblocking(true).unwrap();

    let beta_addr = beta_receiver.local_addr().unwrap();
    let relay_addr = relay_receiver.local_addr().unwrap();
    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let relay_address = format!("{} {}", relay_addr.ip(), relay_addr.port());
    let beta_host = config_tree(&[("Address", &beta_address), ("Subnet", "10.2.0.0/16")]);
    let relay_host = config_tree(&[("Address", &relay_address)]);
    let config = RuntimeConfig::from_config_tree_with_hosts(
        &alpha_server,
        [("beta", &beta_host), ("relay", &relay_host)],
    )
    .unwrap();
    let keys = RuntimeKeys {
        private_key: None,
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &config, keys);

    let beta_answer = AnswerKeyMessage {
        from: "beta".to_owned(),
        to: "alpha".to_owned(),
        key: "42".repeat(48),
        cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
        digest: LegacyDigest::Sha256 { length: 4 }.nid(),
        mac_length: 4,
        compression: 0,
        address: None,
    };
    let relay_answer = AnswerKeyMessage {
        from: "relay".to_owned(),
        to: "alpha".to_owned(),
        key: "24".repeat(48),
        cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
        digest: LegacyDigest::Sha256 { length: 4 }.nid(),
        mac_length: 4,
        compression: 0,
        address: None,
    };
    alpha.apply_legacy_answer_key_message(&beta_answer).unwrap();
    alpha
        .apply_legacy_answer_key_message(&relay_answer)
        .unwrap();

    {
        let relay = alpha.state.graph.node_mut("relay").unwrap();
        relay.status.reachable = true;
        relay.status.sptps = false;
        relay.status.valid_key_in = true;
        relay.options = 0;
        relay.route.next_hop = Some("relay".to_owned());
        relay.route.via = Some("relay".to_owned());
        relay.min_mtu = DEFAULT_MTU;
    }
    {
        let beta = alpha.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = false;
        beta.status.valid_key_in = true;
        beta.route.next_hop = Some("relay".to_owned());
        beta.route.via = Some("beta".to_owned());
        beta.route.distance = Some(2);
        beta.route.weighted_distance = Some(2);
        beta.min_mtu = DEFAULT_MTU;
    }

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let beta_len = loop {
        match beta_receiver.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(alpha.listen_sockets[0].info().address, source);
                break len;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                panic!("timed out waiting for legacy UDP datagram to final owner")
            }
            Err(error) => panic!("failed to receive beta legacy UDP datagram: {error}"),
        }
    };

    assert_eq!(VpnPacket::new(packet).unwrap(), {
        let mut beta_codec = LegacyUdpCodec::default();
        let mut beta_peer = LegacyPeerState::new(DEFAULT_REPLAY_WINDOW_BYTES);
        beta_peer
            .apply_incoming_legacy_answer_key(&beta_answer)
            .unwrap();
        beta_codec.insert_peer("alpha", beta_peer);
        beta_codec.decode("alpha", &buffer[..beta_len]).unwrap()
    });
    assert!(matches!(
        relay_receiver.recv_from(&mut buffer),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert_eq!(1, alpha.traffic["beta"].out_packets);
    assert!(!alpha.traffic.contains_key("relay"));
}
