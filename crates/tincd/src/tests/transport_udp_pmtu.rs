use super::*;

#[test]
fn udp_target_selection_matches_tinc_unconfirmed_edge_and_latest_guess_cycle() {
    tinc_test_support::assert_can_create_netns();
    let latest = "127.0.0.1:10001".parse::<SocketAddr>().unwrap();
    let edge = "127.0.0.1:10002".parse::<SocketAddr>().unwrap();
    let snapshot = RuntimeUdpTargetSnapshot {
        latest: Some(latest),
        udp_confirmed: false,
        edge_candidates: vec![Some(edge)],
        local_candidates: Vec::new(),
    };
    let mut counter = 0;

    assert_eq!(
        Some(edge),
        choose_udp_target_from_snapshot(&snapshot, &mut counter)
    );
    assert_eq!(
        Some(edge),
        choose_udp_target_from_snapshot(&snapshot, &mut counter)
    );
    assert_eq!(
        Some(latest),
        choose_udp_target_from_snapshot(&snapshot, &mut counter)
    );
    assert_eq!(0, counter);

    let confirmed = RuntimeUdpTargetSnapshot {
        udp_confirmed: true,
        ..snapshot
    };
    assert_eq!(
        Some(latest),
        choose_udp_target_from_snapshot(&confirmed, &mut counter)
    );
    assert_eq!(0, counter);
}

#[test]
fn runtime_try_udp_sends_sptps_probe_request_like_tinc() {
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
    let alpha_addr = alpha_socket.info().address;
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
    let beta_config =
        RuntimeConfig::from_config_tree_with_hosts(&beta_server, [("alpha", &beta_alpha_host)])
            .unwrap();
    let alpha_config =
        RuntimeConfig::from_config_tree_with_hosts(&alpha_server, [("beta", &alpha_beta_host)])
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
    beta.state.graph.ensure_node("alpha");
    let beta_peer = beta.state.graph.node_mut("alpha").unwrap();
    beta_peer.status.reachable = true;
    beta_peer.options = options;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    alpha.try_udp_for_peer("beta").unwrap();

    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let len = loop {
        match beta.listen_sockets[0].udp.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(alpha.listen_sockets[0].info().address, source);
                break len;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive UDP probe request: {error}"),
        }
    };
    let record = beta
        .packet_codec
        .decode_record("alpha", &buffer[..len])
        .unwrap();

    assert_eq!(SPTPS_UDP_PROBE_TYPE, record.record_type);
    assert_eq!(UDP_PROBE_MIN_SIZE, record.payload.len());
    assert_eq!(&[0u8; 14], &record.payload[..14]);
    let beta_node = alpha.state.graph.node("beta").unwrap();
    assert!(beta_node.status.ping_sent);
    assert!(alpha.udp_probe["beta"].udp_ping_sent.is_some());
}

#[test]
fn runtime_meta_ping_timer_retries_udp_probe_after_recent_meta_activity_like_tinc() {
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

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("PingInterval", "1"),
        ("PingTimeout", "1"),
        ("UDPDiscoveryInterval", "0"),
    ]);
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
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    let options = (PROT_MINOR as u32) << 24;
    let alpha_peer = alpha.state.graph.node_mut("beta").unwrap();
    alpha_peer.status.reachable = true;
    alpha_peer.status.sptps = true;
    alpha_peer.options = options;
    alpha_peer.route.next_hop = Some("beta".to_owned());
    alpha_peer.route.via = Some("beta".to_owned());
    let beta_peer = beta.state.graph.node_mut("alpha").unwrap();
    beta_peer.status.reachable = true;
    beta_peer.status.sptps = true;
    beta_peer.options = options;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    beta_connection.id = 11;
    beta_connection.edge_peer = Some("beta".to_owned());
    let now = Instant::now();
    beta_connection.last_activity = now;
    beta_connection.last_ping_time = now - alpha.ping_timeout;
    alpha.meta_connections.push(beta_connection);
    alpha.local_edge_connections.insert("beta".to_owned(), 11);
    alpha.next_meta_ping_check = now - StdDuration::from_secs(1);

    alpha.run_meta_ping_timer_once_like_tinc().unwrap();

    let payload = recv_sptps_probe_payload(&mut beta, "alpha", alpha_addr);
    assert_eq!(UDP_PROBE_MIN_SIZE, payload.len());
    assert!(
        alpha.state.graph.node("beta").unwrap().status.ping_sent,
        "C timeout_handler() calls try_tx(..., false) even after recent meta activity"
    );
    assert!(
        alpha.udp_probe["beta"].udp_ping_sent.is_some(),
        "C try_udp() records a probe in flight from the keepalive pass"
    );
}

#[test]
fn runtime_try_udp_uses_reverse_edge_address_before_latest_guess_like_tinc() {
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
    let edge_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind edge UDP receiver: {error}"),
    };
    edge_receiver.set_nonblocking(true).unwrap();
    let beta_addr = beta_socket.info().address;
    let alpha_addr = alpha_socket.info().address;
    let edge_addr = edge_receiver.local_addr().unwrap();
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
    alpha.state.graph.ensure_node("relay");
    alpha
        .state
        .graph
        .upsert_edge(Edge::new("beta", "relay", 1))
        .unwrap();
    alpha
        .state
        .graph
        .upsert_edge(
            Edge::new("relay", "beta", 1).with_address(EdgeEndpoint::new(
                edge_addr.ip().to_string(),
                edge_addr.port().to_string(),
            )),
        )
        .unwrap();
    beta.state.graph.ensure_node("alpha");
    let beta_peer = beta.state.graph.node_mut("alpha").unwrap();
    beta_peer.status.reachable = true;
    beta_peer.options = options;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    alpha.try_udp_for_peer("beta").unwrap();

    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    let len = loop {
        match edge_receiver.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(alpha.listen_sockets[0].info().address, source);
                break len;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive edge UDP probe request: {error}"),
        }
    };
    let record = beta
        .packet_codec
        .decode_record("alpha", &buffer[..len])
        .unwrap();

    assert_eq!(SPTPS_UDP_PROBE_TYPE, record.record_type);
    assert_eq!(UDP_PROBE_MIN_SIZE, record.payload.len());
    assert!(alpha.state.graph.node("beta").unwrap().status.ping_sent);
}

#[test]
fn runtime_try_udp_local_discovery_sends_duplicate_to_edge_local_address_like_tinc() {
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
    let local_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind local discovery receiver: {error}"),
    };
    local_receiver.set_nonblocking(true).unwrap();
    let beta_addr = beta_socket.info().address;
    let alpha_addr = alpha_socket.info().address;
    let local_addr = local_receiver.local_addr().unwrap();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    let alpha_server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("LocalDiscovery", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let alpha_beta_host = config_tree(&[("Address", &beta_address)]);
    let beta_server = config_tree(&[("Name", "beta"), ("AddressFamily", "IPv4")]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[("Address", &alpha_address)]);
    let beta_config =
        RuntimeConfig::from_config_tree_with_hosts(&beta_server, [("alpha", &beta_alpha_host)])
            .unwrap();
    let alpha_config =
        RuntimeConfig::from_config_tree_with_hosts(&alpha_server, [("beta", &alpha_beta_host)])
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
    alpha_peer.route.previous_edge = Some(tinc_core::graph::EdgeKey::new("beta", "alpha"));
    alpha
        .state
        .graph
        .upsert_edge(
            Edge::new("beta", "alpha", 1).with_local_address(EdgeEndpoint::new(
                local_addr.ip().to_string(),
                local_addr.port().to_string(),
            )),
        )
        .unwrap();
    beta.state.graph.ensure_node("alpha");
    let beta_peer = beta.state.graph.node_mut("alpha").unwrap();
    beta_peer.status.reachable = true;
    beta_peer.options = options;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    alpha.try_udp_for_peer("beta").unwrap();

    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    loop {
        match beta.listen_sockets[0].udp.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(alpha.listen_sockets[0].info().address, source);
                assert!(len > 0);
                break;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive regular UDP probe request: {error}"),
        }
    }
    loop {
        match local_receiver.recv_from(&mut buffer) {
            Ok((len, source)) => {
                assert_eq!(alpha.listen_sockets[0].info().address, source);
                assert!(len > 0);
                break;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to receive local UDP probe request: {error}"),
        }
    }
    let beta_node = alpha.state.graph.node("beta").unwrap();
    assert!(beta_node.status.ping_sent);
    assert!(!beta_node.status.send_locally);
}

#[test]
fn pmtu_initial_probe_formula_matches_tinc_float_schedule() {
    tinc_test_support::assert_can_create_netns();
    #[cfg(not(feature = "jumbograms"))]
    {
        assert_eq!(1330, pmtu_initial_probe_len(0, DEFAULT_MTU, 0));
        assert_eq!(826, pmtu_initial_probe_len(0, DEFAULT_MTU, 1));
    }
    #[cfg(feature = "jumbograms")]
    {
        assert_eq!(6996, pmtu_initial_probe_len(0, DEFAULT_MTU, 0));
        assert_eq!(2362, pmtu_initial_probe_len(0, DEFAULT_MTU, 1));
    }
    assert_eq!(513, pmtu_initial_probe_len(0, DEFAULT_MTU, 7));
    assert_eq!(900, pmtu_initial_probe_len(0, 900, 0));
}

#[test]
fn runtime_try_mtu_sends_initial_sptps_probe_like_tinc() {
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

    let options = ((PROT_MINOR as u32) << 24) | OPTION_PMTU_DISCOVERY;
    let alpha_peer = alpha.state.graph.node_mut("beta").unwrap();
    alpha_peer.status.reachable = true;
    alpha_peer.status.udp_confirmed = true;
    alpha_peer.options = options;
    let beta_peer = beta.state.graph.node_mut("alpha").unwrap();
    beta_peer.status.reachable = true;
    beta_peer.options = options;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);

    alpha.try_mtu_for_peer("beta").unwrap();

    let max_mtu = alpha.state.graph.node("beta").unwrap().max_mtu;
    let payload = recv_sptps_probe_payload(&mut beta, "alpha", alpha_addr);
    assert_eq!(pmtu_initial_probe_len(0, max_mtu, 0), payload.len());
    assert_eq!(&[0u8; 14], &payload[..14]);
    let beta_node = alpha.state.graph.node("beta").unwrap();
    assert_eq!(1, beta_node.mtu_probes);
    assert!(alpha.udp_probe["beta"].mtu_ping_sent.is_some());
}

#[test]
fn runtime_try_mtu_negative_phase_sends_max_and_plus_one_like_tinc() {
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

    let options = ((PROT_MINOR as u32) << 24) | OPTION_PMTU_DISCOVERY;
    let alpha_peer = alpha.state.graph.node_mut("beta").unwrap();
    alpha_peer.status.reachable = true;
    alpha_peer.status.udp_confirmed = true;
    alpha_peer.options = options;
    alpha_peer.mtu_probes = -1;
    alpha_peer.min_mtu = 1400;
    alpha_peer.max_mtu = 1400;
    alpha_peer.mtu = 1400;
    let beta_peer = beta.state.graph.node_mut("alpha").unwrap();
    beta_peer.status.reachable = true;
    beta_peer.options = options;
    complete_sptps_udp_exchange(&mut alpha, &mut beta);
    alpha
        .udp_probe
        .entry("beta".to_owned())
        .or_default()
        .mtu_ping_sent = Some(Instant::now() - alpha.ping_interval);

    alpha.try_mtu_for_peer("beta").unwrap();

    let first = recv_sptps_probe_payload(&mut beta, "alpha", alpha_addr);
    let second = recv_sptps_probe_payload(&mut beta, "alpha", alpha_addr);
    assert_eq!(1400, first.len());
    assert_eq!(1401, second.len());
    assert_eq!(-2, alpha.state.graph.node("beta").unwrap().mtu_probes);
}

#[test]
fn runtime_applies_udp_probe_reply_state_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let server = config_tree(&[("Name", "alpha")]);
    let beta_host = config_tree(&[("Address", "127.0.0.1 655")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.ping_sent = true;
    beta.status.udp_confirmed = false;
    beta.min_mtu = 0;
    beta.max_mtu = DEFAULT_MTU;

    let mut reply = vec![0u8; UDP_PROBE_MIN_SIZE];
    reply[0] = 2;
    reply[1..3].copy_from_slice(&1400u16.to_be_bytes());
    runtime.apply_udp_probe_reply("beta", &reply);

    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(!beta.status.ping_sent);
    assert!(beta.status.udp_confirmed);
    assert_eq!(1400, beta.min_mtu);
    assert_eq!(DEFAULT_MTU, beta.max_mtu);
    assert!(runtime.udp_probe["beta"].udp_ping_timeout.is_some());

    runtime.udp_probe.get_mut("beta").unwrap().udp_ping_timeout =
        Some(Instant::now() - StdDuration::from_secs(1));
    runtime.try_udp_for_peer("beta").unwrap();

    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(!beta.status.udp_confirmed);
    assert_eq!(0, beta.min_mtu);
    assert_eq!(DEFAULT_MTU, beta.max_mtu);
    assert_eq!(0, beta.mtu_probes);
}

#[test]
fn runtime_udp_probe_timeout_expires_from_timer_pass_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let server = config_tree(&[("Name", "alpha")]);
    let beta_host = config_tree(&[("Address", "127.0.0.1 655")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.udp_confirmed = true;
    beta.min_mtu = 1400;
    beta.max_mtu = 1400;
    beta.mtu_probes = -1;
    runtime.udp_probe.insert(
        "beta".to_owned(),
        RuntimeUdpProbeState {
            udp_ping_timeout: Some(Instant::now() - StdDuration::from_secs(1)),
            udp_ping_rtt: Some(StdDuration::from_millis(20)),
            max_recent_len: 1200,
            ..Default::default()
        },
    );

    runtime.run_timers_once_with_periodic(None).unwrap();

    let probe = runtime.udp_probe.get("beta").unwrap();
    assert_eq!(None, probe.udp_ping_timeout);
    assert_eq!(None, probe.udp_ping_rtt);
    assert_eq!(0, probe.max_recent_len);
    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(!beta.status.udp_confirmed);
    assert_eq!(0, beta.min_mtu);
    assert_eq!(DEFAULT_MTU, beta.max_mtu);
    assert_eq!(0, beta.mtu_probes);
}

#[test]
fn runtime_udp_probe_confirm_resets_address_cache_to_edge_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-udp-probe-cache-confirm");
    let old_addr: SocketAddr = "127.0.0.1:10".parse().unwrap();
    let edge_addr: SocketAddr = "127.0.0.1:1665".parse().unwrap();
    let server = config_tree(&[("Name", "alpha")]);
    let beta_host = config_tree(&[("Address", "127.0.0.1 655")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.set_confbase(confbase.clone());
    runtime
        .state
        .graph
        .add_edge(
            Edge::new("alpha", "beta", 1).with_address(EdgeEndpoint::new(
                edge_addr.ip().to_string(),
                edge_addr.port().to_string(),
            )),
        )
        .unwrap();
    {
        let beta = runtime.state.graph.node_mut("beta").unwrap();
        beta.status.ping_sent = true;
        beta.status.udp_confirmed = false;
        beta.min_mtu = 0;
        beta.max_mtu = DEFAULT_MTU;
    }
    write_tinc_address_cache(&confbase.join("cache").join("beta"), &[old_addr]).unwrap();

    let mut reply = vec![0u8; UDP_PROBE_MIN_SIZE];
    reply[0] = 2;
    reply[1..3].copy_from_slice(&1400u16.to_be_bytes());
    runtime.apply_udp_probe_reply("beta", &reply);

    assert!(
        runtime
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .udp_confirmed
    );
    assert_eq!(
        vec![edge_addr, old_addr],
        read_tinc_address_cache(&confbase.join("cache").join("beta")),
        "C receive_udppacket() reset_address_cache() keeps recent slots and add_recent_address() promotes n->connection->edge->address when UDP becomes confirmed"
    );

    let replacement: SocketAddr = "127.0.0.1:1777".parse().unwrap();
    runtime
        .state
        .graph
        .add_edge(
            Edge::new("alpha", "beta", 1).with_address(EdgeEndpoint::new(
                replacement.ip().to_string(),
                replacement.port().to_string(),
            )),
        )
        .unwrap_err();
    if let Some(edge) = runtime.state.graph.edge("alpha", "beta").cloned() {
        let updated = edge.with_address(EdgeEndpoint::new(
            replacement.ip().to_string(),
            replacement.port().to_string(),
        ));
        runtime.state.graph.upsert_edge(updated).unwrap();
    }
    runtime.apply_udp_probe_reply("beta", &reply);
    assert_eq!(
        vec![edge_addr, old_addr],
        read_tinc_address_cache(&confbase.join("cache").join("beta")),
        "C only runs the cache reset inside the !udp_confirmed transition"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_try_tx_false_does_not_run_pmtu_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind alpha listener: {error}"),
    };
    let beta_receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind beta UDP receiver: {error}"),
    };
    beta_receiver.set_nonblocking(true).unwrap();
    let beta_addr = beta_receiver.local_addr().unwrap();
    let server = config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_address = format!("{} {}", beta_addr.ip(), beta_addr.port());
    let beta_host = config_tree(&[
        ("Address", &beta_address),
        ("Subnet", "10.2.0.0/16"),
        ("PMTUDiscovery", "yes"),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
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
        beta.status.udp_confirmed = true;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
        beta.options = ((PROT_MINOR as u32) << 24) | OPTION_PMTU_DISCOVERY;
        beta.min_mtu = MIN_MTU;
        beta.max_mtu = DEFAULT_MTU;
        beta.mtu = DEFAULT_MTU;
        beta.mtu_probes = 0;
    }

    alpha.try_tx_like_tinc("beta", false).unwrap();

    assert!(
        alpha.state.graph.node("beta").unwrap().status.ping_sent,
        "C try_tx(..., false) still calls try_udp()"
    );
    let beta = alpha.state.graph.node("beta").unwrap();
    assert_eq!(
        0, beta.mtu_probes,
        "C try_tx(..., false) must not call try_mtu()"
    );
    assert_eq!(MIN_MTU, beta.min_mtu);
    assert_eq!(DEFAULT_MTU, beta.max_mtu);
}

#[test]
fn runtime_forwards_udp_and_mtu_info_messages_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("gamma".to_owned(), gamma_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key.clone(), gamma_key.clone())
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    gamma_connection.id = 1;
    runtime.meta_connections.push(gamma_connection);

    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.options = (PROT_MINOR as u32) << 24;
    beta.route.via = Some("beta".to_owned());

    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("alpha".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    let udp_info = MetaMessage::UdpInfo(UdpInfoMessage {
        from: "beta".to_owned(),
        to: "gamma".to_owned(),
        endpoint: EdgeAddress {
            address: "203.0.113.9".to_owned(),
            port: "1234".to_owned(),
        },
    });
    let mtu_info = MetaMessage::MtuInfo(MtuInfoMessage {
        from: "beta".to_owned(),
        to: "gamma".to_owned(),
        mtu: 1400,
    });
    let mut wire = gamma_driver.send_meta_message(&udp_info).unwrap();
    wire.extend(gamma_driver.send_meta_message(&mtu_info).unwrap());
    gamma_stream.write_all(&wire).unwrap();
    runtime.poll_once().unwrap();
    runtime.flush_meta_outputs().unwrap();

    let mut events = Vec::new();
    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    while Instant::now() < deadline {
        let len = match gamma_stream.read(&mut buffer) {
            Ok(len) => len,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(StdDuration::from_millis(10));
                continue;
            }
            Err(error) => panic!("failed to read forwarded info messages: {error}"),
        };
        let step = gamma_driver.receive_bytes(&buffer[..len]).unwrap();
        events.extend(step.events);
        if events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                    if message.from == "beta"
                        && message.to == "gamma"
                        && message.endpoint.address == "203.0.113.9"
                        && message.endpoint.port == "1234"
            )
        }) && events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                    if message.from == "beta" && message.to == "gamma" && message.mtu == 1400
            )
        }) {
            break;
        }
    }

    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
            if message.from == "beta"
                && message.to == "gamma"
                && message.endpoint.address == "203.0.113.9"
                && message.endpoint.port == "1234"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
            if message.from == "beta" && message.to == "gamma" && message.mtu == 1400
    )));
}

#[test]
fn runtime_udp_info_for_unknown_origin_address_uses_unspec_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("gamma".to_owned(), gamma_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key.clone(), gamma_key.clone())
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    gamma_connection.id = 1;
    runtime.meta_connections.push(gamma_connection);

    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.options = (PROT_MINOR as u32) << 24;
    beta.route.via = Some("beta".to_owned());
    beta.udp_address = None;

    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("alpha".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    runtime.send_udp_info("beta", "gamma").unwrap();

    let events = flush_then_read_meta_events_until(
        &mut runtime,
        &mut gamma_stream,
        &mut gamma_driver,
        |event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                    if message.from == "beta"
                        && message.to == "gamma"
                        && message.endpoint.address == "unspec"
                        && message.endpoint.port == "unspec"
            )
        },
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                if message.from == "beta"
                    && message.to == "gamma"
                    && message.endpoint.address == "unspec"
                    && message.endpoint.port == "unspec"
        )),
        "C protocol_misc.c::send_udp_info() forwards sockaddr2str(AF_UNSPEC) as unspec/unspec instead of dropping the message"
    );
}

#[test]
fn runtime_mtu_info_forwarding_uses_best_path_mtu_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("gamma".to_owned(), gamma_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key.clone(), gamma_key.clone())
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    gamma_connection.id = 1;
    runtime.meta_connections.push(gamma_connection);

    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("alpha".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.via = Some("alpha".to_owned());
    beta.route.next_hop = Some("beta".to_owned());
    beta.min_mtu = 1250;
    beta.max_mtu = 1250;
    beta.mtu = 1250;

    runtime.state.graph.ensure_node("delta");
    let delta = runtime.state.graph.node_mut("delta").unwrap();
    delta.status.reachable = true;
    delta.route.via = Some("static_relay".to_owned());

    runtime.state.graph.ensure_node("static_relay");
    let static_relay = runtime.state.graph.node_mut("static_relay").unwrap();
    static_relay.status.reachable = true;
    static_relay.min_mtu = 1200;
    static_relay.max_mtu = 1200;

    runtime.state.graph.ensure_node("epsilon");
    let epsilon = runtime.state.graph.node_mut("epsilon").unwrap();
    epsilon.status.reachable = true;
    epsilon.route.via = Some("dynamic_relay".to_owned());

    runtime.state.graph.ensure_node("dynamic_relay");
    let dynamic_relay = runtime.state.graph.node_mut("dynamic_relay").unwrap();
    dynamic_relay.status.reachable = true;
    dynamic_relay.route.next_hop = Some("relay_next".to_owned());

    runtime.state.graph.ensure_node("relay_next");
    let relay_next = runtime.state.graph.node_mut("relay_next").unwrap();
    relay_next.status.reachable = true;
    relay_next.min_mtu = 1100;
    relay_next.max_mtu = 1100;

    let mut wire = Vec::new();
    for from in ["beta", "delta", "epsilon"] {
        wire.extend(
            gamma_driver
                .send_meta_message(&MetaMessage::MtuInfo(MtuInfoMessage {
                    from: from.to_owned(),
                    to: "gamma".to_owned(),
                    mtu: 1400,
                }))
                .unwrap(),
        );
    }
    gamma_stream.write_all(&wire).unwrap();
    runtime.poll_once().unwrap();
    runtime.flush_meta_outputs().unwrap();

    let mut events = Vec::new();
    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    while Instant::now() < deadline {
        let len = match gamma_stream.read(&mut buffer) {
            Ok(len) => len,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(StdDuration::from_millis(10));
                continue;
            }
            Err(error) => panic!("failed to read forwarded MTU info messages: {error}"),
        };
        let step = gamma_driver.receive_bytes(&buffer[..len]).unwrap();
        events.extend(step.events);
        if events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                    if message.from == "beta" && message.to == "gamma" && message.mtu == 1250
            )
        }) && events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                    if message.from == "delta" && message.to == "gamma" && message.mtu == 1200
            )
        }) && events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                    if message.from == "epsilon" && message.to == "gamma" && message.mtu == 1100
            )
        }) {
            break;
        }
    }

    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
            if message.from == "beta" && message.to == "gamma" && message.mtu == 1250
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
            if message.from == "delta" && message.to == "gamma" && message.mtu == 1200
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
            if message.from == "epsilon" && message.to == "gamma" && message.mtu == 1100
    )));
    assert_eq!(1250, runtime.state.graph.node("beta").unwrap().mtu);
    assert_eq!(1400, runtime.state.graph.node("delta").unwrap().mtu);
    assert_eq!(1400, runtime.state.graph.node("epsilon").unwrap().mtu);
}

#[test]
fn runtime_tunnel_server_forwards_mtu_info_only_to_addressed_next_hop_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("TunnelServer", "yes"),
    ]))
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
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        return;
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    gamma_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(gamma_connection);

    for name in ["beta", "gamma"] {
        runtime.state.graph.ensure_node(name);
        let node = runtime.state.graph.node_mut(name).unwrap();
        node.status.reachable = true;
        node.route.next_hop = Some(name.to_owned());
        node.route.via = Some("alpha".to_owned());
        node.options = (PROT_MINOR as u32) << 24;
    }
    {
        let beta = runtime.state.graph.node_mut("beta").unwrap();
        beta.mtu = 1400;
        beta.min_mtu = 1400;
        beta.max_mtu = 1400;
    }

    let message = MetaMessage::MtuInfo(MtuInfoMessage {
        from: "beta".to_owned(),
        to: "gamma".to_owned(),
        mtu: DEFAULT_MTU,
    });
    beta_stream
        .write_all(&beta_driver.send_meta_message(&message).unwrap())
        .unwrap();
    runtime.poll_once().unwrap();

    let events = flush_then_read_meta_events_until(
        &mut runtime,
        &mut gamma_stream,
        &mut gamma_driver,
        |event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                    if message.from == "beta" && message.to == "gamma" && message.mtu == 1400
            )
        },
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                if message.from == "beta" && message.to == "gamma" && message.mtu == 1400
        )),
        "C mtu_info_h() continues through send_mtu_info() in TunnelServer mode and clamps to the direct beta MTU"
    );

    let mut leaked = Vec::new();
    assert_eq!(
        0,
        read_test_tcp_available(&mut beta_stream, &mut leaked),
        "C MTU_INFO is routed to to->nexthop, not broadcast to other tunnel-server clients"
    );
    assert_eq!(1400, runtime.state.graph.node("beta").unwrap().mtu);
}

#[test]
fn runtime_mtu_info_from_unknown_origin_is_not_forwarded_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("gamma".to_owned(), gamma_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    gamma_connection.id = 1;
    runtime.meta_connections.push(gamma_connection);
    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("alpha".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    gamma_stream
        .write_all(
            &gamma_driver
                .send_meta_message(&MetaMessage::MtuInfo(MtuInfoMessage {
                    from: "unknown".to_owned(),
                    to: "gamma".to_owned(),
                    mtu: 1400,
                }))
                .unwrap(),
        )
        .unwrap();
    runtime.poll_once().unwrap();
    runtime.flush_meta_outputs().unwrap();

    let mut extra = Vec::new();
    assert_eq!(
        0,
        read_test_tcp_available(&mut gamma_stream, &mut extra),
        "C mtu_info_h() returns handled without calling send_mtu_info() when the origin node is unknown"
    );
}

#[test]
fn runtime_ignores_udp_info_from_origin_past_static_relay_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("gamma".to_owned(), gamma_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((_gamma_stream, _gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    gamma_connection.id = 1;
    runtime.meta_connections.push(gamma_connection);

    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.status.udp_confirmed = false;
    beta.route.via = Some("relay".to_owned());
    beta.udp_address = Some(EdgeEndpoint::new("198.51.100.7", "655"));

    runtime.state.graph.ensure_node("relay");
    let relay = runtime.state.graph.node_mut("relay").unwrap();
    relay.status.reachable = true;
    relay.route.via = Some("relay".to_owned());

    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("alpha".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    let first_written = runtime.meta_connections[0].bytes_written;
    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::UdpInfo(
                    UdpInfoMessage {
                        from: "beta".to_owned(),
                        to: "gamma".to_owned(),
                        endpoint: EdgeAddress {
                            address: "203.0.113.9".to_owned(),
                            port: "1234".to_owned(),
                        },
                    },
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    let beta = runtime.state.graph.node("beta").unwrap();
    assert_eq!(
        Some(&EdgeEndpoint::new("198.51.100.7", "655")),
        beta.udp_address.as_ref()
    );
    assert_eq!(first_written, runtime.meta_connections[0].bytes_written);
}

#[test]
fn runtime_udp_info_does_not_override_direct_meta_connection_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        return;
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    gamma_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(gamma_connection);

    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.status.udp_confirmed = false;
    beta.options = (PROT_MINOR as u32) << 24;
    beta.route.via = Some("beta".to_owned());
    beta.udp_address = Some(EdgeEndpoint::new("198.51.100.7", "655"));

    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("alpha".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    let incoming = MetaMessage::UdpInfo(UdpInfoMessage {
        from: "beta".to_owned(),
        to: "gamma".to_owned(),
        endpoint: EdgeAddress {
            address: "203.0.113.9".to_owned(),
            port: "1234".to_owned(),
        },
    });
    let wire = gamma_driver.send_meta_message(&incoming).unwrap();
    gamma_stream.write_all(&wire).unwrap();
    runtime.poll_once().unwrap();

    let beta = runtime.state.graph.node("beta").unwrap();
    assert_eq!(
        Some(&EdgeEndpoint::new("198.51.100.7", "655")),
        beta.udp_address.as_ref()
    );

    let events = flush_then_read_meta_events_until(
        &mut runtime,
        &mut gamma_stream,
        &mut gamma_driver,
        |event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                    if message.from == "beta"
                        && message.to == "gamma"
                        && message.endpoint.address == "198.51.100.7"
                        && message.endpoint.port == "655"
            )
        },
    );
    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
            if message.from == "beta"
                && message.to == "gamma"
                && message.endpoint.address == "198.51.100.7"
                && message.endpoint.port == "655"
    )));
}

#[test]
fn runtime_udp_info_does_not_override_confirmed_udp_address_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("gamma".to_owned(), gamma_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    gamma_connection.id = 1;
    runtime.meta_connections.push(gamma_connection);

    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.status.udp_confirmed = true;
    beta.options = (PROT_MINOR as u32) << 24;
    beta.route.via = Some("beta".to_owned());
    beta.udp_address = Some(EdgeEndpoint::new("198.51.100.7", "655"));

    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("alpha".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    let incoming = MetaMessage::UdpInfo(UdpInfoMessage {
        from: "beta".to_owned(),
        to: "gamma".to_owned(),
        endpoint: EdgeAddress {
            address: "203.0.113.9".to_owned(),
            port: "1234".to_owned(),
        },
    });
    let wire = gamma_driver.send_meta_message(&incoming).unwrap();
    gamma_stream.write_all(&wire).unwrap();
    runtime.poll_once().unwrap();

    let beta = runtime.state.graph.node("beta").unwrap();
    assert_eq!(
        Some(&EdgeEndpoint::new("198.51.100.7", "655")),
        beta.udp_address.as_ref()
    );
    assert!(beta.status.udp_confirmed);

    let events = flush_then_read_meta_events_until(
        &mut runtime,
        &mut gamma_stream,
        &mut gamma_driver,
        |event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                    if message.from == "beta"
                        && message.to == "gamma"
                        && message.endpoint.address == "198.51.100.7"
                        && message.endpoint.port == "655"
            )
        },
    );
    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
            if message.from == "beta"
                && message.to == "gamma"
                && message.endpoint.address == "198.51.100.7"
                && message.endpoint.port == "655"
    )));
}

#[test]
fn runtime_throttles_local_mtu_info_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let gamma_key = test_key(3);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("MTUInfoInterval", "60"),
    ]))
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("gamma".to_owned(), gamma_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((_gamma_stream, _gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key.clone(), gamma_key.clone())
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    gamma_connection.id = 1;
    runtime.meta_connections.push(gamma_connection);

    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("alpha".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    runtime.state.graph.ensure_node("delta");
    let delta = runtime.state.graph.node_mut("delta").unwrap();
    delta.status.reachable = true;
    delta.route.next_hop = Some("gamma".to_owned());
    delta.route.via = Some("gamma".to_owned());
    delta.options = (PROT_MINOR as u32) << 24;

    runtime
        .send_mtu_info("alpha", "delta", DEFAULT_MTU)
        .unwrap();
    runtime.flush_meta_outputs().unwrap();
    let first_written = runtime.meta_connections[0].bytes_written;
    assert!(first_written > 0);

    runtime
        .send_mtu_info("alpha", "delta", DEFAULT_MTU)
        .unwrap();
    runtime.flush_meta_outputs().unwrap();
    assert_eq!(first_written, runtime.meta_connections[0].bytes_written);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn udp_listen_socket_sets_dont_fragment_for_pmtu_discovery_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("BindToAddress", "127.0.0.1 0"),
        ("PMTUDiscovery", "yes"),
    ]))
    .unwrap();
    let sockets = bind_runtime_listeners(&config).unwrap();

    assert_eq!(
        libc::IP_PMTUDISC_DO,
        socket_option_i32(
            sockets[0].udp().as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER
        )
        .unwrap()
    );

    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv6"),
        ("BindToAddress", "::1 0"),
        ("PMTUDiscovery", "yes"),
    ]))
    .unwrap();
    let sockets = bind_runtime_listeners(&config).unwrap();

    assert_eq!(
        libc::IPV6_PMTUDISC_DO,
        socket_option_i32(
            sockets[0].udp().as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER
        )
        .unwrap()
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn udp_listen_socket_leaves_fragmentation_enabled_when_pmtu_disabled_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
        ("BindToAddress", "127.0.0.1 0"),
        ("PMTUDiscovery", "no"),
    ]))
    .unwrap();
    let sockets = bind_runtime_listeners(&config).unwrap();

    assert_ne!(
        libc::IP_PMTUDISC_DO,
        socket_option_i32(
            sockets[0].udp().as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER
        )
        .unwrap()
    );
}
