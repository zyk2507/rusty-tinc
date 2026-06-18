use super::*;

#[test]
fn runtime_autoconnect_makes_new_connection_when_below_three_edges_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let remote_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind autoconnect listener: {error}"),
    };
    let remote_addr = remote_listener.local_addr().unwrap();
    let server = config_tree(&[("Name", "alpha"), ("AutoConnect", "yes")]);
    let beta_host = config_tree(&[
        (
            "Address",
            &format!("{} {}", remote_addr.ip(), remote_addr.port()),
        ),
        ("Ed25519PublicKey", &beta_key.public_key().to_base64()),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert_eq!(
        1,
        runtime.do_autoconnect_like_tinc(&config).unwrap(),
        "C do_autoconnect() calls make_new_connection() when there are fewer than three active edge connections"
    );

    let (remote_stream, _) = remote_listener.accept().unwrap();
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    assert_eq!(
        Some("beta".to_owned()),
        runtime.meta_connection_infos()[0].name
    );
}

#[test]
fn runtime_autoconnect_respects_disabled_autoconnect_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let remote_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind disabled autoconnect listener: {error}"),
    };
    let remote_addr = remote_listener.local_addr().unwrap();
    let server = config_tree(&[("Name", "alpha"), ("AutoConnect", "no")]);
    let beta_host = config_tree(&[
        (
            "Address",
            &format!("{} {}", remote_addr.ip(), remote_addr.port()),
        ),
        ("Ed25519PublicKey", &beta_key.public_key().to_base64()),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert_eq!(0, runtime.do_autoconnect_like_tinc(&config).unwrap());
    assert!(runtime.meta_connection_infos().is_empty());
}

#[test]
fn runtime_autoconnect_failed_outgoing_is_retried_later_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to reserve autoconnect retry address: {error}"),
    };
    let remote_addr = probe.local_addr().unwrap();
    drop(probe);
    let server = config_tree(&[
        ("Name", "alpha"),
        ("AutoConnect", "yes"),
        ("MaxTimeout", "8"),
    ]);
    let beta_host = config_tree(&[
        (
            "Address",
            &format!("{} {}", remote_addr.ip(), remote_addr.port()),
        ),
        ("Ed25519PublicKey", &beta_key.public_key().to_base64()),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert_eq!(0, runtime.do_autoconnect_like_tinc(&config).unwrap());
    assert_eq!(5, runtime.autoconnect_outgoing["beta"].timeout_secs);
    let first_next_attempt = runtime.autoconnect_outgoing["beta"].next_attempt;

    assert_eq!(0, runtime.do_autoconnect_like_tinc(&config).unwrap());
    assert_eq!(
        first_next_attempt, runtime.autoconnect_outgoing["beta"].next_attempt,
        "C make_new_connection() leaves an outgoing_t in outgoing_list, so a second autoconnect pass does not create a duplicate immediate attempt"
    );

    let remote_listener = match TcpListener::bind(remote_addr) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => return,
        Err(error) => panic!("failed to bind autoconnect retry listener: {error}"),
    };
    runtime
        .autoconnect_outgoing
        .get_mut("beta")
        .unwrap()
        .next_attempt = Instant::now() - StdDuration::from_secs(1);

    assert_eq!(1, runtime.do_autoconnect_like_tinc(&config).unwrap());
    let (remote_stream, _) = remote_listener.accept().unwrap();
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    assert_eq!(0, runtime.autoconnect_outgoing["beta"].timeout_secs);
}

#[test]
fn runtime_autoconnect_does_not_make_new_connection_at_three_edges_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let delta_key = test_key(4);
    let epsilon_key = test_key(5);
    let remote_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind autoconnect extra listener: {error}"),
    };
    let remote_addr = remote_listener.local_addr().unwrap();
    let server = config_tree(&[("Name", "alpha"), ("AutoConnect", "yes")]);
    let epsilon_host = config_tree(&[
        (
            "Address",
            &format!("{} {}", remote_addr.ip(), remote_addr.port()),
        ),
        ("Ed25519PublicKey", &epsilon_key.public_key().to_base64()),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("epsilon", &epsilon_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
            ("delta".to_owned(), delta_key.public_key()),
            ("epsilon".to_owned(), epsilon_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    for (index, (name, key)) in [
        ("beta", beta_key),
        ("gamma", gamma_key),
        ("delta", delta_key),
    ]
    .into_iter()
    .enumerate()
    {
        let Some((_stream, _driver, mut connection)) =
            active_runtime_connection(name, alpha_key.clone(), key)
        else {
            return;
        };
        connection.id = index as u64 + 1;
        runtime.meta_connections.push(connection);
        runtime.state.graph.ensure_node(name);
        runtime
            .state
            .graph
            .add_edge(Edge::new("alpha", name, 1))
            .unwrap();
    }
    runtime.state.graph.ensure_node("epsilon");
    runtime
        .state
        .graph
        .node_mut("epsilon")
        .unwrap()
        .status
        .has_address = true;
    runtime
        .state
        .graph
        .node_mut("epsilon")
        .unwrap()
        .status
        .reachable = true;

    assert_eq!(0, runtime.do_autoconnect_like_tinc(&config).unwrap());
    assert!(
        !runtime.has_meta_connection_with_name("epsilon"),
        "C do_autoconnect() does not call make_new_connection() once three active edge connections exist; reachable selected nodes are ignored by connect_to_unreachable()"
    );
}

#[test]
fn runtime_autoconnect_after_edge_cut_adds_only_one_target_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let delta_key = test_key(4);
    let epsilon_key = test_key(5);
    let epsilon_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind edge-cut autoconnect listener: {error}"),
    };
    let epsilon_addr = epsilon_listener.local_addr().unwrap();
    let server = config_tree(&[("Name", "alpha"), ("AutoConnect", "yes")]);
    let epsilon_host = config_tree(&[
        (
            "Address",
            &format!("{} {}", epsilon_addr.ip(), epsilon_addr.port()),
        ),
        ("Ed25519PublicKey", &epsilon_key.public_key().to_base64()),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("epsilon", &epsilon_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
            ("delta".to_owned(), delta_key.public_key()),
            ("epsilon".to_owned(), epsilon_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    for (index, (name, key)) in [
        ("beta", beta_key),
        ("gamma", gamma_key),
        ("delta", delta_key),
    ]
    .into_iter()
    .enumerate()
    {
        let Some((_stream, _driver, mut connection)) =
            active_runtime_connection(name, alpha_key.clone(), key)
        else {
            return;
        };
        connection.id = index as u64 + 1;
        runtime.meta_connections.push(connection);
        runtime.state.graph.ensure_node(name);
        runtime
            .state
            .graph
            .add_edge(Edge::new("alpha", name, 1))
            .unwrap();
    }
    runtime.state.graph.ensure_node("epsilon");
    runtime
        .state
        .graph
        .node_mut("epsilon")
        .unwrap()
        .status
        .has_address = true;

    let before_cut = runtime.meta_connection_infos().len();
    assert_eq!(3, before_cut);
    let delta_index = runtime
        .meta_connections
        .iter()
        .position(|connection| connection.active_name() == Some("delta"))
        .unwrap();
    runtime.close_meta_connection(delta_index).unwrap();
    assert_eq!(2, runtime.active_edge_connection_count_like_tinc());

    assert_eq!(
        1,
        runtime.do_autoconnect_like_tinc(&config).unwrap(),
        "C do_autoconnect() sees fewer than three active edge connections after a cut, calls make_new_connection() once, and returns"
    );
    let (remote_stream, _) = epsilon_listener.accept().unwrap();
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    assert!(runtime.has_meta_connection_with_name("epsilon"));
    assert_eq!(
        before_cut,
        runtime.meta_connection_infos().len(),
        "one lost edge is replaced by exactly one new autoconnect target in this tick"
    );
}

#[test]
fn runtime_autoconnect_cancels_pending_when_edges_are_sufficient_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let delta_key = test_key(4);
    let epsilon_key = test_key(5);
    let server = config_tree(&[
        ("Name", "alpha"),
        ("AutoConnect", "yes"),
        ("MaxTimeout", "8"),
    ]);
    let epsilon_host = config_tree(&[
        ("Address", "127.0.0.1 1"),
        ("Ed25519PublicKey", &epsilon_key.public_key().to_base64()),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("epsilon", &epsilon_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
            ("delta".to_owned(), delta_key.public_key()),
            ("epsilon".to_owned(), epsilon_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime
        .state
        .graph
        .node_mut("epsilon")
        .unwrap()
        .status
        .has_address = true;

    runtime.mark_autoconnect_failed("epsilon", Instant::now());
    assert!(
        runtime.autoconnect_outgoing.contains_key("epsilon"),
        "failed setup_outgoing_connection() leaves an outgoing_t waiting for retry"
    );

    for (index, (name, key)) in [
        ("beta", beta_key),
        ("gamma", gamma_key),
        ("delta", delta_key),
    ]
    .into_iter()
    .enumerate()
    {
        let Some((_stream, _driver, mut connection)) =
            active_runtime_connection(name, alpha_key.clone(), key)
        else {
            return;
        };
        connection.id = index as u64 + 1;
        runtime.meta_connections.push(connection);
        runtime.state.graph.ensure_node(name);
        runtime
            .state
            .graph
            .add_edge(Edge::new("alpha", name, 1))
            .unwrap();
    }
    runtime
        .state
        .graph
        .node_mut("epsilon")
        .unwrap()
        .status
        .reachable = true;

    assert_eq!(0, runtime.do_autoconnect_like_tinc(&config).unwrap());
    assert!(
        !runtime.autoconnect_outgoing.contains_key("epsilon"),
        "C drop_superfluous_pending_connections() cancels outgoing_t entries that are waiting for retry when enough active edges exist; reachable nodes are not immediately re-added by connect_to_unreachable()"
    );
}

#[test]
fn runtime_autoconnect_tries_selected_unreachable_node_when_edges_are_sufficient_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let delta_key = test_key(4);
    let epsilon_key = test_key(5);
    let remote_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind unreachable autoconnect listener: {error}"),
    };
    let remote_addr = remote_listener.local_addr().unwrap();
    let server = config_tree(&[("Name", "alpha"), ("AutoConnect", "yes")]);
    let epsilon_host = config_tree(&[
        (
            "Address",
            &format!("{} {}", remote_addr.ip(), remote_addr.port()),
        ),
        ("Ed25519PublicKey", &epsilon_key.public_key().to_base64()),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("epsilon", &epsilon_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
            ("delta".to_owned(), delta_key.public_key()),
            ("epsilon".to_owned(), epsilon_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    for (index, (name, key)) in [
        ("beta", beta_key),
        ("gamma", gamma_key),
        ("delta", delta_key),
    ]
    .into_iter()
    .enumerate()
    {
        let Some((_stream, _driver, mut connection)) =
            active_runtime_connection(name, alpha_key.clone(), key)
        else {
            return;
        };
        connection.id = index as u64 + 1;
        runtime.meta_connections.push(connection);
        runtime.state.graph.ensure_node(name);
        runtime
            .state
            .graph
            .add_edge(Edge::new("alpha", name, 1))
            .unwrap();
    }
    runtime.state.graph.ensure_node("epsilon");
    runtime
        .state
        .graph
        .node_mut("epsilon")
        .unwrap()
        .status
        .has_address = true;
    let epsilon_index = runtime
        .state
        .graph
        .nodes()
        .position(|node| node.name == "epsilon")
        .unwrap();

    assert_eq!(
        1,
        runtime
            .connect_to_unreachable_at_index_like_tinc(&config, epsilon_index)
            .unwrap(),
        "C connect_to_unreachable() connects to the selected unreachable node when it has an address and no active connection"
    );
    let (remote_stream, _) = remote_listener.accept().unwrap();
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    assert!(runtime.has_meta_connection_with_name("epsilon"));
}

#[test]
fn runtime_autoconnect_unreachable_selection_respects_pending_outgoing_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let epsilon_key = test_key(5);
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to reserve unreachable pending address: {error}"),
    };
    let remote_addr = probe.local_addr().unwrap();
    drop(probe);
    let server = config_tree(&[
        ("Name", "alpha"),
        ("AutoConnect", "yes"),
        ("MaxTimeout", "8"),
    ]);
    let epsilon_host = config_tree(&[
        (
            "Address",
            &format!("{} {}", remote_addr.ip(), remote_addr.port()),
        ),
        ("Ed25519PublicKey", &epsilon_key.public_key().to_base64()),
    ]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("epsilon", &epsilon_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("epsilon".to_owned(), epsilon_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.state.graph.ensure_node("epsilon");
    runtime
        .state
        .graph
        .node_mut("epsilon")
        .unwrap()
        .status
        .has_address = true;
    let epsilon_index = runtime
        .state
        .graph
        .nodes()
        .position(|node| node.name == "epsilon")
        .unwrap();

    assert_eq!(
        0,
        runtime
            .connect_to_unreachable_at_index_like_tinc(&config, epsilon_index)
            .unwrap()
    );
    assert!(runtime.autoconnect_outgoing.contains_key("epsilon"));
    let next_attempt = runtime.autoconnect_outgoing["epsilon"].next_attempt;

    assert_eq!(
        0,
        runtime
            .connect_to_unreachable_at_index_like_tinc(&config, epsilon_index)
            .unwrap(),
        "C connect_to_unreachable() returns when outgoing_list already contains the selected node"
    );
    assert_eq!(
        next_attempt,
        runtime.autoconnect_outgoing["epsilon"].next_attempt
    );
    assert!(runtime.meta_connection_infos().is_empty());
}
