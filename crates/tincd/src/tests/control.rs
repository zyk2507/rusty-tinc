use super::*;

#[test]
fn control_endpoint_writes_tinc_compatible_pidfile_and_socket_path() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-endpoint");
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());

    let mut endpoint = ControlEndpoint::new(&options);
    endpoint.cookie = "abcdef".to_owned();
    endpoint.pid = 42;
    endpoint.host = "localhost".to_owned();
    endpoint.port = "12345".to_owned();
    write_control_pidfile(&endpoint).unwrap();

    assert_eq!(confbase.join("pid"), endpoint.pidfile);
    assert_eq!(confbase.join("pid.socket"), endpoint.socket);
    assert_eq!(
        "42 abcdef localhost port 12345\n",
        fs::read_to_string(&endpoint.pidfile).unwrap()
    );

    options.pidfile = Some(confbase.join("custom.pid"));
    let endpoint = ControlEndpoint::new(&options);
    assert_eq!(confbase.join("custom.socket"), endpoint.socket);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_pidfile_endpoint_uses_first_runtime_listener_like_c_init_control() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-endpoint-listener");
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let endpoint = ControlEndpoint::new(&options);

    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let address = listener.local_addr().unwrap();
    let socket = RuntimeListenSocket {
        tcp: listener,
        udp: UdpSocket::bind("0.0.0.0:0").unwrap(),
        address,
        bind_to: false,
        priority: Cell::new(0),
    };
    let runtime_endpoint = endpoint.for_runtime_listeners(&[socket]);

    assert_eq!("127.0.0.1", runtime_endpoint.host);
    assert_eq!(address.port().to_string(), runtime_endpoint.port);

    let listener = TcpListener::bind("[::]:0").unwrap();
    let address = listener.local_addr().unwrap();
    let socket = RuntimeListenSocket {
        tcp: listener,
        udp: UdpSocket::bind("[::]:0").unwrap(),
        address,
        bind_to: false,
        priority: Cell::new(0),
    };
    let runtime_endpoint = endpoint.for_runtime_listeners(&[socket]);

    assert_eq!("::1", runtime_endpoint.host);
    assert_eq!(address.port().to_string(), runtime_endpoint.port);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn tcp_control_endpoint_pidfile_uses_listener_address_like_c_windows_control() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("tcp-control-endpoint-listener");
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let mut options = TincdOptions::new("tincd".to_owned());
    options.pidfile = Some(confbase.join("pid"));
    let endpoint = ControlEndpoint::new(&options);
    let runtime_endpoint = endpoint.for_tcp_control_listener(&listener).unwrap();

    assert_eq!("127.0.0.1", runtime_endpoint.host);
    assert_eq!(
        listener.local_addr().unwrap().port().to_string(),
        runtime_endpoint.port
    );
    write_control_pidfile(&runtime_endpoint).unwrap();
    assert_eq!(
        format!(
            "{} {} 127.0.0.1 port {}\n",
            std::process::id(),
            runtime_endpoint.cookie,
            listener.local_addr().unwrap().port()
        ),
        fs::read_to_string(&runtime_endpoint.pidfile).unwrap()
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_request_lines_return_tinc_control_responses() {
    tinc_test_support::assert_can_create_netns();
    let mut stop = false;

    assert_eq!(
        Some("18 1 0\n".to_owned()),
        handle_control_request_line("18 1", &mut stop, None, None)
    );
    assert!(!stop);

    assert_eq!(
        Some("18 9 0\n".to_owned()),
        handle_control_request_line("18 9 5", &mut stop, None, None)
    );

    assert_eq!(
        Some("18 12 -2\n".to_owned()),
        handle_control_request_line("18 12 alpha", &mut stop, None, None)
    );
    assert_eq!(
        Some("18 12 -1\n".to_owned()),
        handle_control_request_line("18 12", &mut stop, None, None)
    );
    assert_eq!(
        Some("18 -1\n".to_owned()),
        handle_control_request_line("18 11 alpha", &mut stop, None, None)
    );

    assert_eq!(
        Some("18 0 0\n".to_owned()),
        handle_control_request_line("18 0", &mut stop, None, None)
    );
    assert!(stop);
}

#[test]
fn control_log_request_streams_filtered_runtime_log_entries() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-log-runtime");
    let alpha_key = test_key(1);

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let mut config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.set_debug_level(7);
    runtime.record_log_with_priority(3, LOG_ERR, "visible control log");
    runtime.record_log_with_priority(7, LOG_DEBUG, "hidden control log");

    let mut stop = false;
    let response = handle_control_stream_request_line_mut(
        "18 15 3 0",
        &mut stop,
        Some(&mut config),
        Some(&mut runtime),
        None,
    )
    .unwrap();
    let output = String::from_utf8(response.bytes).unwrap();

    assert!(response.close_after_write);
    assert!(output.contains("18 15 "));
    assert!(output.contains("ERROR"));
    assert!(output.contains("visible control log"));
    assert!(!output.contains("hidden control log"));
    assert!(!stop);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_debug_request_returns_old_level_and_updates_runtime_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "5")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.record_log(2, "low level log");
    runtime.record_log(4, "high level log");

    let mut stop = false;
    assert_eq!(
        Some("18 9 5\n".to_owned()),
        handle_control_request_line("18 9 3", &mut stop, Some(&config), Some(&mut runtime))
    );
    assert_eq!(3, runtime.debug_level());

    assert_eq!(
        Some("18 9 3\n".to_owned()),
        handle_control_request_line("18 9 -1", &mut stop, Some(&config), Some(&mut runtime))
    );
    assert_eq!(3, runtime.debug_level());

    let response = handle_control_stream_request_line_mut(
        "18 15 -1 0",
        &mut stop,
        None,
        Some(&mut runtime),
        None,
    )
    .unwrap();
    let output = String::from_utf8(response.bytes).unwrap();
    assert!(output.contains("low level log"));
    assert!(!output.contains("high level log"));

    let response = handle_control_stream_request_line_mut(
        "18 15 5 0",
        &mut stop,
        None,
        Some(&mut runtime),
        None,
    )
    .unwrap();
    let output = String::from_utf8(response.bytes).unwrap();
    assert!(output.contains("low level log"));
    assert!(output.contains("high level log"));
}

#[test]
fn control_connect_request_is_invalid_like_c_control_h() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-connect-disconnect");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let remote_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind control connect listener: {error}"),
    };
    let remote_addr = remote_listener.local_addr().unwrap();

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            remote_addr.ip(),
            remote_addr.port(),
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let mut stop = false;

    assert_eq!(
        Some("18 -1\n".to_owned()),
        handle_control_request_line("18 11 beta", &mut stop, Some(&config), Some(&mut runtime))
    );
    assert!(
        runtime.meta_connection_infos().is_empty(),
        "C control_h() has no REQ_CONNECT case, so the request falls through to REQ_INVALID"
    );

    drop(remote_listener);
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let gamma_key = test_key(3);
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    beta_connection.id = 1;
    gamma_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(gamma_connection);
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 1 alpha beta 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 2 beta alpha 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 3 alpha gamma 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 4 gamma alpha 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 5 gamma beta 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 6 beta gamma 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    let edges_before =
        handle_control_request_line("18 4", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    assert!(edges_before.contains(" alpha beta "));

    assert_eq!(
        Some("18 12 0\n".to_owned()),
        handle_control_request_line("18 12 beta", &mut stop, Some(&config), Some(&mut runtime))
    );
    assert_eq!(1, runtime.meta_connection_infos().len());
    assert!(
        runtime
            .meta_connection_infos()
            .iter()
            .any(|info| info.name.as_deref() == Some("gamma"))
    );
    let edges_after =
        handle_control_request_line("18 4", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    assert!(
        !edges_after.contains(" alpha beta "),
        "C terminate_connection() removes the local edge before returning REQ_DISCONNECT success"
    );
    assert!(
        edges_after.contains(" beta alpha "),
        "C terminate_connection() keeps the reverse edge while the peer remains reachable through other paths"
    );
    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                if message.from == "alpha" && message.to == "beta"
        )
    });
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                    if message.from == "alpha" && message.to == "beta"
            )
        }),
        "C terminate_connection(report=true) broadcasts DEL_EDGE alpha beta"
    );

    assert_eq!(
        Some("18 12 -2\n".to_owned()),
        handle_control_request_line("18 12 beta", &mut stop, Some(&config), Some(&mut runtime))
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_disconnect_cleans_reverse_edge_only_after_peer_unreachable_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-disconnect-reverse-edge");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    beta_connection.id = 1;
    gamma_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(gamma_connection);
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 1 alpha beta 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 2 beta alpha 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();

    let mut stop = false;
    assert_eq!(
        Some("18 12 0\n".to_owned()),
        handle_control_request_line("18 12 beta", &mut stop, Some(&config), Some(&mut runtime))
    );
    let edges_after =
        handle_control_request_line("18 4", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    assert!(!edges_after.contains(" alpha beta "));
    assert!(
        !edges_after.contains(" beta alpha "),
        "C terminate_connection() removes the stale reverse edge after the peer becomes unreachable"
    );
    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                if message.from == "beta" && message.to == "alpha"
        )
    });
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                    if message.from == "alpha" && message.to == "beta"
            )
        }),
        "C terminate_connection(report=true) broadcasts the local DEL_EDGE before deleting it"
    );
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                    if message.from == "beta" && message.to == "alpha"
            )
        }),
        "C terminate_connection(report=true) broadcasts reverse stale DEL_EDGE only after beta is unreachable"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_disconnect_tunnel_server_removes_edges_without_broadcast_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-disconnect-tunnel-server");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nTunnelServer = yes\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    beta_connection.id = 1;
    gamma_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(gamma_connection);
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 1 alpha beta 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 2 beta alpha 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();

    let mut stop = false;
    assert_eq!(
        Some("18 12 0\n".to_owned()),
        handle_control_request_line("18 12 beta", &mut stop, Some(&config), Some(&mut runtime))
    );
    let edges_after =
        handle_control_request_line("18 4", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    assert!(!edges_after.contains(" alpha beta "));
    assert!(!edges_after.contains(" beta alpha "));
    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::DeleteEdge(_))
        )
    });
    assert!(
        !events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::DeleteEdge(_))
            )
        }),
        "C terminate_connection() suppresses DEL_EDGE broadcast while TunnelServer is enabled"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_remote_del_edge_cleans_stale_reverse_edge_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-remote-del-edge-stale-reverse");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let delta_key = test_key(4);
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((mut delta_stream, mut delta_driver, mut delta_connection)) =
        active_runtime_connection("delta", alpha_key, delta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    beta_connection.id = 1;
    delta_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(delta_connection);

    for request in [
        "12 1 alpha beta 127.0.0.1 655 0 7",
        "12 2 beta alpha 127.0.0.1 655 0 7",
        "12 3 beta gamma 127.0.0.1 655 0 7",
        "12 4 gamma beta 127.0.0.1 655 0 7",
        "12 5 gamma alpha 127.0.0.1 655 0 7",
    ] {
        runtime
            .apply_runtime_meta_message(parse_meta_message(request).unwrap())
            .unwrap();
    }
    assert!(runtime.state.graph.node("gamma").unwrap().status.reachable);
    assert!(runtime.state.graph.edge("gamma", "alpha").is_some());

    let delete = parse_meta_message("13 6 beta gamma").unwrap();
    let chunk = beta_driver.send_meta_message(&delete).unwrap();
    beta_stream.write_all(&chunk).unwrap();
    runtime.poll_once().unwrap();

    assert!(runtime.state.graph.edge("beta", "gamma").is_none());
    assert!(
        runtime.state.graph.edge("gamma", "alpha").is_none(),
        "C del_edge_h() removes to->myself when deleting the edge makes to unreachable"
    );
    assert!(!runtime.state.graph.node("gamma").unwrap().status.reachable);

    let events = read_meta_events_until(&mut delta_stream, &mut delta_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                if message.from == "gamma" && message.to == "alpha"
        )
    });
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                    if message.from == "beta" && message.to == "gamma"
            )
        }),
        "C del_edge_h() forwards the original DEL_EDGE to the rest of the mesh"
    );
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                    if message.from == "gamma" && message.to == "alpha"
            )
        }),
        "C del_edge_h() broadcasts a second DEL_EDGE for the stale reverse edge"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_duplicate_contradicting_add_edge_is_seen_before_correction_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-duplicate-contradicting-add-edge");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 1 alpha beta 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();

    let contradiction = parse_meta_message("12 99 alpha beta 198.51.100.99 655 0 9").unwrap();
    let chunk = beta_driver.send_meta_message(&contradiction).unwrap();
    beta_stream.write_all(&chunk).unwrap();
    runtime.poll_once().unwrap();

    let first = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                if message.edge.from == "alpha"
                    && message.edge.to == "beta"
                    && message.address == "127.0.0.1"
                    && message.edge.weight == 7
        )
    });
    assert!(
        first.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                    if message.edge.from == "alpha"
                        && message.edge.to == "beta"
                        && message.address == "127.0.0.1"
                        && message.edge.weight == 7
            )
        }),
        "C add_edge_h() sends one correction for the first contradicting ADD_EDGE"
    );

    let duplicate = beta_driver.send_meta_message(&contradiction).unwrap();
    beta_stream.write_all(&duplicate).unwrap();
    runtime.poll_once().unwrap();
    let duplicate_events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                if message.edge.from == "alpha" && message.edge.to == "beta"
        )
    });
    assert!(
        !duplicate_events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                    if message.edge.from == "alpha" && message.edge.to == "beta"
            )
        }),
        "C add_edge_h() calls seen_request() before sending correction for an already seen contradiction"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_strict_subnets_forwards_but_ignores_remote_add_subnet_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-strict-add-subnet");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nStrictSubnets = yes\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    beta_connection.id = 1;
    gamma_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(gamma_connection);

    let add = parse_meta_message("10 77 beta 10.77.0.0/16").unwrap();
    let chunk = beta_driver.send_meta_message(&add).unwrap();
    beta_stream.write_all(&chunk).unwrap();
    runtime.poll_once().unwrap();

    assert!(
        runtime
            .state
            .subnets
            .lookup_owner_subnet("beta", &"10.77.0.0/16".parse().unwrap())
            .is_none(),
        "C add_subnet_h() ignores unauthorized ADD_SUBNET locally when StrictSubnets is enabled"
    );
    assert!(
        runtime.state.graph.node("beta").is_some(),
        "C add_subnet_h() creates the owner node before the StrictSubnets ignore branch"
    );

    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AddSubnet(message))
                if message.owner == "beta"
                    && message.subnet == "10.77.0.0/16".parse().unwrap()
        )
    });
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddSubnet(message))
                    if message.owner == "beta"
                        && message.subnet == "10.77.0.0/16".parse().unwrap()
            )
        }),
        "C add_subnet_h() still forwards unauthorized ADD_SUBNET while StrictSubnets is enabled"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_strict_subnets_syncs_forwarded_unauthorized_subnet_to_late_peer_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-strict-late-forwarded-subnet");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nStrictSubnets = yes\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        "Subnet = 10.2.0.0/16\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
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
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    beta_connection.id = 1;
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.meta_connections.push(beta_connection);

    let unauthorized = parse_meta_message("10 77 beta 10.77.0.0/16").unwrap();
    let chunk = beta_driver.send_meta_message(&unauthorized).unwrap();
    beta_stream.write_all(&chunk).unwrap();
    runtime.poll_once().unwrap();

    assert!(
        runtime
            .state
            .subnets
            .lookup_owner_subnet("beta", &"10.77.0.0/16".parse().unwrap())
            .is_none(),
        "StrictSubnets must not install the unauthorized subnet locally"
    );

    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    gamma_connection.id = 2;
    runtime.meta_connections.push(gamma_connection);
    runtime
        .apply_meta_step(
            1,
            tinc_runtime::meta::MetaConnectionStep {
                outbound: Vec::new(),
                events: vec![MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                    peer: "gamma".to_owned(),
                    port: "655".to_owned(),
                    weight: 0,
                    options: (PROT_MINOR as u32) << 24,
                })],
            },
        )
        .unwrap();

    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AddSubnet(message))
                if message.owner == "beta"
                    && message.subnet == "10.77.0.0/16".parse().unwrap()
        )
    });
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AddSubnet(message))
                if message.owner == "beta"
                    && message.subnet == "10.77.0.0/16".parse().unwrap()
        )),
        "C add_subnet_h() floods unauthorized strict subnet announcements, so late peers must still learn them"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_strict_subnets_forwards_but_ignores_remote_del_subnet_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-strict-del-subnet");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nStrictSubnets = yes\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        "Subnet = 10.77.0.0/16\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    beta_connection.id = 1;
    gamma_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(gamma_connection);

    assert!(
        runtime
            .state
            .subnets
            .lookup_owner_subnet("beta", &"10.77.0.0/16".parse().unwrap())
            .is_some()
    );

    let delete = parse_meta_message("11 78 beta 10.77.0.0/16").unwrap();
    let chunk = beta_driver.send_meta_message(&delete).unwrap();
    beta_stream.write_all(&chunk).unwrap();
    runtime.poll_once().unwrap();

    assert!(
        runtime
            .state
            .subnets
            .lookup_owner_subnet("beta", &"10.77.0.0/16".parse().unwrap())
            .is_some(),
        "C del_subnet_h() forwards but does not delete known subnets when StrictSubnets is enabled"
    );

    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::DeleteSubnet(message))
                if message.owner == "beta"
                    && message.subnet == "10.77.0.0/16".parse().unwrap()
        )
    });
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::DeleteSubnet(message))
                    if message.owner == "beta"
                        && message.subnet == "10.77.0.0/16".parse().unwrap()
            )
        }),
        "C del_subnet_h() still forwards DEL_SUBNET while StrictSubnets is enabled"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_activation_closes_duplicate_connection_without_del_edge_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-duplicate-connection-activation");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let Some((_old_beta_stream, _old_beta_driver, mut old_beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((_new_beta_stream, _new_beta_driver, mut new_beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key, gamma_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    old_beta_connection.id = 1;
    new_beta_connection.id = 2;
    gamma_connection.id = 3;
    runtime.meta_connections.push(old_beta_connection);
    runtime.meta_connections.push(new_beta_connection);
    runtime.meta_connections.push(gamma_connection);
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 1 alpha beta 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 2 beta alpha 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    assert_eq!(3, runtime.meta_connection_infos().len());

    runtime
        .apply_meta_step(
            1,
            tinc_runtime::meta::MetaConnectionStep {
                outbound: Vec::new(),
                events: vec![MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                    peer: "beta".to_owned(),
                    port: "1665".to_owned(),
                    weight: 5,
                    options: (PROT_MINOR as u32) << 24,
                })],
            },
        )
        .unwrap();

    let infos = runtime.meta_connection_infos();
    assert_eq!(2, infos.len());
    assert!(
        infos
            .iter()
            .any(|info| info.id == 2 && info.name.as_deref() == Some("beta")),
        "C ack_h() keeps the newly activated duplicate connection"
    );
    assert!(
        !infos.iter().any(|info| info.id == 1),
        "C ack_h() closes the old connection to the same node"
    );
    assert!(
        runtime.state.graph.edge("alpha", "beta").is_some(),
        "the new ACK activation recreates alpha->beta after closing the old connection"
    );

    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                if message.edge.from == "alpha"
                    && message.edge.to == "beta"
                    && message.port == "1665"
        )
    });
    assert!(
        !events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::DeleteEdge(message))
                    if message.from == "alpha" && message.to == "beta"
            )
        }),
        "C ack_h() calls terminate_connection(old, false), so duplicate cleanup does not broadcast DEL_EDGE"
    );
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                    if message.edge.from == "alpha"
                        && message.edge.to == "beta"
                        && message.port == "1665"
            )
        }),
        "C ack_h() still broadcasts the new edge after duplicate cleanup"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_duplicate_activation_keeps_current_index_for_followup_messages_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-duplicate-connection-followup");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let Some((_old_beta_stream, _old_beta_driver, mut old_beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((mut new_beta_stream, mut new_beta_driver, mut new_beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    old_beta_connection.id = 1;
    new_beta_connection.id = 2;
    runtime.meta_connections.push(old_beta_connection);
    runtime.meta_connections.push(new_beta_connection);
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 1 alpha beta 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 2 beta alpha 127.0.0.1 655 0 7").unwrap(),
        )
        .unwrap();

    runtime
        .apply_meta_step(
            1,
            tinc_runtime::meta::MetaConnectionStep {
                outbound: Vec::new(),
                events: vec![
                    MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                        peer: "beta".to_owned(),
                        port: "1665".to_owned(),
                        weight: 5,
                        options: (PROT_MINOR as u32) << 24,
                    }),
                    MetaConnectionEvent::Message(
                        parse_meta_message("10 9 beta 10.2.0.0/16").unwrap(),
                    ),
                ],
            },
        )
        .unwrap();

    assert_eq!(1, runtime.meta_connection_infos().len());
    assert!(
        runtime
            .state
            .subnets
            .lookup_owner_subnet("beta", &"10.2.0.0/16".parse().unwrap())
            .is_some(),
        "C ack_h() keeps processing later requests on the newly activated duplicate connection"
    );
    let events = read_meta_events_until(&mut new_beta_stream, &mut new_beta_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                if message.edge.from == "alpha" && message.edge.to == "beta"
        )
    });
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddSubnet(message))
                    if message.owner == "alpha"
            )
        }),
        "responses after duplicate cleanup are still written to the current connection"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_retry_request_forces_configured_peer_reconnect_attempt() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-retry");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to reserve control retry address: {error}"),
    };
    let remote_addr = probe.local_addr().unwrap();
    drop(probe);

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nConnectTo = beta\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            remote_addr.ip(),
            remote_addr.port(),
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert_eq!(0, runtime.retry_configured_peers(&config).unwrap());

    let remote_listener = match TcpListener::bind(remote_addr) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind control retry listener: {error}"),
    };
    assert_eq!(0, runtime.retry_configured_peers(&config).unwrap());

    let mut stop = false;
    assert_eq!(
        Some("18 10 0\n".to_owned()),
        handle_control_request_line("18 10", &mut stop, Some(&config), Some(&mut runtime))
    );

    let (remote_stream, _) = remote_listener.accept().unwrap();
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);

    let connections = runtime.meta_connection_infos();
    assert_eq!(1, connections.len());
    assert_eq!(Some("beta".to_owned()), connections[0].name);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_purge_request_removes_unreachable_runtime_state() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-purge");
    let alpha_key = test_key(1);
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAutoConnect = no\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime
        .state
        .apply_meta_message(parse_meta_message("10 1 beta 10.2.0.0/16").unwrap())
        .unwrap();
    runtime
        .state
        .apply_meta_message(parse_meta_message("12 2 beta gamma 198.51.100.9 655 0 7").unwrap())
        .unwrap();

    let mut stop = false;
    let subnets_before =
        handle_control_request_line("18 5", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    assert!(subnets_before.contains("18 5 10.2.0.0/16 beta\n"));

    assert_eq!(
        Some("18 8 0\n".to_owned()),
        handle_control_request_line("18 8", &mut stop, Some(&config), Some(&mut runtime))
    );

    let subnets_after =
        handle_control_request_line("18 5", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    let edges_after =
        handle_control_request_line("18 4", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    assert!(!subnets_after.contains("10.2.0.0/16 beta"));
    assert!(!edges_after.contains(" beta gamma "));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_reload_request_rereads_config_and_retries_new_connect_to() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-reload-runtime");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let remote_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind reload listener: {error}"),
    };
    let remote_addr = remote_listener.local_addr().unwrap();

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!("Ed25519PublicKey = {}\n", beta_key.public_key().to_base64()),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let mut config = load_runtime_config(&options).unwrap();
    let keys = load_runtime_keys(&options).unwrap();
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert_eq!(Vec::<String>::new(), config.connect_to);
    assert_eq!(
        vec!["10.0.0.0/8"],
        runtime
            .state()
            .subnets
            .owner_subnets("alpha")
            .map(|subnet| subnet.to_string())
            .collect::<Vec<_>>()
    );

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nConnectTo = beta\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.1.0.0/16\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            remote_addr.ip(),
            remote_addr.port(),
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();

    let mut stop = false;
    assert_eq!(
        Some("18 1 0\n".to_owned()),
        handle_control_request_line_mut(
            "18 1",
            &mut stop,
            Some(&mut config),
            Some(&mut runtime),
            Some(&options),
        )
    );

    let (remote_stream, _) = remote_listener.accept().unwrap();
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);

    assert_eq!(vec!["beta"], config.connect_to);
    assert_eq!(
        vec!["10.1.0.0/16"],
        runtime
            .state()
            .subnets
            .owner_subnets("alpha")
            .map(|subnet| subnet.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(Some(remote_addr), config.addresses.address("beta"));
    assert_eq!(
        Some("beta".to_owned()),
        runtime.meta_connection_infos()[0].name
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_dump_requests_report_loaded_runtime_state() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-dumps");
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nConnectTo = beta\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Port = 12345\nSubnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        "Address = 192.0.2.7 777\nSubnet = 10.2.0.0/16\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let mut config = load_runtime_config(&options).unwrap();
    config
        .state
        .graph
        .add_edge(
            tinc_core::graph::Edge::new("alpha", "beta", 7)
                .with_address(EdgeEndpoint::new("198.51.100.8", "655"))
                .with_local_address(EdgeEndpoint::new("10.0.0.1", "655"))
                .with_options(0x24),
        )
        .unwrap();
    let mut stop = false;

    let nodes = handle_control_request_line("18 3", &mut stop, Some(&config), None).unwrap();
    assert!(nodes.contains("18 3 alpha "));
    assert!(nodes.contains(" MYSELF port 12345 "));
    assert!(nodes.contains("18 3 beta "));
    assert!(nodes.contains(" 192.0.2.7 port 777 "));
    assert!(nodes.ends_with("18 3\n"));

    let runtime = RuntimeDaemonState::new(
        Vec::new(),
        &config,
        RuntimeKeys {
            private_key: Some(test_key(1)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    let runtime_nodes = dump_nodes(&config, runtime.state(), Some(&runtime));
    assert!(
        runtime_nodes.contains(" MYSELF port 12345 0 0 0 0 700000c "),
        "runtime dump should expose C setup_myself() local options: {runtime_nodes}"
    );

    let legacy_config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("ExperimentalProtocol", "no"),
    ]))
    .unwrap();
    let legacy_runtime = RuntimeDaemonState::new(
        Vec::new(),
        &legacy_config,
        RuntimeKeys {
            private_key: None,
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(test_rsa_key())),
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    let legacy_nodes = dump_nodes(
        &legacy_config,
        legacy_runtime.state(),
        Some(&legacy_runtime),
    );
    assert!(
        legacy_nodes.contains(" MYSELF port 655 0 0 0 0 700000c "),
        "C setup_myself() leaves PROT_MINOR in local dump options even when ExperimentalProtocol = no: {legacy_nodes}"
    );

    let subnets = handle_control_request_line("18 5", &mut stop, Some(&config), None).unwrap();
    assert!(subnets.contains("18 5 10.0.0.0/8 alpha\n"));
    assert!(subnets.ends_with("18 5\n"));

    let edges = handle_control_request_line("18 4", &mut stop, Some(&config), None).unwrap();
    assert!(edges.contains("18 4 alpha beta 198.51.100.8 port 655 10.0.0.1 port 655 24 7\n"));
    assert!(edges.ends_with("18 4\n"));

    let connections = handle_control_request_line("18 6", &mut stop, Some(&config), None).unwrap();
    assert_eq!(
        "18 6 <control> localhost port unix 0 0 200\n18 6\n",
        connections
    );

    let traffic = handle_control_request_line("18 13", &mut stop, Some(&config), None).unwrap();
    assert!(traffic.contains("18 13 alpha 0 0 0 0\n"));
    assert!(traffic.contains("18 13 beta 0 0 0 0\n"));
    assert!(traffic.ends_with("18 13\n"));
    assert!(!stop);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_node_dump_includes_runtime_fields_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-node-runtime-fields");
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        "Address = 192.0.2.7 777\nSubnet = 10.2.0.0/16\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    {
        let beta = runtime.state.graph.node_mut("beta").unwrap();
        beta.options = 0x24;
        beta.status.reachable = true;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
        beta.route.distance = Some(1);
        beta.mtu = 1400;
        beta.min_mtu = 1200;
        beta.max_mtu = 1450;
        beta.last_state_change = 123_456;
    }
    let key = bin_to_hex(&[0x42; 32]);
    runtime
        .apply_legacy_answer_key_message(&AnswerKeyMessage {
            from: "beta".to_owned(),
            to: "alpha".to_owned(),
            key,
            cipher: 419,
            digest: 672,
            mac_length: 16,
            compression: 9,
            address: None,
        })
        .unwrap();
    runtime.traffic.insert(
        "beta".to_owned(),
        TrafficCounters {
            in_packets: 7,
            in_bytes: 701,
            out_packets: 8,
            out_bytes: 802,
        },
    );
    runtime
        .udp_probe
        .entry("beta".to_owned())
        .or_default()
        .udp_ping_rtt = Some(Duration::from_micros(12_345));

    let mut stop = false;
    let nodes =
        handle_control_request_line("18 3", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    let beta_line = nodes
        .lines()
        .find(|line| line.starts_with("18 3 beta "))
        .unwrap();
    let fields = beta_line.split_whitespace().collect::<Vec<_>>();

    assert_eq!(25, fields.len());
    assert_eq!("192.0.2.7", fields[4]);
    assert_eq!("port", fields[5]);
    assert_eq!("777", fields[6]);
    assert_eq!("419", fields[7]);
    assert_eq!("672", fields[8]);
    assert_eq!("16", fields[9]);
    assert_eq!("9", fields[10]);
    assert_eq!("24", fields[11]);
    let status = u32::from_str_radix(fields[12], 16).unwrap();
    assert_ne!(0, status & (1 << 1));
    assert_ne!(0, status & (1 << 4));
    assert_eq!("beta", fields[13]);
    assert_eq!("beta", fields[14]);
    assert_eq!("1", fields[15]);
    assert_eq!("1400", fields[16]);
    assert_eq!("1200", fields[17]);
    assert_eq!("1450", fields[18]);
    assert_eq!("123456", fields[19]);
    assert_eq!("12345", fields[20]);
    assert_eq!("7", fields[21]);
    assert_eq!("701", fields[22]);
    assert_eq!("8", fields[23]);
    assert_eq!("802", fields[24]);
    assert!(nodes.ends_with("18 3\n"));
    assert!(!stop);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn control_node_dump_status_bits_match_c_node_status_layout_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("control-node-status-bits");
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        "Address = 192.0.2.7 777\nSubnet = 10.2.0.0/16\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    {
        let beta = runtime.state.graph.node_mut("beta").unwrap();
        beta.status.valid_key = true;
        beta.status.waiting_for_key = true;
        beta.status.visited = true;
        beta.status.reachable = true;
        beta.status.indirect = true;
        beta.status.sptps = true;
        beta.status.udp_confirmed = true;
        beta.status.send_locally = true;
        beta.status.udp_packet = true;
        beta.status.valid_key_in = true;
        beta.status.has_address = true;
        beta.status.ping_sent = true;
    }

    let mut stop = false;
    let nodes =
        handle_control_request_line("18 3", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    let beta_line = nodes
        .lines()
        .find(|line| line.starts_with("18 3 beta "))
        .unwrap();
    let fields = beta_line.split_whitespace().collect::<Vec<_>>();
    let status = u32::from_str_radix(fields[12], 16).unwrap();

    assert_eq!(0x1ffe, status);
    assert_eq!(0, status & 1, "C node_status_t bit 0 is unused for nodes");
    assert_eq!(1 << 1, status & (1 << 1), "validkey");
    assert_eq!(1 << 2, status & (1 << 2), "waitingforkey");
    assert_eq!(1 << 3, status & (1 << 3), "visited");
    assert_eq!(1 << 4, status & (1 << 4), "reachable");
    assert_eq!(1 << 5, status & (1 << 5), "indirect");
    assert_eq!(1 << 6, status & (1 << 6), "sptps");
    assert_eq!(1 << 7, status & (1 << 7), "udp_confirmed");
    assert_eq!(1 << 8, status & (1 << 8), "send_locally");
    assert_eq!(1 << 9, status & (1 << 9), "udppacket");
    assert_eq!(1 << 10, status & (1 << 10), "validkey_in");
    assert_eq!(1 << 11, status & (1 << 11), "has_address");
    assert_eq!(1 << 12, status & (1 << 12), "ping_sent");
    assert!(nodes.ends_with("18 3\n"));
    assert!(!stop);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_updates_node_last_state_change_on_reachability_change_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-node-last-state-change");
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    let before = current_unix_secs();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 1 alpha beta 203.0.113.2 655 0 7").unwrap(),
        )
        .unwrap();
    assert!(!runtime.state.graph.node("beta").unwrap().status.reachable);
    assert_eq!(
        0,
        runtime.state.graph.node("beta").unwrap().last_state_change
    );

    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 2 beta alpha 203.0.113.1 655 0 7").unwrap(),
        )
        .unwrap();
    let after = current_unix_secs();
    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(beta.status.reachable);
    let last_state_change = beta.last_state_change;
    assert!(last_state_change >= before);
    assert!(last_state_change <= after);

    let mut stop = false;
    let nodes =
        handle_control_request_line("18 3", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    let beta_line = nodes
        .lines()
        .find(|line| line.starts_with("18 3 beta "))
        .unwrap();
    let fields = beta_line.split_whitespace().collect::<Vec<_>>();
    assert_eq!(last_state_change.to_string(), fields[19]);

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn control_stream_authenticates_cookie_and_handles_stop() {
    tinc_test_support::assert_can_create_netns();
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;

    let confbase = temp_confbase("control-stream");
    let socket = confbase.join("control.socket");
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind test Unix socket: {error}"),
    };
    let endpoint = ControlEndpoint {
        pidfile: confbase.join("pid"),
        socket,
        cookie: "abcdef".to_owned(),
        host: "localhost".to_owned(),
        port: "655".to_owned(),
        pid: 777,
    };
    let server_endpoint = endpoint.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_control_stream(stream, "alpha", &server_endpoint, None, None, None).unwrap()
    });

    let mut stream = UnixStream::connect(&endpoint.socket).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();

    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    stream.write_all(b"0 ^abcdef 0\n").unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!("4 0 777\n", line);

    stream.write_all(b"18 0\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!("18 0 0\n", line);

    assert!(handle.join().unwrap());
    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn tcp_control_stream_authenticates_cookie_and_handles_stop_like_c_windows_control() {
    tinc_test_support::assert_can_create_netns();
    use std::io::{BufRead, BufReader, Write};
    use std::thread;

    let confbase = temp_confbase("tcp-control-stream");
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind test TCP control listener: {error}"),
    };
    let address = listener.local_addr().unwrap();
    let endpoint = ControlEndpoint {
        pidfile: confbase.join("pid"),
        socket: confbase.join("control.socket"),
        cookie: "abcdef".to_owned(),
        host: address.ip().to_string(),
        port: address.port().to_string(),
        pid: 777,
    };
    let server_endpoint = endpoint.clone();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        handle_control_tcp_stream(stream, "alpha", &server_endpoint, None, None, None).unwrap()
    });

    let mut stream = TcpStream::connect(address).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();

    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    stream.write_all(b"0 ^abcdef 0\n").unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!("4 0 777\n", line);

    stream.write_all(b"18 0\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!("18 0 0\n", line);

    assert!(handle.join().unwrap());
    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn tcp_control_accept_handles_stop_like_c_windows_control_runtime() {
    tinc_test_support::assert_can_create_netns();
    use std::io::{BufRead, BufReader, Write};
    use std::thread;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = ControlEndpoint {
        pidfile: PathBuf::from("pid"),
        socket: PathBuf::from("pid.socket"),
        cookie: "abcdef".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: address.port().to_string(),
        pid: 777,
    };
    let mut config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, empty_runtime_keys());
    let endpoint_for_client = endpoint.clone();

    let client = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();

        reader.read_line(&mut line).unwrap();
        assert_eq!("0 alpha 17.7\n", line);
        stream
            .write_all(format!("0 ^{} 0\n", endpoint_for_client.cookie).as_bytes())
            .unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert_eq!("4 0 777\n", line);

        stream.write_all(b"18 0\n").unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert_eq!("18 0 0\n", line);
    });

    let deadline = Instant::now() + StdDuration::from_secs(2);
    let mut stopped = false;
    while Instant::now() < deadline {
        if accept_tcp_control_connections(
            &mut config,
            &endpoint,
            &listener,
            Some(&mut runtime),
            None,
        )
        .unwrap()
        {
            stopped = true;
            break;
        }
        thread::sleep(StdDuration::from_millis(10));
    }

    client.join().unwrap();
    assert!(stopped);
}

#[cfg(unix)]
#[test]
fn control_log_request_registers_live_stream_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;

    let confbase = temp_confbase("control-log-live");
    let socket = confbase.join("control.socket");
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind test Unix socket: {error}"),
    };
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "0")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let endpoint = ControlEndpoint {
        pidfile: confbase.join("pid"),
        socket,
        cookie: "abcdef".to_owned(),
        host: "localhost".to_owned(),
        port: "655".to_owned(),
        pid: 777,
    };
    let server_endpoint = endpoint.clone();
    let socket = endpoint.socket.clone();
    let handle = thread::spawn(move || {
        let (server_stream, _) = listener.accept().unwrap();
        let mut runtime = runtime;
        handle_control_stream(
            server_stream,
            "alpha",
            &server_endpoint,
            None,
            Some(&mut runtime),
            None,
        )
        .unwrap();
        runtime
    });
    let mut client_stream = UnixStream::connect(&socket).unwrap();
    let _ = client_stream.set_read_timeout(Some(StdDuration::from_secs(1)));
    let mut reader = BufReader::new(client_stream.try_clone().unwrap());
    let mut line = String::new();

    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    client_stream.write_all(b"0 ^abcdef 0\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!("4 0 777\n", line);

    client_stream.write_all(b"18 15 5 1\n").unwrap();
    let mut runtime = handle.join().unwrap();
    assert_eq!(1, runtime.log_subscribers.len());

    runtime.record_log_with_priority(4, LOG_WARNING, "future live log");
    runtime.record_log_with_priority(6, LOG_DEBUG, "filtered live log");

    line.clear();
    reader.read_line(&mut line).unwrap();
    let fields = line.split_whitespace().collect::<Vec<_>>();
    assert_eq!(Some(&"18"), fields.first());
    assert_eq!(Some(&"15"), fields.get(1));
    let len = fields[2].parse::<usize>().unwrap();
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).unwrap();
    let payload = String::from_utf8(payload).unwrap();
    assert!(payload.contains("\x1b[90m"));
    assert!(payload.contains("\x1b[33;1m"));
    assert!(payload.contains("WARNING"));
    assert!(payload.contains("future live log"));
    assert!(!payload.contains("filtered live log"));

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn control_pcap_request_registers_live_stream_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;

    let confbase = temp_confbase("control-pcap-live");
    let socket = confbase.join("control.socket");
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind test Unix socket: {error}"),
    };
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let endpoint = ControlEndpoint {
        pidfile: confbase.join("pid"),
        socket,
        cookie: "abcdef".to_owned(),
        host: "localhost".to_owned(),
        port: "655".to_owned(),
        pid: 777,
    };
    let server_endpoint = endpoint.clone();
    let socket = endpoint.socket.clone();
    let handle = thread::spawn(move || {
        let (server_stream, _) = listener.accept().unwrap();
        let mut runtime = runtime;
        handle_control_stream(
            server_stream,
            "alpha",
            &server_endpoint,
            None,
            Some(&mut runtime),
            None,
        )
        .unwrap();
        runtime
    });
    let mut client_stream = UnixStream::connect(&socket).unwrap();
    let _ = client_stream.set_read_timeout(Some(StdDuration::from_secs(1)));
    let mut reader = BufReader::new(client_stream.try_clone().unwrap());
    let mut line = String::new();

    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    client_stream.write_all(b"0 ^abcdef 0\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!("4 0 777\n", line);

    client_stream.write_all(b"18 14 3\n").unwrap();
    let mut runtime = handle.join().unwrap();
    assert_eq!(1, runtime.pcap_subscribers.len());

    runtime.capture_control_pcap_packet(&VpnPacket::new(vec![1, 2, 3, 4, 5]).unwrap());

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!("18 14 3\n", line);
    let mut payload = vec![0u8; 3];
    reader.read_exact(&mut payload).unwrap();
    assert_eq!(&[1, 2, 3], payload.as_slice());

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn control_pcap_slow_subscriber_is_dropped_without_blocking_runtime_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let (sender, receiver) = mpsc::sync_channel(CONTROL_SUBSCRIBER_QUEUE_CAPACITY);
    runtime
        .pcap_subscribers
        .push(RuntimeControlPcapSubscriber { snaplen: 2, sender });

    for index in 0..=CONTROL_SUBSCRIBER_QUEUE_CAPACITY {
        runtime.capture_control_pcap_packet(
            &VpnPacket::new(vec![index as u8, 0xaa, 0xbb, 0xcc]).unwrap(),
        );
    }

    assert!(
        runtime.pcap_subscribers.is_empty(),
        "C send_pcap() relies on meta write failure to drop dead/slow control clients; Rust must not block the daemon when the bounded live pcap queue fills"
    );
    assert_eq!(
        CONTROL_SUBSCRIBER_QUEUE_CAPACITY,
        receiver.try_iter().count(),
        "the slow subscriber keeps only the bounded backlog accepted before TrySendError::Full"
    );

    runtime.capture_control_pcap_packet(&VpnPacket::new(vec![9, 8, 7, 6]).unwrap());
    assert_eq!(
        Some(vec![9, 8, 7, 6]),
        runtime.pcap_packets.back().cloned(),
        "pcap ring capture continues after the slow live subscriber is removed"
    );
}

#[test]
fn no_detach_run_prepares_foreground_control_endpoint() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("foreground-action");
    let alpha_key = test_key(1);

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let action = run(args(&[
        "tincd",
        "--config",
        confbase.to_str().unwrap(),
        "--pidfile",
        confbase.join("custom.pid").to_str().unwrap(),
        "-D",
    ]))
    .unwrap();

    let CliAction::RunForeground {
        config,
        control,
        keys,
        ..
    } = action
    else {
        panic!("expected foreground action");
    };

    assert_eq!("alpha", config.name);
    assert_eq!(
        alpha_key.public_key(),
        keys.private_key.as_ref().unwrap().public_key()
    );
    assert_eq!(confbase.join("custom.pid"), control.pidfile);
    assert_eq!(confbase.join("custom.socket"), control.socket);
    assert_eq!(64, control.cookie.len());

    fs::remove_dir_all(confbase).unwrap();
}
