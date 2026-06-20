use super::*;

#[test]
fn upnp_runtime_starts_only_when_c_would_request_mapping() {
    tinc_test_support::assert_can_create_netns();
    let mut yes =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("UPnP", "yes")]))
            .unwrap();
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &yes, empty_runtime_keys());
    runtime.set_debug_level(0);
    initialize_upnp_like_tinc(&mut runtime, &yes);
    assert!(
        runtime
            .test_log_entries(0, false)
            .iter()
            .any(|line| { line.contains("[upnp] No listening sockets to map") })
    );

    yes.daemon.upnp.mode = tinc_runtime::config::UpnpMode::UdpOnly;
    let mut udp_only = RuntimeDaemonState::new(Vec::new(), &yes, empty_runtime_keys());
    udp_only.set_debug_level(0);
    initialize_upnp_like_tinc(&mut udp_only, &yes);
    assert!(
        udp_only
            .test_log_entries(0, false)
            .iter()
            .any(|line| line.contains("[upnp] No listening sockets to map"))
    );

    let bogus =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("UPnP", "maybe")]))
            .unwrap();
    let mut disabled = RuntimeDaemonState::new(Vec::new(), &bogus, empty_runtime_keys());
    disabled.set_debug_level(0);
    initialize_upnp_like_tinc(&mut disabled, &bogus);
    assert!(
        disabled
            .test_log_entries(0, false)
            .iter()
            .all(|line| !line.contains("[upnp]")),
        "C net_setup.c only enables UPnP for yes and udponly"
    );
}

#[test]
fn upnp_mapping_selection_matches_c_yes_and_udponly_modes() {
    tinc_test_support::assert_can_create_netns();
    let mut yes = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("UPnP", "yes"),
        ("UPnPRefreshPeriod", "37"),
    ]))
    .unwrap();
    let socket = test_runtime_listen_socket().unwrap();
    let tcp_port = socket.tcp().local_addr().unwrap().port();
    let udp_port = socket.udp().local_addr().unwrap().port();
    let runtime = RuntimeDaemonState::new(vec![socket], &yes, empty_runtime_keys());
    let mappings = upnp_port_mappings_like_tinc(&runtime, &yes);

    assert_eq!(2, mappings.len());
    assert_eq!(
        Some(UpnpProtocol::Tcp),
        mappings.first().map(|mapping| mapping.protocol)
    );
    assert_eq!(
        Some(tcp_port),
        mappings.first().map(|mapping| mapping.external_port)
    );
    assert_eq!(
        Some(UpnpProtocol::Udp),
        mappings.get(1).map(|mapping| mapping.protocol)
    );
    assert_eq!(
        Some(udp_port),
        mappings.get(1).map(|mapping| mapping.external_port)
    );
    assert!(
        mappings
            .iter()
            .all(|mapping| mapping.lease_duration_secs == 74)
    );
    assert!(mappings.iter().all(|mapping| mapping.description == "tinc"));

    yes.daemon.upnp.mode = tinc_runtime::config::UpnpMode::UdpOnly;
    let socket = test_runtime_listen_socket().unwrap();
    let udp_port = socket.udp().local_addr().unwrap().port();
    let runtime = RuntimeDaemonState::new(vec![socket], &yes, empty_runtime_keys());
    let mappings = upnp_port_mappings_like_tinc(&runtime, &yes);

    assert_eq!(1, mappings.len());
    assert_eq!(UpnpProtocol::Udp, mappings[0].protocol);
    assert_eq!(udp_port, mappings[0].external_port);
}

#[test]
fn upnp_gateway_local_addr_uses_route_to_gateway_like_tinc_miniupnpc() {
    tinc_test_support::assert_can_create_netns();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let gateway = igd_next::Gateway {
        addr: listener.local_addr().unwrap(),
        root_url: "/root.xml".to_owned(),
        control_url: "/upnp/control".to_owned(),
        control_schema_url: "/schema.xml".to_owned(),
        control_schema: std::collections::HashMap::new(),
    };

    assert_eq!(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        gateway_local_addr(&gateway).unwrap().ip()
    );
}

#[test]
fn upnp_background_logs_are_published_through_runtime_logger_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, empty_runtime_keys());
    let (mut logger, receiver) = upnp_log_channel();
    runtime.upnp_log_receiver = Some(receiver);
    logger(0, LOG_WARNING, "[upnp] test log".to_owned());

    assert!(runtime.poll_once().unwrap());
    assert!(
        runtime
            .test_log_entries(0, false)
            .iter()
            .any(|entry| entry.contains("[upnp] test log"))
    );
}
