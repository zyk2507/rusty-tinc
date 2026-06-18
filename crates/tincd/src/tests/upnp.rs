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
            .control_log_entries(0, false)
            .iter()
            .any(|line| { line.contains("[upnp] No listening sockets to map") })
    );

    yes.daemon.upnp.mode = tinc_runtime::config::UpnpMode::UdpOnly;
    let mut udp_only = RuntimeDaemonState::new(Vec::new(), &yes, empty_runtime_keys());
    udp_only.set_debug_level(0);
    initialize_upnp_like_tinc(&mut udp_only, &yes);
    assert!(
        udp_only
            .control_log_entries(0, false)
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
            .control_log_entries(0, false)
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
fn upnp_description_parser_finds_wan_service_and_resolves_control_url() {
    tinc_test_support::assert_can_create_netns();
    let description_url = Url::parse("http://192.0.2.1:5431/root/desc.xml").unwrap();
    let service = parse_upnp_service_description(
        &description_url,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
        r#"<?xml version="1.0"?>
<root>
  <device>
<serviceList>
  <service>
    <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
    <controlURL>/ignored</controlURL>
  </service>
  <service>
    <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
    <controlURL>../upnp/control/WANIPConn1</controlURL>
  </service>
</serviceList>
  </device>
</root>"#,
    )
    .unwrap();

    assert_eq!(
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        service.service_type
    );
    assert_eq!(
        Url::parse("http://192.0.2.1:5431/upnp/control/WANIPConn1").unwrap(),
        service.control_url
    );
    assert_eq!(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
        service.lan_address
    );
}

#[test]
fn upnp_add_port_mapping_body_matches_c_mapping_fields() {
    tinc_test_support::assert_can_create_netns();
    let service = UpnpService {
        description_url: Url::parse("http://192.0.2.1/root.xml").unwrap(),
        control_url: Url::parse("http://192.0.2.1/upnp/control").unwrap(),
        service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".to_owned(),
        lan_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
    };
    let mapping = UpnpPortMapping {
        local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 655),
        external_port: 655,
        internal_port: 655,
        protocol: UpnpProtocol::Tcp,
        description: "tinc.prod&test".to_owned(),
        lease_duration_secs: 120,
    };
    let body = upnp_add_port_mapping_body(&service, &mapping);

    assert!(body.contains("<NewExternalPort>655</NewExternalPort>"));
    assert!(body.contains("<NewProtocol>TCP</NewProtocol>"));
    assert!(body.contains("<NewInternalPort>655</NewInternalPort>"));
    assert!(body.contains("<NewInternalClient>192.0.2.44</NewInternalClient>"));
    assert!(
        body.contains("<NewPortMappingDescription>tinc.prod&amp;test</NewPortMappingDescription>")
    );
    assert!(body.contains("<NewLeaseDuration>120</NewLeaseDuration>"));
}

#[test]
fn upnp_background_logs_are_published_through_runtime_logger_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, empty_runtime_keys());
    let (sender, receiver) = mpsc::channel();
    runtime.upnp_log_receiver = Some(receiver);
    sender
        .send(RuntimeLogEntry {
            level: 0,
            priority: LOG_WARNING,
            message: "[upnp] test log".to_owned(),
        })
        .unwrap();

    assert!(runtime.poll_once().unwrap());
    assert!(
        runtime
            .control_log_entries(0, false)
            .iter()
            .any(|entry| entry.contains("[upnp] test log"))
    );
}
