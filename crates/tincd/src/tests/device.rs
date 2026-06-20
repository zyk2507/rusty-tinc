use super::*;

#[cfg(target_os = "linux")]
#[test]
fn linux_ifreq_builds_tun_tap_ioctl_request() {
    tinc_test_support::assert_can_create_netns();
    let request = linux_ifreq(Some("vpn0"), LINUX_IFF_TUN).unwrap();
    let name = request
        .name
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();

    assert_eq!(40, std::mem::size_of::<LinuxIfreq>());
    assert_eq!(b"vpn0", &name[..4]);
    assert_eq!(0, name[4]);
    assert_eq!(LINUX_IFF_TUN, request.flags);
    assert_eq!(Some("vpn0".to_owned()), linux_ifreq_name(&request));

    let tap = linux_ifreq(Some("tap0"), LINUX_IFF_TAP | LINUX_IFF_NO_PI).unwrap();
    assert_eq!(LINUX_IFF_TAP | LINUX_IFF_NO_PI, tap.flags);
    assert_eq!(
        LINUX_IFF_TUN | LINUX_IFF_ONE_QUEUE,
        linux_tun_tap_flags(FrameMode::Tun, true).unwrap()
    );
    assert_eq!(
        LINUX_IFF_TAP | LINUX_IFF_NO_PI | LINUX_IFF_ONE_QUEUE,
        linux_tun_tap_flags(FrameMode::Tap, true).unwrap()
    );

    let too_long = "0123456789abcdef";
    assert!(linux_ifreq(Some(too_long), LINUX_IFF_TUN).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_ifindex_ifreq_builds_raw_socket_ioctl_request() {
    tinc_test_support::assert_can_create_netns();
    let request = linux_ifindex_ifreq("eth0").unwrap();
    let name = request
        .name
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();

    assert_eq!(40, std::mem::size_of::<LinuxIfIndexIfreq>());
    assert_eq!(b"eth0", &name[..4]);
    assert_eq!(0, name[4]);
    assert_eq!(0, request.ifindex);

    let too_long = "0123456789abcdef";
    assert!(linux_ifindex_ifreq(too_long).is_err());
}

#[test]
fn multicast_device_config_parser_matches_c_shape() {
    tinc_test_support::assert_can_create_netns();
    assert_eq!(
        MulticastDeviceConfig {
            host: "224.15.98.12".to_owned(),
            port: "38245".to_owned(),
            ttl: 1,
        },
        parse_multicast_device("224.15.98.12 38245").unwrap()
    );
    assert_eq!(
        MulticastDeviceConfig {
            host: "ff02::1".to_owned(),
            port: "1234".to_owned(),
            ttl: 7,
        },
        parse_multicast_device("ff02::1 1234 7 trailing").unwrap()
    );
    assert_eq!(
        0,
        parse_multicast_device("224.15.98.12 38245 nope")
            .unwrap()
            .ttl
    );
    assert!(parse_multicast_device("224.15.98.12").is_err());
}

#[cfg(unix)]
#[test]
fn multicast_device_requires_device_like_c() {
    tinc_test_support::assert_can_create_netns();
    let missing = DeviceConfig {
        device_type: DeviceType::Multicast,
        device: None,
        interface: None,
        iff_one_queue: false,
        vde_port: 0,
        vde_group: None,
    };
    assert!(
        open_multicast_device(&missing)
            .unwrap_err()
            .to_string()
            .contains("Device variable required for multicast socket")
    );

    let no_port = DeviceConfig {
        device_type: DeviceType::Multicast,
        device: Some("224.15.98.12".to_owned()),
        interface: None,
        iff_one_queue: false,
        vde_port: 0,
        vde_group: None,
    };
    assert!(
        open_multicast_device(&no_port)
            .unwrap_err()
            .to_string()
            .contains("Port number required for multicast socket")
    );
}

#[test]
fn vde_device_default_build_reports_disabled_optional_backend_like_c_optional_vde() {
    tinc_test_support::assert_can_create_netns();
    let config = DeviceConfig {
        device_type: DeviceType::Vde,
        device: Some("/tmp/vde.ctl".to_owned()),
        interface: Some("vde0".to_owned()),
        iff_one_queue: false,
        vde_port: 7,
        vde_group: Some("switchers".to_owned()),
    };

    #[cfg(not(all(unix, feature = "vde")))]
    assert!(
        open_vde_device("alpha", &config)
            .unwrap_err()
            .to_string()
            .contains("VDE socket device support is not enabled")
    );

    #[cfg(all(unix, feature = "vde"))]
    {
        assert_eq!(
            std::mem::size_of::<libc::c_int>(),
            std::mem::size_of_val(&config.vde_port)
        );
        assert_eq!("/run/vde.ctl", default_vde_socket_path());
    }
}

#[cfg(unix)]
#[test]
fn multicast_device_receives_frames_and_ignores_last_written_source() -> io::Result<()> {
    tinc_test_support::assert_can_create_netns();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let group = Ipv4Addr::new(224, 15, 98, (suffix % 200 + 1) as u8);
    let port = 30000 + (suffix % 20000) as u16;
    let target = SocketAddr::new(IpAddr::V4(group), port);
    let config = DeviceConfig {
        device_type: DeviceType::Multicast,
        device: Some(format!("{group} {port} 1")),
        interface: Some("mcast0".to_owned()),
        iff_one_queue: false,
        vde_port: 0,
        vde_group: None,
    };
    let RuntimeDevice::Multicast(mut device) = (match open_multicast_device(&config) {
        Ok(device) => device,
        Err(error) => {
            eprintln!("skipping multicast socket test: {error}");
            return Ok(());
        }
    }) else {
        panic!("DeviceType = multicast did not open multicast device");
    };
    assert_eq!(DeviceKind::Multicast, device.info().kind);
    assert_eq!(Some("mcast0"), device.info().interface.as_deref());

    let sender = UdpSocket::bind("0.0.0.0:0")?;
    let ignored_source = [1, 2, 3, 4, 5, 6];
    device.ignore_src = ignored_source;
    let ignored = ethernet_packet(
        MacAddr::new([0xaa; 6]),
        MacAddr::new(ignored_source),
        ETH_P_IP,
        &[0x45; 20],
    );
    let accepted = ethernet_packet(
        MacAddr::new([0xaa; 6]),
        MacAddr::new([6, 5, 4, 3, 2, 1]),
        ETH_P_IP,
        &[0x45; 20],
    );

    sender.send_to(&ignored, target)?;
    sender.send_to(&accepted, target)?;

    let deadline = Instant::now() + StdDuration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(packet) = device.read_packet().map_err(io::Error::other)? {
            assert_ne!(ignored, packet.data);
            if packet.data == accepted {
                return Ok(());
            }
        }
        thread::sleep(StdDuration::from_millis(20));
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out waiting for multicast device packet",
    ))
}

#[cfg(target_os = "linux")]
#[test]
fn uml_device_matches_c_control_handshake_and_datagram_frame_flow() -> io::Result<()> {
    tinc_test_support::assert_can_create_netns();
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    let confbase = temp_confbase("uml-device");
    let device_path = confbase.join("uml.socket");
    let peer_path = confbase.join("uml-peer.socket");
    let config = DeviceConfig {
        device_type: DeviceType::Uml,
        device: Some(device_path.to_string_lossy().into_owned()),
        interface: Some("uml0".to_owned()),
        iff_one_queue: false,
        vde_port: 0,
        vde_group: None,
    };
    let RuntimeDevice::Uml(mut device) = open_uml_device(&config).unwrap() else {
        panic!("DeviceType = uml did not open UML device");
    };

    assert_eq!(DeviceKind::Uml, device.info().kind);
    assert_eq!(Some("uml0"), device.info().interface.as_deref());
    assert!(device_path.exists());

    let dropped = VpnPacket::new(vec![0; ETH_HLEN + 20]).unwrap();
    device.write_packet(&dropped).unwrap();

    let mut control = UnixStream::connect(&device_path)?;
    assert!(device.read_packet().unwrap().is_none());
    assert_eq!(LinuxUmlDeviceState::Request, device.state);

    let peer = UnixDatagram::bind(&peer_path)?;
    let request = LinuxUmlRequest {
        magic: 0xfeedface,
        version: 3,
        request_type: 0,
        sock: pathname_sockaddr_un(&peer_path),
    };
    let request_bytes = unsafe {
        std::slice::from_raw_parts(
            (&request as *const LinuxUmlRequest).cast::<u8>(),
            std::mem::size_of::<LinuxUmlRequest>(),
        )
    };
    control.write_all(request_bytes)?;

    assert!(device.read_packet().unwrap().is_none());
    assert_eq!(LinuxUmlDeviceState::Connected, device.state);

    let mut response: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let response_bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut response as *mut libc::sockaddr_un).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_un>(),
        )
    };
    control.read_exact(response_bytes)?;
    assert_eq!(libc::AF_UNIX as libc::sa_family_t, response.sun_family);
    assert_eq!(0, response.sun_path[0]);

    let inbound = ethernet_packet(
        MacAddr::new([0xaa; 6]),
        MacAddr::new([1, 2, 3, 4, 5, 6]),
        ETH_P_IP,
        &[0x45; 20],
    );
    sendto_unix_sockaddr(peer.as_raw_fd(), &response, &inbound)?;
    assert_eq!(inbound, device.read_packet().unwrap().unwrap().data);

    let outbound = ethernet_packet(
        MacAddr::new([0xbb; 6]),
        MacAddr::new([6, 5, 4, 3, 2, 1]),
        ETH_P_IP,
        &[0x45; 20],
    );
    device
        .write_packet(&VpnPacket::new(outbound.clone()).unwrap())
        .unwrap();
    let mut buffer = [0u8; 128];
    let len = peer.recv(&mut buffer)?;
    assert_eq!(outbound, buffer[..len]);

    drop(device);
    assert!(!device_path.exists());
    fs::remove_dir_all(confbase).unwrap();
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn uml_device_rejects_bad_c_handshake_magic() -> io::Result<()> {
    tinc_test_support::assert_can_create_netns();
    use std::os::unix::net::UnixStream;

    let confbase = temp_confbase("uml-device-bad-magic");
    let device_path = confbase.join("uml.socket");
    let config = DeviceConfig {
        device_type: DeviceType::Uml,
        device: Some(device_path.to_string_lossy().into_owned()),
        interface: None,
        iff_one_queue: false,
        vde_port: 0,
        vde_group: None,
    };
    let RuntimeDevice::Uml(mut device) = open_uml_device(&config).unwrap() else {
        panic!("DeviceType = uml did not open UML device");
    };
    let mut control = UnixStream::connect(&device_path)?;
    assert!(device.read_packet().unwrap().is_none());

    let request = LinuxUmlRequest {
        magic: 0,
        version: 3,
        request_type: 0,
        sock: unsafe { std::mem::zeroed() },
    };
    let request_bytes = unsafe {
        std::slice::from_raw_parts(
            (&request as *const LinuxUmlRequest).cast::<u8>(),
            std::mem::size_of::<LinuxUmlRequest>(),
        )
    };
    control.write_all(request_bytes)?;

    assert!(matches!(
        device.read_packet(),
        Err(DeviceError::Io(error)) if error.kind() == io::ErrorKind::InvalidData
    ));

    drop(device);
    fs::remove_dir_all(confbase).unwrap();
    Ok(())
}

#[test]
fn runtime_reload_does_not_change_device_standby_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let standby_config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("DeviceStandby", "yes"),
    ]))
    .unwrap();
    let active_config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("DeviceStandby", "no"),
    ]))
    .unwrap();

    let mut standby_runtime = RuntimeDaemonState::new(
        Vec::new(),
        &standby_config,
        RuntimeKeys {
            private_key: Some(test_key(1)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    standby_runtime
        .apply_reloaded_config(
            &active_config,
            RuntimeKeys {
                private_key: Some(test_key(2)),
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        )
        .unwrap();
    assert!(standby_runtime.device_standby);
    assert!(!standby_runtime.device_enabled);

    let mut active_runtime = RuntimeDaemonState::new(
        Vec::new(),
        &active_config,
        RuntimeKeys {
            private_key: Some(test_key(3)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    active_runtime
        .apply_reloaded_config(
            &standby_config,
            RuntimeKeys {
                private_key: Some(test_key(4)),
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        )
        .unwrap();
    assert!(!active_runtime.device_standby);
    assert!(active_runtime.device_enabled);
}

#[test]
fn device_standby_runs_tinc_up_down_on_remote_reachability_edges() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("device-standby-events");
    let output = confbase.join("events.out");
    let output_arg = output.display().to_string();
    for script in ["tinc-up", "tinc-down"] {
        fs::write(
            confbase.join(format!("{script}.sh")),
            event_script(script, &output_arg),
        )
        .unwrap();
    }

    let mut tree = ConfigTree::new();
    tree.add(Config::new(
        "Name",
        "alpha",
        ConfigSource::file("tinc.conf", 1),
    ));
    tree.add(Config::new(
        "DeviceStandby",
        "yes",
        ConfigSource::file("tinc.conf", 2),
    ));
    tree.add(Config::new(
        "ScriptsInterpreter",
        "/bin/sh",
        ConfigSource::file("tinc.conf", 3),
    ));
    tree.add(Config::new(
        "ScriptsExtension",
        ".sh",
        ConfigSource::file("tinc.conf", 4),
    ));
    let config = RuntimeConfig::from_config_tree(&tree).unwrap();
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    options.netname = Some("prod".to_owned());
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_scripts(&config, &options);

    assert!(!runtime.device_enabled);
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 1 alpha beta 127.0.0.1 1234 0 1").unwrap(),
        )
        .unwrap();
    assert!(!output.exists());

    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 2 beta alpha 127.0.0.1 4321 0 1").unwrap(),
        )
        .unwrap();
    assert!(runtime.device_enabled);
    assert_eq!(
        "tinc-up NAME=alpha NETNAME=prod NODE= SUBNET= WEIGHT= REMOTEADDRESS= REMOTEPORT=\n",
        fs::read_to_string(&output).unwrap()
    );

    runtime
        .apply_runtime_meta_message(parse_meta_message("13 3 alpha beta").unwrap())
        .unwrap();
    assert!(!runtime.device_enabled);
    assert_eq!(
        "tinc-up NAME=alpha NETNAME=prod NODE= SUBNET= WEIGHT= REMOTEADDRESS= REMOTEPORT=\n\
tinc-down NAME=alpha NETNAME=prod NODE= SUBNET= WEIGHT= REMOTEADDRESS= REMOTEPORT=\n",
        fs::read_to_string(&output).unwrap()
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_does_not_send_device_packets_over_udp_without_secure_state_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-device-no-key-drop");
    let receiver = match UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind UDP receiver: {error}"),
    };
    receiver.set_nonblocking(true).unwrap();
    let receiver_addr = receiver.local_addr().unwrap();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nPriorityInheritance = yes\n",
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
            "Address = {} {}\n",
            receiver_addr.ip(),
            receiver_addr.port()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    assert!(config.engine.route.priority_inheritance);
    assert_eq!(Some(receiver_addr), config.addresses.address("beta"));
    let sockets = match bind_runtime_listeners(&config) {
        Ok(sockets) => sockets,
        Err(TincdError::ListenIo(error))
            if error.contains("Operation not permitted") || error.contains("Permission denied") =>
        {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind runtime UDP sender: {error}"),
    };
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
        .apply_meta_message(parse_meta_message("10 1 beta 10.2.0.0/16").unwrap())
        .unwrap();
    runtime
        .state
        .graph
        .node_mut("beta")
        .unwrap()
        .status
        .reachable = true;

    let mut packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    packet[ETH_HLEN + 1] = 0x2e;
    runtime
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    runtime.poll_once().unwrap();

    assert_eq!(0, runtime.listen_sockets[0].priority.get());
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;

        assert_eq!(
            0,
            socket_option_i32(
                runtime.listen_sockets[0].udp().as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_TOS
            )
            .unwrap()
        );
    }

    let mut buffer = [0u8; 2048];
    match receiver.recv_from(&mut buffer) {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok((len, peer)) => panic!("unexpected unsecured UDP datagram from {peer}: len={len}"),
        Err(error) => panic!("failed to check UDP receiver: {error}"),
    }
    assert_eq!(
        Some(&1),
        runtime
            .packet_diag_counts
            .get("transport-deferred:beta:beta")
    );

    let mut stop = false;
    let traffic =
        handle_control_request_line("18 13", &mut stop, Some(&config), Some(&mut runtime)).unwrap();
    assert!(traffic.contains("18 13 beta 0 0 0 0\n"));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_memory_device_sends_packets_to_udp_peer_after_sptps_key_exchange() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-secure-device-data");
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind secure alpha listener: {error}"),
    };
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind secure beta listener: {error}"),
    };
    let alpha_addr = alpha_socket.info().address;
    let beta_addr = beta_socket.info().address;
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_public_key = alpha_key.public_key();
    let beta_public_key = beta_key.public_key();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nStrictSubnets = yes\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        format!(
            "Subnet = 10.1.0.0/16\nEd25519PublicKey = {}\n",
            alpha_public_key.to_base64()
        ),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nSubnet = 10.2.0.0/16\nEd25519PublicKey = {}\n",
            beta_addr.ip(),
            beta_addr.port(),
            beta_public_key.to_base64()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let alpha_config = load_runtime_config(&options).unwrap();
    let beta_server = config_tree(&[
        ("Name", "beta"),
        ("AddressFamily", "IPv4"),
        ("StrictSubnets", "yes"),
        ("Subnet", "10.2.0.0/16"),
    ]);
    let alpha_address = format!("{} {}", alpha_addr.ip(), alpha_addr.port());
    let beta_alpha_host = config_tree(&[
        ("Address", &alpha_address),
        ("Subnet", "10.1.0.0/16"),
        ("Ed25519PublicKey", &alpha_public_key.to_base64()),
    ]);
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
    let mut runtime = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);
    runtime
        .state
        .graph
        .node_mut("beta")
        .unwrap()
        .status
        .reachable = true;
    runtime.state.graph.node_mut("beta").unwrap().min_mtu = DEFAULT_MTU;
    beta.state.graph.node_mut("alpha").unwrap().status.reachable = true;
    complete_sptps_udp_exchange(&mut runtime, &mut beta);

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    runtime
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    runtime.poll_once().unwrap();
    beta.poll_once().unwrap();

    assert_eq!(1, beta.device_writes().len());
    assert_eq!(
        test_ipv4_router_packet([10, 2, 0, 42]),
        beta.device_writes()[0].data
    );
    assert_eq!(1, runtime.traffic["beta"].out_packets);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_sends_device_packets_over_meta_tcp_when_tcponly_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("TCPOnly", "yes")]))
            .unwrap();
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
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    runtime
        .state
        .apply_meta_message(parse_meta_message("10 1 beta 10.2.0.0/16").unwrap())
        .unwrap();
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());
    beta.route.via = Some("beta".to_owned());
    beta.options = (PROT_MINOR as u32) << 24;

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    runtime
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    runtime.poll_once().unwrap();
    runtime.flush_meta_outputs().unwrap();

    let mut buffer = [0u8; 2048];
    let len = beta_stream.read(&mut buffer).unwrap();
    let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();

    assert!(step.events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::TcpPacket(payload) if payload == &packet
    )));
}
