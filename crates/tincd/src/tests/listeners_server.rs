use super::*;

#[test]
fn runtime_listeners_bind_tcp_and_udp_from_daemon_config() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-listeners");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nBindToInterface = lo\nUDPRcvBuf = 4096\nUDPSndBuf = 8192\nFWMark = 7\n",
    )
    .unwrap();
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
    let config = load_runtime_config(&options).unwrap();
    let keys = load_runtime_keys(&options).unwrap();

    let sockets = match bind_runtime_listeners(&config) {
        Ok(sockets) => sockets,
        Err(TincdError::ListenIo(error))
            if error.contains("Operation not permitted") || error.contains("Permission denied") =>
        {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind runtime listeners: {error}"),
    };

    assert_eq!(1, sockets.len());
    let info = sockets[0].info();
    assert_eq!("127.0.0.1".parse::<IpAddr>().unwrap(), info.address.ip());
    assert_ne!(0, info.address.port());
    assert!(info.bind_to);
    assert_eq!(info.address, sockets[0].tcp().local_addr().unwrap());
    assert_eq!(info.address, sockets[0].udp().local_addr().unwrap());
    #[cfg(unix)]
    {
        assert!(udp_socket_buffer_size(sockets[0].udp(), libc::SO_RCVBUF).unwrap() >= 4096);
        assert!(udp_socket_buffer_size(sockets[0].udp(), libc::SO_SNDBUF).unwrap() >= 8192);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        assert_eq!(7, socket_fwmark(sockets[0].tcp().as_raw_fd()).unwrap());
        assert_eq!(7, socket_fwmark(sockets[0].udp().as_raw_fd()).unwrap());
        assert_eq!(
            "lo",
            socket_bound_device(sockets[0].tcp().as_raw_fd()).unwrap()
        );
        assert_eq!(
            "lo",
            socket_bound_device(sockets[0].udp().as_raw_fd()).unwrap()
        );
    }

    let mut client = TcpStream::connect(info.address).unwrap();
    client.write_all(b"0 beta 17.7\n").unwrap();

    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);
    runtime.poll_once().unwrap();
    let connections = runtime.meta_connection_infos();

    assert_eq!(1, connections.len());
    assert_eq!(Some("beta".to_owned()), connections[0].name);
    assert_eq!(info.address, connections[0].local);
    assert_eq!(client.local_addr().unwrap(), connections[0].peer);
    assert!(connections[0].bytes_read >= 12);
    assert!(connections[0].bytes_written > 0);
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        let fd = runtime.meta_connections[0].stream.as_raw_fd();
        assert_eq!(
            1,
            socket_option_i32(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY).unwrap()
        );
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;

        let fd = runtime.meta_connections[0].stream.as_raw_fd();
        assert_eq!(
            IPTOS_LOWDELAY,
            socket_option_i32(fd, libc::IPPROTO_IP, libc::IP_TOS).unwrap()
        );
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        assert_eq!(
            7,
            socket_fwmark(runtime.meta_connections[0].stream.as_raw_fd()).unwrap()
        );
    }

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_listener_rejects_address_family_mismatch() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-listener-family");
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv6\nBindToAddress = 127.0.0.1 0\n",
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

    assert_eq!(
        Err(TincdError::InvalidListenAddress("127.0.0.1 0".to_owned())),
        bind_runtime_listeners(&config).map(|_| ())
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn systemd_listen_fd_is_reused_and_gets_matching_udp_socket_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let fd = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
    assert!(fd >= 0, "failed to duplicate listener fd");
    drop(listener);

    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("AddressFamily", "IPv4"),
    ]))
    .unwrap();
    let sockets = bind_runtime_listeners_from_systemd_fds(&config, 1, fd).unwrap();

    assert_eq!(1, sockets.len());
    assert_eq!(address, sockets[0].info().address);

    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(b"x").unwrap();
    let mut accepted = loop {
        match sockets[0].tcp.accept() {
            Ok((accepted, _)) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(StdDuration::from_millis(5));
            }
            Err(error) => panic!("accept failed: {error}"),
        }
    };
    let mut byte = [0u8; 1];
    accepted.set_nonblocking(false).unwrap();
    accepted.read_exact(&mut byte).unwrap();
    assert_eq!(b"x", &byte);

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(b"u", address).unwrap();
    let mut buffer = [0u8; 1];
    let (len, _) = loop {
        match sockets[0].udp.recv_from(&mut buffer) {
            Ok(result) => break result,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(StdDuration::from_millis(5));
            }
            Err(error) => panic!("udp recv failed: {error}"),
        }
    };
    assert_eq!(1, len);
    assert_eq!(b"u", &buffer);
}

#[cfg(unix)]
#[test]
fn systemd_listen_fd_limit_matches_tinc_maxsockets() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let error = bind_runtime_listeners_from_systemd_fds(&config, MAX_SYSTEMD_LISTEN_FDS + 1, 3)
        .unwrap_err();
    assert_eq!(
        TincdError::ListenIo("Too many listening sockets".to_owned()),
        error
    );
}

#[cfg(unix)]
#[test]
fn foreground_server_fails_before_writing_pidfile_when_runtime_listeners_fail() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("foreground-listener-fail");
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv6\nBindToAddress = 127.0.0.1 0\n",
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    options.pidfile = Some(confbase.join("custom.pid"));
    let config = load_runtime_config(&options).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let endpoint = ControlEndpoint::new(&options);

    assert_eq!(
        Err(TincdError::InvalidListenAddress("127.0.0.1 0".to_owned())),
        run_foreground_server(&config, &endpoint, keys, &options)
    );
    assert!(!endpoint.pidfile.exists());
    assert!(!endpoint.socket.exists());

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn systemd_listen_pid_prepares_foreground_runtime_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("systemd-foreground-action");
    let alpha_key = test_key(1);

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let _guard = EnvVarGuard::set("LISTEN_PID", std::process::id().to_string());
    let action = run(args(&[
        "tincd",
        "--config",
        confbase.to_str().unwrap(),
        "--pidfile",
        confbase.join("custom.pid").to_str().unwrap(),
    ]))
    .unwrap();

    let CliAction::RunForeground {
        options,
        config,
        control,
        keys,
    } = action
    else {
        panic!("expected foreground action");
    };

    assert!(!options.no_detach);
    assert_eq!("alpha", config.name);
    assert_eq!(
        alpha_key.public_key(),
        keys.private_key.as_ref().unwrap().public_key()
    );
    assert_eq!(confbase.join("custom.pid"), control.pidfile);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn default_run_prepares_daemon_runtime_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("daemon-action");
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
    ]))
    .unwrap();

    let CliAction::RunDaemon {
        options,
        config,
        control,
        keys,
    } = action
    else {
        panic!("expected daemon action");
    };

    assert!(!options.no_detach);
    assert_eq!("alpha", config.name);
    assert_eq!(
        alpha_key.public_key(),
        keys.private_key.as_ref().unwrap().public_key()
    );
    assert_eq!(confbase.join("custom.pid"), control.pidfile);
    assert_eq!(confbase.join("custom.socket"), control.socket);

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(not(unix))]
#[test]
fn non_unix_default_run_does_not_silently_exit_after_loading_config() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("non-unix-daemon-action");
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
    ]))
    .unwrap();

    let CliAction::RunDaemon {
        options,
        config,
        control,
        keys,
    } = action
    else {
        panic!("expected daemon action");
    };

    assert!(!options.no_detach);
    assert_eq!("alpha", config.name);
    assert_eq!(
        alpha_key.public_key(),
        keys.private_key.as_ref().unwrap().public_key()
    );
    assert_eq!(confbase.join("custom.pid"), control.pidfile);

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn daemon_runtime_defaults_to_syslog_like_tincd_detach() {
    tinc_test_support::assert_can_create_netns();
    let mut options = TincdOptions::new("tincd".to_owned());
    let detached = daemon_runtime_options_like_tinc(&options);
    assert!(detached.use_syslog);
    assert_eq!(None, detached.logfile);

    options.logfile = Some(Some(PathBuf::from("/tmp/tinc.log")));
    let logfile = daemon_runtime_options_like_tinc(&options);
    assert!(!logfile.use_syslog);
    assert_eq!(Some(Some(PathBuf::from("/tmp/tinc.log"))), logfile.logfile);
}
