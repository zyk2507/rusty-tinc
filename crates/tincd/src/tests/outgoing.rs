use super::*;

#[test]
fn runtime_connects_configured_peers_and_sends_initial_id() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-to");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let remote_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind remote listener: {error}"),
    };
    let remote_addr = remote_listener.local_addr().unwrap();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nBindToInterface = lo\nConnectTo = beta\nFWMark = 7\n",
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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());

    let (remote_stream, _) = remote_listener.accept().unwrap();
    drive_outgoing_meta_output(&mut runtime);
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);

    let connections = runtime.meta_connection_infos();
    assert_eq!(1, connections.len());
    assert_eq!(Some("beta".to_owned()), connections[0].name);
    assert_eq!(remote_addr, connections[0].peer);
    assert!(connections[0].bytes_written >= line.len() as u64);
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
        assert_eq!(
            "lo",
            socket_bound_device(runtime.meta_connections[0].stream.as_raw_fd()).unwrap()
        );
    }

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_connects_configured_peer_through_http_proxy_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-http-proxy");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let proxy_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind HTTP proxy listener: {error}"),
    };
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    drop(target_listener);

    fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\nProxy = http {} {}\n",
            proxy_addr.ip(),
            proxy_addr.port()
        ),
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            target_addr.ip(),
            target_addr.port(),
            beta_key.public_key().to_base64()
        ),
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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);
    runtime.set_bypass_security(true);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());

    let (mut proxy_stream, _) = proxy_listener.accept().unwrap();
    drive_outgoing_meta_output(&mut runtime);
    let mut reader = BufReader::new(proxy_stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(
        format!(
            "CONNECT {}:{} HTTP/1.1\n",
            target_addr.ip(),
            target_addr.port()
        ),
        line.replace('\r', "")
    );
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(
        "\r0 alpha 17.0\n", line,
        "C send_id() writes the HTTP CONNECT request before the tinc ID line"
    );

    proxy_stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n0 beta 17.0\n4 655 0 0\n")
        .unwrap();
    runtime.poll_once().unwrap();
    assert!(
        runtime.state.graph.edge("alpha", "beta").is_some(),
        "C receive_request() swallows the HTTP 200 proxy response while allow_request == ID, then processes the peer ID/ACK"
    );
    assert_eq!(target_addr, runtime.meta_connection_infos()[0].peer);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_connects_configured_peer_through_socks5_no_auth_proxy_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-socks5-proxy");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let proxy_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind SOCKS5 proxy listener: {error}"),
    };
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    drop(target_listener);

    fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\nProxy = socks5 {} {}\n",
            proxy_addr.ip(),
            proxy_addr.port()
        ),
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            target_addr.ip(),
            target_addr.port(),
            beta_key.public_key().to_base64()
        ),
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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);
    runtime.set_bypass_security(true);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());

    let (mut proxy_stream, _) = proxy_listener.accept().unwrap();
    drive_outgoing_meta_output(&mut runtime);
    proxy_stream
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let mut request = vec![0u8; 13];
    proxy_stream.read_exact(&mut request).unwrap();
    let mut expected = vec![5, 1, 0, 5, 1, 0, 1];
    let IpAddr::V4(target_ip) = target_addr.ip() else {
        panic!("SOCKS5 no-auth proxy test target should be IPv4");
    };
    expected.extend_from_slice(&target_ip.octets());
    expected.extend_from_slice(&target_addr.port().to_be_bytes());
    assert_eq!(
        expected, request,
        "C create_socks5_req() sends greeting and CONNECT request in one meta write"
    );

    let mut response = vec![5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 0];
    response.extend_from_slice(b"0 beta 17.0\n4 655 0 0\n");
    proxy_stream.write_all(&response).unwrap();
    runtime.poll_once().unwrap();
    assert!(
        runtime.state.graph.edge("alpha", "beta").is_some(),
        "C check_socks5_resp() accepts no-auth status OK before peer ID/ACK are processed"
    );
    assert_eq!(target_addr, runtime.meta_connection_infos()[0].peer);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_connects_configured_peer_through_socks4_proxy_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-socks4-proxy");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let proxy_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind SOCKS4 proxy listener: {error}"),
    };
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    drop(target_listener);

    fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\nProxy = socks4 {} {} proxyuser\n",
            proxy_addr.ip(),
            proxy_addr.port()
        ),
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            target_addr.ip(),
            target_addr.port(),
            beta_key.public_key().to_base64()
        ),
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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);
    runtime.set_bypass_security(true);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());

    let (mut proxy_stream, _) = proxy_listener.accept().unwrap();
    drive_outgoing_meta_output(&mut runtime);
    proxy_stream
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let mut request = vec![0u8; 18];
    proxy_stream.read_exact(&mut request).unwrap();
    let mut expected = vec![4, 1];
    let IpAddr::V4(target_ip) = target_addr.ip() else {
        panic!("SOCKS4 proxy test target should be IPv4");
    };
    expected.extend_from_slice(&target_addr.port().to_be_bytes());
    expected.extend_from_slice(&target_ip.octets());
    expected.extend_from_slice(b"proxyuser\0");
    assert_eq!(
        expected, request,
        "C create_socks4_req() writes version, command, network-order port/IP and NUL-terminated proxy user"
    );

    let mut response = vec![0, 0x5a, 0, 0, 127, 0, 0, 1];
    response.extend_from_slice(b"0 beta 17.0\n4 655 0 0\n");
    proxy_stream.write_all(&response).unwrap();
    runtime.poll_once().unwrap();
    assert!(
        runtime.state.graph.edge("alpha", "beta").is_some(),
        "C check_socks4_resp() accepts status 0x5a before peer ID/ACK are processed"
    );
    assert_eq!(target_addr, runtime.meta_connection_infos()[0].peer);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_accepts_socks4a_config_but_fails_like_c_unimplemented_proxy() {
    tinc_test_support::assert_can_create_netns();
    let proxy = ProxyConfig::Socks4a {
        host: "127.0.0.1".to_owned(),
        port: "1080".to_owned(),
        user: Some("user".to_owned()),
        password: None,
    };
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 655);

    assert!(matches!(
        outgoing_proxy_connect_target(&proxy, target, "alpha", "beta", Some("net")),
        Err(TincdError::MetaConnection(message))
            if message == "Proxy type not implemented yet"
    ));
}

#[test]
fn runtime_connects_configured_peer_through_socks5_password_proxy_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-socks5-password-proxy");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let proxy_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind SOCKS5 proxy listener: {error}"),
    };
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    drop(target_listener);

    fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\nProxy = socks5 {} {} user pass\n",
            proxy_addr.ip(),
            proxy_addr.port()
        ),
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            target_addr.ip(),
            target_addr.port(),
            beta_key.public_key().to_base64()
        ),
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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);
    runtime.set_bypass_security(true);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());

    let (mut proxy_stream, _) = proxy_listener.accept().unwrap();
    drive_outgoing_meta_output(&mut runtime);
    proxy_stream
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let mut request = vec![0u8; 24];
    proxy_stream.read_exact(&mut request).unwrap();
    let mut expected = vec![5, 1, 2, 1, 4];
    expected.extend_from_slice(b"user");
    expected.push(4);
    expected.extend_from_slice(b"pass");
    expected.extend_from_slice(&[5, 1, 0, 1]);
    let IpAddr::V4(target_ip) = target_addr.ip() else {
        panic!("SOCKS5 password proxy test target should be IPv4");
    };
    expected.extend_from_slice(&target_ip.octets());
    expected.extend_from_slice(&target_addr.port().to_be_bytes());
    assert_eq!(
        expected, request,
        "C create_socks5_req() sends greeting, username/password auth and CONNECT request in one meta write"
    );

    let mut response = vec![5, 2, 1, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 0];
    response.extend_from_slice(b"0 beta 17.0\n4 655 0 0\n");
    proxy_stream.write_all(&response).unwrap();
    runtime.poll_once().unwrap();
    assert!(
        runtime.state.graph.edge("alpha", "beta").is_some(),
        "C check_socks5_resp() accepts password auth status OK before peer ID/ACK are processed"
    );
    assert_eq!(target_addr, runtime.meta_connection_infos()[0].peer);

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn runtime_connects_configured_peer_through_exec_proxy_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-exec-proxy");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let target_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    drop(target_listener);
    let transcript = confbase.join("exec-proxy.transcript");
    let script = confbase.join("exec-proxy.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n\
             IFS= read -r line\n\
             printf 'line=%s\\nNAME=%s\\nNODE=%s\\nNETNAME=%s\\nREMOTEADDRESS=%s\\nREMOTEPORT=%s\\n' \"$line\" \"$NAME\" \"$NODE\" \"$NETNAME\" \"$REMOTEADDRESS\" \"$REMOTEPORT\" > '{}'\n\
             printf '0 beta 17.0\\n4 655 0 0\\n'\n\
             sleep 2\n",
            transcript.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script, permissions).unwrap();
    }

    fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\nProxy = exec {}\n",
            script.display()
        ),
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            target_addr.ip(),
            target_addr.port(),
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    options.netname = Some("prod".to_owned());
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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);
    runtime.enable_scripts(&config, &options);
    runtime.set_bypass_security(true);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());
    let deadline = Instant::now() + StdDuration::from_secs(1);
    while runtime.state.graph.edge("alpha", "beta").is_none() && Instant::now() < deadline {
        runtime.poll_once().unwrap();
        thread::sleep(StdDuration::from_millis(10));
    }

    assert!(
        runtime.state.graph.edge("alpha", "beta").is_some(),
        "C send_proxyrequest(PROXY_EXEC) sends no proxy prelude, then receive_request() processes peer ID/ACK from the pipe"
    );
    assert_eq!(target_addr, runtime.meta_connection_infos()[0].peer);
    let transcript = fs::read_to_string(transcript).unwrap();
    assert!(transcript.contains("line=0 alpha 17.0\n"));
    assert!(transcript.contains("NAME=alpha\n"));
    assert!(transcript.contains("NODE=beta\n"));
    assert!(transcript.contains("NETNAME=prod\n"));
    assert!(transcript.contains(&format!("REMOTEADDRESS={}\n", target_addr.ip())));
    assert!(transcript.contains(&format!("REMOTEPORT={}\n", target_addr.port())));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_connects_configured_peer_after_first_address_fails_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-to-address-list");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let dead_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind dead listener: {error}"),
    };
    let dead_addr = dead_listener.local_addr().unwrap();
    drop(dead_listener);
    let remote_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\n",
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nAddress = localhost {}\nEd25519PublicKey = {}\n",
            dead_addr.ip(),
            dead_addr.port(),
            remote_addr.port(),
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let addresses = config.addresses.addresses("beta").unwrap();
    assert_eq!(dead_addr, addresses[0]);
    assert_eq!(remote_addr, addresses[1]);
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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());

    let (remote_stream, _) = accept_after_runtime_progress(&remote_listener, &mut runtime);
    drive_outgoing_meta_output(&mut runtime);
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    assert_eq!(remote_addr, runtime.meta_connection_infos()[0].peer);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_outgoing_connection_prefers_disk_address_cache_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-address-cache");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let dead_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind configured listener: {error}"),
    };
    let configured_addr = dead_listener.local_addr().unwrap();
    let cached_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let cached_addr = cached_listener.local_addr().unwrap();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\n",
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            configured_addr.ip(),
            configured_addr.port(),
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();
    write_tinc_address_cache(&confbase.join("cache").join("beta"), &[cached_addr]).unwrap();

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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);
    runtime.set_confbase(confbase.clone());

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());

    let (remote_stream, _) = cached_listener.accept().unwrap();
    drive_outgoing_meta_output(&mut runtime);
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    assert_eq!(cached_addr, runtime.meta_connection_infos()[0].peer);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_outgoing_address_cache_falls_back_to_second_recent_and_promotes_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-address-cache-two-recent");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let dead_probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to reserve first recent address: {error}"),
    };
    let first_recent_addr = dead_probe.local_addr().unwrap();
    drop(dead_probe);
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind beta listener: {error}"),
    };
    let second_recent_addr = beta_socket.address;
    let configured_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let configured_addr = configured_listener.local_addr().unwrap();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\n",
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = {} {}\nEd25519PublicKey = {}\n",
            configured_addr.ip(),
            configured_addr.port(),
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();
    write_tinc_address_cache(
        &confbase.join("cache").join("beta"),
        &[first_recent_addr, second_recent_addr],
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let alpha_config = load_runtime_config(&options).unwrap();
    let alpha_keys = load_runtime_keys(&options).unwrap();
    let alpha_sockets = match bind_runtime_listeners(&alpha_config) {
        Ok(sockets) => sockets,
        Err(TincdError::ListenIo(error))
            if error.contains("Operation not permitted") || error.contains("Permission denied") =>
        {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind runtime listeners: {error}"),
    };
    let beta_config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "beta"),
        ("AddressFamily", "IPv4"),
    ]))
    .unwrap();
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(alpha_sockets, &alpha_config, alpha_keys);
    alpha.set_confbase(confbase.clone());
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    assert_eq!(1, alpha.connect_configured_peers(&alpha_config).unwrap());

    for _ in 0..100 {
        alpha.poll_once().unwrap();
        if alpha.meta_connection_infos()[0].peer == second_recent_addr {
            break;
        }
        thread::sleep(StdDuration::from_millis(10));
    }

    assert_eq!(second_recent_addr, alpha.meta_connection_infos()[0].peer);
    assert_eq!(
        0, alpha.outgoing_retry["beta"].timeout_secs,
        "initial C outgoing_t timeout starts at zero until a retry failure increments it"
    );

    for _ in 0..100 {
        alpha.poll_once().unwrap();
        beta.poll_once().unwrap();
        alpha.flush_meta_outputs().unwrap();
        beta.flush_meta_outputs().unwrap();
        if alpha.state.graph.edge("alpha", "beta").is_some() {
            break;
        }
        thread::sleep(StdDuration::from_millis(10));
    }
    assert!(alpha.state.graph.edge("alpha", "beta").is_some());
    assert_eq!(
        vec![second_recent_addr, first_recent_addr],
        read_tinc_address_cache(&confbase.join("cache").join("beta")),
        "C get_recent_address() tries cached slots in order and add_recent_address() promotes the address that completed activation"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_outgoing_connection_uses_reverse_edge_before_config_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-reverse-edge-address");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let dead_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind configured listener: {error}"),
    };
    let configured_addr = dead_listener.local_addr().unwrap();
    let reverse_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let reverse_addr = reverse_listener.local_addr().unwrap();

    let server = config_tree(&[("Name", "alpha"), ("AddressFamily", "IPv4")]);
    let beta_host = config_tree(&[(
        "Address",
        &format!("{} {}", configured_addr.ip(), configured_addr.port()),
    )]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.set_confbase(confbase.clone());
    runtime.state.graph.ensure_node("relay");
    runtime.state.graph.ensure_node("beta");
    runtime
        .state
        .graph
        .add_edge(Edge::new("beta", "relay", 1))
        .unwrap();
    runtime
        .state
        .graph
        .add_edge(
            Edge::new("relay", "beta", 1).with_address(EdgeEndpoint::new(
                reverse_addr.ip().to_string(),
                reverse_addr.port().to_string(),
            )),
        )
        .unwrap();

    assert!(runtime.connect_peer(&config, "beta").unwrap());

    let (remote_stream, _) = reverse_listener.accept().unwrap();
    drive_outgoing_meta_output(&mut runtime);
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    assert_eq!(reverse_addr, runtime.meta_connection_infos()[0].peer);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_address_cache_file_matches_tinc_binary_layout() {
    tinc_test_support::assert_can_create_netns();
    let first: SocketAddr = "127.0.0.1:655".parse().unwrap();
    let second: SocketAddr = "[::1]:443".parse().unwrap();
    let encoded = encode_tinc_address_cache(&[first, second]);

    #[cfg(unix)]
    assert_eq!(
        8 + MAX_CACHED_ADDRESSES * c_sockaddr_cache_slot_len(),
        encoded.len(),
        "C address_cache_t::data is version/used plus sockaddr_t[MAX_CACHED_ADDRESSES]"
    );
    assert_eq!(
        ADDRESS_CACHE_VERSION,
        u32::from_ne_bytes(encoded[0..4].try_into().unwrap())
    );
    assert_eq!(2, u32::from_ne_bytes(encoded[4..8].try_into().unwrap()));
    assert_eq!(vec![first, second], decode_tinc_address_cache(&encoded));

    let mut promoted = vec![first, second];
    promote_recent_address(&mut promoted, second);
    assert_eq!(vec![second, first], promoted);
    for port in 10..20 {
        promote_recent_address(
            &mut promoted,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        );
    }
    assert_eq!(MAX_CACHED_ADDRESSES, promoted.len());
}

#[test]
fn runtime_outgoing_ack_caches_remote_address_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-cache-after-ack");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind alpha listener: {error}"),
    };
    let beta_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind beta listener: {error}"),
    };
    let beta_addr = beta_socket.address;
    let alpha_server = config_tree(&[("Name", "alpha"), ("AddressFamily", "IPv4")]);
    let beta_host = config_tree(&[(
        "Address",
        &format!("{} {}", beta_addr.ip(), beta_addr.port()),
    )]);
    let alpha_config =
        RuntimeConfig::from_config_tree_with_hosts(&alpha_server, [("beta", &beta_host)]).unwrap();
    let beta_config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "beta"),
        ("AddressFamily", "IPv4"),
    ]))
    .unwrap();
    let alpha_keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let beta_keys = RuntimeKeys {
        private_key: Some(beta_key),
        peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(vec![alpha_socket], &alpha_config, alpha_keys);
    alpha.set_confbase(confbase.clone());
    let mut beta = RuntimeDaemonState::new(vec![beta_socket], &beta_config, beta_keys);

    assert!(alpha.connect_peer(&alpha_config, "beta").unwrap());
    for _ in 0..100 {
        alpha.poll_once().unwrap();
        beta.poll_once().unwrap();
        alpha.flush_meta_outputs().unwrap();
        beta.flush_meta_outputs().unwrap();
        if alpha.state.graph.edge("alpha", "beta").is_some() {
            break;
        }
        thread::sleep(StdDuration::from_millis(10));
    }
    assert!(alpha.state.graph.edge("alpha", "beta").is_some());
    assert_eq!(
        vec![beta_addr],
        read_tinc_address_cache(&confbase.join("cache").join("beta")),
        "C ack_h()/graph reachable path records the activated outgoing meta address"
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_pong_after_outgoing_retry_resets_address_cache_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-pong-cache-reset");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let old_addr: SocketAddr = "127.0.0.1:10".parse().unwrap();
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let beta_addr = beta_connection.peer;
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &config, keys);
    alpha.set_confbase(confbase.clone());
    beta_connection.id = 1;
    beta_connection.outgoing_peer = Some("beta".to_owned());
    alpha.meta_connections.push(beta_connection);
    write_tinc_address_cache(&confbase.join("cache").join("beta"), &[old_addr]).unwrap();
    alpha.mark_outgoing_failed("beta", Instant::now());
    assert!(alpha.outgoing_retry["beta"].timeout_secs > 0);

    alpha
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::Pong)],
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(
        vec![beta_addr, old_addr],
        read_tinc_address_cache(&confbase.join("cache").join("beta")),
        "C pong_h() resets cache iterator state and promotes the active outgoing address after retry succeeds"
    );
    assert_eq!(0, alpha.outgoing_retry["beta"].timeout_secs);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_binds_outgoing_connection_to_unique_bindtoaddress() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-bind-address");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let local_bind_ip = "127.0.0.2".parse::<IpAddr>().unwrap();
    let remote_listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind remote listener: {error}"),
    };
    let remote_addr = remote_listener.local_addr().unwrap();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.2 0\nConnectTo = beta\n",
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
    let keys = load_runtime_keys(&options).unwrap();
    let sockets = match bind_runtime_listeners(&config) {
        Ok(sockets) => sockets,
        Err(TincdError::ListenIo(error))
            if error.contains("Operation not permitted")
                || error.contains("Permission denied")
                || error.contains("Cannot assign requested address") =>
        {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind runtime listeners: {error}"),
    };
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());

    let (remote_stream, remote_peer) = remote_listener.accept().unwrap();
    assert_eq!(local_bind_ip, remote_peer.ip());
    drive_outgoing_meta_output(&mut runtime);
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);

    let connections = runtime.meta_connection_infos();
    assert_eq!(1, connections.len());
    assert_eq!(local_bind_ip, connections[0].local.ip());
    assert_eq!(remote_addr, connections[0].peer);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_can_retry_configured_peer_after_initial_failure() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-connect-retry");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to reserve remote address: {error}"),
    };
    let remote_addr = probe.local_addr().unwrap();
    drop(probe);

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nConnectTo = beta\n",
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
    let mut runtime = RuntimeDaemonState::new(sockets, &config, keys);

    assert_eq!(1, runtime.connect_configured_peers(&config).unwrap());
    assert_eq!(1, runtime.meta_connection_infos().len());
    for _ in 0..100 {
        runtime.poll_once().unwrap();
        if runtime.meta_connection_infos().is_empty() {
            break;
        }
        thread::sleep(StdDuration::from_millis(10));
    }
    assert!(runtime.meta_connection_infos().is_empty());
    assert!(runtime.outgoing_retry["beta"].timeout_secs > 0);

    let remote_listener = match TcpListener::bind(remote_addr) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind retry listener: {error}"),
    };

    runtime.outgoing_retry.get_mut("beta").unwrap().next_attempt =
        Instant::now() - StdDuration::from_secs(1);
    assert_eq!(1, runtime.retry_configured_peers(&config).unwrap());
    let (remote_stream, _) = accept_after_runtime_progress(&remote_listener, &mut runtime);
    drive_outgoing_meta_output(&mut runtime);
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);

    let connections = runtime.meta_connection_infos();
    assert_eq!(1, connections.len());
    assert_eq!(Some("beta".to_owned()), connections[0].name);

    fs::remove_dir_all(confbase).unwrap();
}
