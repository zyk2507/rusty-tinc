use super::*;

#[test]
fn runtime_key_expire_broadcasts_key_changed_and_forces_sptps_kex_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("KeyExpire", "1")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let mut beta_runtime = RuntimeDaemonState::new(
        Vec::new(),
        &RuntimeConfig::from_config_tree(&config_tree(&[("Name", "beta")])).unwrap(),
        RuntimeKeys {
            private_key: Some(beta_key.clone()),
            peer_public_keys: BTreeMap::from([("alpha".to_owned(), alpha_key.public_key())]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    complete_sptps_udp_exchange(&mut runtime, &mut beta_runtime);

    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.valid_key_in = true;

    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind key expire test listener: {error}"),
    };
    let mut remote_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (daemon_stream, peer) = listener.accept().unwrap();
    daemon_stream.set_nonblocking(true).unwrap();
    remote_stream
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let local = daemon_stream.local_addr().unwrap();
    let (alpha_driver, mut beta_driver) =
        established_meta_driver_pair(alpha_key.clone(), beta_key.clone());

    runtime.meta_connections.push(RuntimeMetaConnection {
        id: 1,
        stream: daemon_stream,
        peer,
        local,
        bytes_read: 0,
        bytes_written: 0,
        outbound: Vec::new(),
        outbound_offset: 0,
        status: CONNECTION_STATUS_ACTIVE,
        options: (PROT_MINOR as u32) << 24,
        outgoing_autoconnect: false,
        close_requested: false,
        last_activity: Instant::now(),
        last_ping_sent: None,
        exec_proxy: None,
        kind: RuntimeMetaConnectionKind::Active {
            driver: RuntimeMetaDriver::modern(alpha_driver),
            name: Some("beta".to_owned()),
            proxy: ProxyHandshake::None,
        },
    });
    runtime.next_key_expire = Some(Instant::now() - StdDuration::from_secs(1));

    runtime.expire_symmetric_keys().unwrap();

    assert!(
        !runtime
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .valid_key_in
    );
    let mut buffer = [0u8; 4096];
    let len = remote_stream.read(&mut buffer).unwrap();
    let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();
    assert!(step.events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::KeyChanged(KeyChangedMessage {
                origin,
                ..
            })) if origin == "alpha"
        )
    }));
    assert!(step.events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha"
                    && answer.to == "beta"
                    && answer.is_sptps_handshake()
        )
    }));
}

#[test]
fn runtime_key_expire_sends_legacy_ans_key_to_direct_non_sptps_peer_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("ExperimentalProtocol", "no"),
        ("KeyExpire", "1"),
    ]))
    .unwrap();
    let keys = RuntimeKeys {
        private_key: None,
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(alpha_rsa.clone())),
        peer_rsa_public_keys: BTreeMap::from([("beta".to_owned(), RsaPublicKey::from(&beta_rsa))]),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_legacy_runtime_connection("beta", alpha_rsa, beta_rsa)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.status.valid_key_in = true;
    beta.route.next_hop = Some("beta".to_owned());
    runtime.next_key_expire = Some(Instant::now() - StdDuration::from_secs(1));

    runtime.expire_symmetric_keys().unwrap();

    assert!(
        !runtime
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .valid_key_in
    );
    assert!(runtime.legacy_codec.peer("beta").is_some());

    let mut events = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    while Instant::now() < deadline {
        match beta_stream.read(&mut buffer) {
            Ok(len) => {
                events.extend(beta_driver.receive_bytes(&buffer[..len]).unwrap().events);
                if events.iter().any(|event| {
                    matches!(
                        event,
                        MetaConnectionEvent::Message(MetaMessage::KeyChanged(KeyChangedMessage {
                            origin,
                            ..
                        })) if origin == "alpha"
                    )
                }) && events.iter().any(|event| {
                    matches!(
                        event,
                        MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                            if answer.from == "alpha"
                                && answer.to == "beta"
                                && !answer.is_sptps_handshake()
                    )
                }) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to read legacy key-expire messages: {error}"),
        }
    }

    assert!(events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::KeyChanged(KeyChangedMessage {
                origin,
                ..
            })) if origin == "alpha"
        )
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha" && answer.to == "beta" && !answer.is_sptps_handshake()
        )
    }));
}

#[test]
fn runtime_tunnel_server_applies_but_does_not_forward_key_changed_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let server = config_tree(&[("Name", "alpha"), ("TunnelServer", "yes")]);
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
    beta.status.valid_key = true;
    beta.status.sptps = false;
    runtime
        .legacy_last_req_key
        .insert("beta".to_owned(), Instant::now());

    beta_stream
        .write_all(
            &beta_driver
                .send_meta_message(&MetaMessage::KeyChanged(KeyChangedMessage {
                    nonce: 0x1234,
                    origin: "beta".to_owned(),
                }))
                .unwrap(),
        )
        .unwrap();

    runtime.poll_once().unwrap();

    assert!(
        !runtime.state.graph.node("beta").unwrap().status.valid_key,
        "C key_changed_h() clears validkey for non-SPTPS origins"
    );
    assert!(
        !runtime.legacy_last_req_key.contains_key("beta"),
        "C key_changed_h() resets last_req_key so the next legacy send can request a fresh key"
    );

    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::KeyChanged(KeyChangedMessage {
                origin,
                ..
            })) if origin == "beta"
        )
    });
    assert!(
        !events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::KeyChanged(KeyChangedMessage {
                origin,
                ..
            })) if origin == "beta"
        )),
        "C key_changed_h() does not forward KEY_CHANGED while TunnelServer is enabled"
    );
}

#[test]
fn runtime_meta_request_nonce_starts_randomly_like_tinc() {
    let first = random_meta_nonce_start();
    let second = random_meta_nonce_start();

    assert!(
        first != 1 || second != 1,
        "C topology messages use random nonces; restarting Rust tincd must not reuse nonce 1 because peers cache seen request lines"
    );
}

#[test]
fn runtime_tunnel_server_drops_transit_ans_key_like_tinc() {
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
    for peer in ["beta", "gamma"] {
        runtime.state.graph.ensure_node(peer);
        let node = runtime.state.graph.node_mut(peer).unwrap();
        node.status.reachable = true;
        node.route.next_hop = Some(peer.to_owned());
    }

    let answer = MetaMessage::AnswerKey(
        AnswerKeyMessage {
            from: "beta".to_owned(),
            to: "gamma".to_owned(),
            key: "42".repeat(48),
            cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
            digest: LegacyDigest::Sha256 { length: 4 }.nid(),
            mac_length: 4,
            compression: 0,
            address: None,
        }
        .with_address("203.0.113.77", "1665"),
    );
    beta_stream
        .write_all(&beta_driver.send_meta_message(&answer).unwrap())
        .unwrap();

    runtime.poll_once().unwrap();

    assert!(
        runtime.legacy_codec.peer("beta").is_none(),
        "C ans_key_h() returns before installing transit ANS_KEY material on a tunnel server"
    );
    assert!(
        runtime
            .state
            .graph
            .node("beta")
            .unwrap()
            .udp_address
            .is_none(),
        "C ans_key_h() returns before applying a transit ANS_KEY reflexive UDP address on a tunnel server"
    );
    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(forwarded))
                if forwarded.from == "beta" && forwarded.to == "gamma"
        )
    });
    assert!(
        !events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(forwarded))
                if forwarded.from == "beta" && forwarded.to == "gamma"
        )),
        "C ans_key_h() does not forward transit ANS_KEY while TunnelServer is enabled"
    );
}

#[test]
fn runtime_negative_key_expire_fires_once_like_tinc_timer() {
    tinc_test_support::assert_can_create_netns();
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("KeyExpire", "-1")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.next_key_expire = Some(Instant::now() - StdDuration::from_secs(1));

    runtime.expire_symmetric_keys().unwrap();
    assert_eq!(None, runtime.next_key_expire);

    runtime.expire_symmetric_keys().unwrap();
    assert_eq!(None, runtime.next_key_expire);
}

#[test]
fn runtime_key_expire_timer_includes_tinc_jitter() {
    tinc_test_support::assert_can_create_netns();
    let base = Instant::now();

    let scheduled = schedule_next_key_expire(base, 1).expect("positive KeyExpire schedules");
    let delay = scheduled.saturating_duration_since(base);
    assert!(
        delay >= StdDuration::from_secs(1),
        "C timeout_set() schedules KeyExpire after the configured seconds"
    );
    assert!(
        delay < StdDuration::from_secs(1) + StdDuration::from_micros(TINC_TIMER_JITTER_US as u64),
        "C KeyExpire timers add jitter() microseconds below 131072"
    );

    assert_eq!(
        Some(base),
        schedule_next_key_expire(base, -1),
        "negative KeyExpire remains immediately due so it fires once like C"
    );
}

#[test]
fn runtime_tarpits_incoming_meta_bursts_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("MaxConnectionBurst", "3"),
    ]))
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let now = Instant::now();

    assert!(!runtime.should_tarpit_meta_connection("198.51.100.1:1".parse().unwrap(), now));
    assert!(!runtime.should_tarpit_meta_connection("198.51.100.2:1".parse().unwrap(), now));
    assert!(runtime.should_tarpit_meta_connection("198.51.100.3:1".parse().unwrap(), now));
    assert!(!runtime.should_tarpit_meta_connection(
        "198.51.100.4:1".parse().unwrap(),
        now + StdDuration::from_secs(4)
    ));
}

#[test]
fn runtime_tarpit_skips_loopback_connections_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("MaxConnectionBurst", "1"),
    ]))
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let now = Instant::now();

    for _ in 0..4 {
        assert!(!runtime.should_tarpit_meta_connection("127.0.0.1:1".parse().unwrap(), now));
    }
    assert!(runtime.should_tarpit_meta_connection("198.51.100.1:1".parse().unwrap(), now));
}

#[test]
fn runtime_tarpit_keeps_recent_sockets_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind tarpit listener: {error}"),
    };
    let address = listener.local_addr().unwrap();
    for _ in 0..(TARPIT_CAPACITY + 2) {
        let client = TcpStream::connect(address).unwrap();
        let (stream, _) = listener.accept().unwrap();
        runtime.tarpit_meta_connection(stream);
        drop(client);
    }

    assert_eq!(TARPIT_CAPACITY, runtime.tarpit.len());
}

#[test]
fn runtime_meta_ack_uses_peer_configured_options_and_weight_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let server = config_tree(&[("Name", "alpha"), ("Weight", "9"), ("ClampMSS", "yes")]);
    let beta_host = config_tree(&[("TCPOnly", "yes"), ("ClampMSS", "no"), ("Weight", "42")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert_eq!(42, runtime.local_weight_for_peer("beta"));
    assert_eq!(
        ((PROT_MINOR as u32) << 24) | OPTION_TCPONLY | OPTION_INDIRECT,
        runtime.local_options_for_peer("beta")
    );
    assert_eq!(9, runtime.local_weight_for_peer("gamma"));

    let mut alpha = runtime.meta_driver_for_peer("beta", true).unwrap().unwrap();
    let mut beta = MetaConnectionDriver::new(MetaConnectionAuth::new(
        "beta",
        false,
        beta_key,
        alpha_key.public_key(),
        "655",
        0,
        (PROT_MINOR as u32) << 24,
    ));

    let alpha_id = alpha.initial_id_bytes();
    let beta_after_id = beta.receive_bytes(&alpha_id).unwrap();
    let mut beta_to_alpha = beta.initial_id_bytes();
    beta_to_alpha.extend(flatten_outbound(beta_after_id.outbound));

    let alpha_after_beta = alpha.receive_bytes(&beta_to_alpha).unwrap();
    let beta_after_alpha = beta
        .receive_bytes(&flatten_outbound(alpha_after_beta.outbound))
        .unwrap();
    let alpha_after_beta_ack = alpha
        .receive_bytes(&flatten_outbound(beta_after_alpha.outbound))
        .unwrap();
    let beta_done = beta
        .receive_bytes(&flatten_outbound(alpha_after_beta_ack.outbound))
        .unwrap();

    assert!(
        beta_done
            .events
            .contains(&MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                peer: "alpha".to_owned(),
                port: "655".to_owned(),
                weight: 21,
                options: ((PROT_MINOR as u32) << 24) | OPTION_TCPONLY | OPTION_INDIRECT,
            }))
    );
}

#[test]
fn runtime_bypass_security_skips_peer_key_requirement_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert!(matches!(
        runtime.meta_driver_for_peer("beta", true),
        Err(TincdError::UnknownPeerKey(peer)) if peer == "beta"
    ));

    runtime.set_bypass_security(true);
    let driver = runtime.meta_driver_for_peer("beta", true).unwrap().unwrap();

    assert_eq!(
        "0 alpha 17.0\n",
        String::from_utf8(driver.initial_id_bytes()).unwrap()
    );
}

#[test]
fn runtime_uses_legacy_rsa_meta_driver_without_peer_ed25519_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let alpha_public = alpha_key.public_key().to_base64();
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(alpha_rsa.clone())),
        peer_rsa_public_keys: BTreeMap::from([("beta".to_owned(), RsaPublicKey::from(&beta_rsa))]),
    };
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let mut alpha = runtime.meta_driver_for_peer("beta", true).unwrap().unwrap();
    let mut beta = LegacyMetaConnectionDriver::new(
        LegacyMetaAuth::new(
            "beta",
            false,
            LegacyMetaPrivateKey::Pem(beta_rsa),
            RsaPublicKey::from(&alpha_rsa),
            "655",
            20,
            0,
        )
        .with_protocol_minor(PROT_MINOR as i32)
        .with_upgrade_public_key("beta-ed25519"),
    );

    assert!(matches!(alpha, RuntimeMetaDriver::Legacy(_)));
    assert_eq!(
        "0 alpha 17.1\n",
        String::from_utf8(alpha.initial_id_bytes()).unwrap()
    );

    let beta_after_id = beta.receive_bytes(&alpha.initial_id_bytes()).unwrap();
    assert_eq!(2, beta_after_id.outbound.len());
    assert_eq!(
        format!("0 beta 17.{PROT_MINOR}\n"),
        String::from_utf8(beta_after_id.outbound[0].clone()).unwrap()
    );
    assert!(
        String::from_utf8(beta_after_id.outbound[1].clone())
            .unwrap()
            .starts_with("1 429 672 4 0 ")
    );

    let alpha_after_id = alpha
        .receive_bytes(&beta_after_id.outbound.concat())
        .unwrap();
    assert_eq!(2, alpha_after_id.outbound.len());
    assert!(
        String::from_utf8(alpha_after_id.outbound[0].clone())
            .unwrap()
            .starts_with("1 429 672 4 0 ")
    );
    assert!(String::from_utf8(alpha_after_id.outbound[1].clone()).is_err());

    let beta_after_metakey = beta
        .receive_bytes(&alpha_after_id.outbound.concat())
        .unwrap();
    assert_eq!(1, beta_after_metakey.outbound.len());
    let alpha_after_challenge = alpha
        .receive_bytes(&beta_after_metakey.outbound.concat())
        .unwrap();
    assert_eq!(1, alpha_after_challenge.outbound.len());
    let beta_after_reply = beta
        .receive_bytes(&alpha_after_challenge.outbound.concat())
        .unwrap();
    assert_eq!(2, beta_after_reply.outbound.len());
    let alpha_done = alpha
        .receive_bytes(&beta_after_reply.outbound.concat())
        .unwrap();
    assert!(!alpha.is_activated());
    assert!(alpha_done.events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Auth(MetaAuthEvent::LegacyEd25519Upgrade { peer, public_key })
                if peer == "beta" && public_key == "beta-ed25519"
        )
    }));
    let beta_done = beta.receive_bytes(&alpha_done.outbound.concat()).unwrap();
    assert_eq!(
        tinc_runtime::legacy_meta::LegacyMetaAuthState::UpgradeTerminating,
        beta.auth().state()
    );
    assert!(beta_done.events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Auth(MetaAuthEvent::LegacyEd25519Upgrade { peer, public_key })
                if peer == "alpha" && public_key == &alpha_public
        )
    }));
    assert!(
        beta_done
            .events
            .contains(&MetaConnectionEvent::Message(MetaMessage::TerminateRequest))
    );
}

#[test]
fn runtime_incoming_legacy_rsa_meta_driver_sends_id_and_metakey_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(alpha_rsa)),
        peer_rsa_public_keys: BTreeMap::from([("beta".to_owned(), RsaPublicKey::from(&beta_rsa))]),
    };
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let mut alpha = runtime
        .meta_driver_for_incoming_peer("beta", Some(LEGACY_META_PROTOCOL_MINOR))
        .unwrap()
        .unwrap();

    assert!(matches!(alpha, RuntimeMetaDriver::Legacy(_)));
    assert_eq!(None, alpha.incoming_initial_id_bytes());
    let step = alpha.receive_bytes(b"0 beta 17.0\n").unwrap();
    assert_eq!(2, step.outbound.len());
    assert_eq!(
        "0 alpha 17.0\n",
        String::from_utf8(step.outbound[0].clone()).unwrap()
    );
    assert!(
        String::from_utf8(step.outbound[1].clone())
            .unwrap()
            .starts_with("1 429 672 4 0 ")
    );
}

#[test]
fn runtime_incoming_legacy_rsa_minor_one_sends_current_id_and_metakey_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(alpha_rsa)),
        peer_rsa_public_keys: BTreeMap::from([("beta".to_owned(), RsaPublicKey::from(&beta_rsa))]),
    };
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let mut alpha = runtime
        .meta_driver_for_incoming_peer("beta", Some(LEGACY_META_UPGRADE_PROTOCOL_MINOR))
        .unwrap()
        .unwrap();

    assert!(matches!(alpha, RuntimeMetaDriver::Legacy(_)));
    assert_eq!(None, alpha.incoming_initial_id_bytes());
    let step = alpha.receive_bytes(b"0 beta 17.1\n").unwrap();
    assert_eq!(2, step.outbound.len());
    assert_eq!(
        format!("0 alpha 17.{PROT_MINOR}\n"),
        String::from_utf8(step.outbound[0].clone()).unwrap()
    );
    assert!(
        String::from_utf8(step.outbound[1].clone())
            .unwrap()
            .starts_with("1 429 672 4 0 ")
    );
}

#[test]
fn runtime_legacy_ed25519_upgrade_appends_host_config_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-legacy-upgrade-config");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let beta_public = beta_key.public_key().to_base64();
    fs::write(
        confbase.join("hosts").join("beta"),
        "Address = beta.example\n",
    )
    .unwrap();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.set_confbase(confbase.clone());
    runtime.mark_outgoing_failed("beta", Instant::now());
    assert!(runtime.outgoing_retry["beta"].timeout_secs > 0);

    runtime
        .accept_legacy_ed25519_upgrade("beta", &beta_public)
        .unwrap();

    let host = fs::read_to_string(confbase.join("hosts").join("beta")).unwrap();
    assert!(host.contains(&format!(
        "\n# The following line was automatically added by tinc\nEd25519PublicKey = {beta_public}\n"
    )));
    assert_eq!(
        Some(beta_key.public_key()),
        runtime.keys.peer_public_keys.get("beta").copied()
    );
    assert_eq!(0, runtime.outgoing_retry["beta"].timeout_secs);
    assert!(runtime.outgoing_retry["beta"].next_attempt <= Instant::now());

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_legacy_ed25519_upgrade_marks_connection_for_close_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-legacy-upgrade-close");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let beta_public = beta_key.public_key().to_base64();
    fs::write(
        confbase.join("hosts").join("beta"),
        "Address = beta.example\n",
    )
    .unwrap();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(alpha_rsa.clone())),
        peer_rsa_public_keys: BTreeMap::from([("beta".to_owned(), RsaPublicKey::from(&beta_rsa))]),
    };
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_legacy_runtime_connection("beta", alpha_rsa, beta_rsa)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.set_confbase(confbase.clone());
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);

    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Auth(
                    MetaAuthEvent::LegacyEd25519Upgrade {
                        peer: "beta".to_owned(),
                        public_key: beta_public,
                    },
                )],
                ..Default::default()
            },
        )
        .unwrap();

    assert!(runtime.meta_connections[0].close_requested);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_answers_extended_req_pubkey_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());

    let request = MetaMessage::RequestKey(RequestKeyMessage {
        from: "beta".to_owned(),
        to: "alpha".to_owned(),
        extension: Some(RequestKeyExtension {
            request: Request::RequestPublicKey.number(),
            payload: None,
        }),
    });
    let wire = beta_driver.send_meta_message(&request).unwrap();
    beta_stream.write_all(&wire).unwrap();
    runtime.poll_once().unwrap();

    let mut events = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    while Instant::now() < deadline {
        match beta_stream.read(&mut buffer) {
            Ok(len) => {
                events.extend(beta_driver.receive_bytes(&buffer[..len]).unwrap().events);
                if events.iter().any(|event| {
                    matches!(
                        event,
                        MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                            if request.from == "alpha"
                                && request.to == "beta"
                                && request.extension.as_ref().is_some_and(|extension| {
                                    extension.request == Request::RequestPublicKey.number()
                                        && extension.payload.is_none()
                                })
                    )
                }) && events.iter().any(|event| {
                    matches!(
                        event,
                        MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                            if request.from == "alpha"
                                && request.to == "beta"
                                && request.extension.as_ref().is_some_and(|extension| {
                                    extension.request == Request::AnswerPublicKey.number()
                                        && extension.payload.as_deref()
                                            == Some(alpha_key.public_key().to_base64().as_str())
                                })
                    )
                }) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to read REQ_PUBKEY responses: {error}"),
        }
    }

    assert!(events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha"
                    && request.to == "beta"
                    && request.extension.as_ref().is_some_and(|extension| {
                        extension.request == Request::RequestPublicKey.number()
                            && extension.payload.is_none()
                    })
        )
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha"
                    && request.to == "beta"
                    && request.extension.as_ref().is_some_and(|extension| {
                        extension.request == Request::AnswerPublicKey.number()
                            && extension.payload.as_deref()
                                == Some(alpha_key.public_key().to_base64().as_str())
                    })
        )
    }));
}

#[test]
fn runtime_forwards_sptps_req_key_to_target_next_hop_like_tinc() {
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
    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());
    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());

    let request = MetaMessage::RequestKey(RequestKeyMessage::sptps_initial_request(
        "beta",
        "gamma",
        b"sptps-kex",
    ));
    let wire = beta_driver.send_meta_message(&request).unwrap();
    beta_stream.write_all(&wire).unwrap();
    runtime.poll_once().unwrap();

    let mut events = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    while Instant::now() < deadline {
        match gamma_stream.read(&mut buffer) {
            Ok(len) => {
                events.extend(gamma_driver.receive_bytes(&buffer[..len]).unwrap().events);
                if events.iter().any(|event| {
                    matches!(
                        event,
                        MetaConnectionEvent::Message(message) if message == &request
                    )
                }) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to read forwarded SPTPS REQ_KEY: {error}"),
        }
    }

    assert!(events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(message) if message == &request
        )
    }));
}

#[test]
fn runtime_relayed_sptps_req_key_sends_udp_info_like_tinc() {
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
    gamma.route.via = Some("gamma".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;

    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("gamma".to_owned());
    beta.route.via = Some("beta".to_owned());
    beta.options = (PROT_MINOR as u32) << 24;

    runtime.state.graph.ensure_node("delta");
    let delta = runtime.state.graph.node_mut("delta").unwrap();
    delta.status.reachable = true;
    delta.route.next_hop = Some("gamma".to_owned());
    delta.route.via = Some("alpha".to_owned());
    delta.options = (PROT_MINOR as u32) << 24;

    let request = RequestKeyMessage::sptps_initial_request("beta", "delta", b"sptps-kex");
    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::RequestKey(
                    request.clone(),
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(forwarded))
                if forwarded == &request
        )
    });

    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::UdpInfo(message))
                if message.from == "alpha" && message.to == "beta"
        )),
        "C req_key_ext_h() sends UDP_INFO(myself, from) for relayed REQ_KEY when to->via == myself"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::RequestKey(forwarded))
            if forwarded == &request
    )));
}

#[test]
fn runtime_sptps_req_key_waits_and_restarts_after_ten_seconds_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let Some((mut runtime, mut beta_stream, mut beta_driver)) =
        active_sptps_runtime_waiting_for_beta_key()
    else {
        return;
    };

    let first_events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        is_sptps_initial_req_key(event, "alpha", "beta")
    });
    assert!(
        first_events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta"))
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
    assert!(runtime.sptps_last_req_key.contains_key("beta"));
    assert!(
        runtime
            .key_exchange
            .as_ref()
            .unwrap()
            .pending_session("beta")
            .is_some()
    );

    let first_written = runtime.meta_connections[0].bytes_written;
    let action = RuntimeSptpsKeyAction {
        peer: "beta".to_owned(),
        next_hop: "beta".to_owned(),
    };
    runtime
        .handle_sptps_key_actions(vec![action.clone()])
        .unwrap();
    assert_eq!(first_written, runtime.meta_connections[0].bytes_written);

    runtime.sptps_last_req_key.insert(
        "beta".to_owned(),
        Instant::now() - SPTPS_REQ_KEY_INTERVAL - StdDuration::from_secs(1),
    );
    runtime.handle_sptps_key_actions(vec![action]).unwrap();
    assert!(runtime.meta_connections[0].bytes_written > first_written);

    let restarted_events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        is_sptps_initial_req_key(event, "alpha", "beta")
    });
    assert!(
        restarted_events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta"))
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
    assert!(runtime.sptps_last_req_key.contains_key("beta"));
    assert!(
        runtime
            .key_exchange
            .as_ref()
            .unwrap()
            .pending_session("beta")
            .is_some()
    );
}

#[test]
fn runtime_bad_sptps_ans_key_from_meta_waits_before_restart_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let Some((mut runtime, _beta_stream, _beta_driver)) =
        active_sptps_runtime_waiting_for_beta_key()
    else {
        return;
    };
    let first_written = runtime.meta_connections[0].bytes_written;

    let bad_answer = AnswerKeyMessage::sptps_handshake("beta", "alpha", b"not-a-record", 0);
    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::AnswerKey(
                    bad_answer,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(1, runtime.meta_connections.len());
    assert_eq!(
        first_written, runtime.meta_connections[0].bytes_written,
        "C ans_key_h() returns true for bad SPTPS ANS_KEY without restarting inside 10s"
    );
    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(beta.status.waiting_for_key);
    assert!(!beta.status.valid_key);
    assert!(runtime.sptps_last_req_key.contains_key("beta"));
    assert!(
        runtime
            .key_exchange
            .as_ref()
            .unwrap()
            .pending_session("beta")
            .is_some()
    );
}

#[test]
fn runtime_bad_sptps_ans_key_from_meta_restarts_after_ten_seconds_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let Some((mut runtime, mut beta_stream, mut beta_driver)) =
        active_sptps_runtime_waiting_for_beta_key()
    else {
        return;
    };
    let first_written = runtime.meta_connections[0].bytes_written;
    runtime.sptps_last_req_key.insert(
        "beta".to_owned(),
        Instant::now() - SPTPS_REQ_KEY_INTERVAL - StdDuration::from_secs(1),
    );

    let bad_answer = AnswerKeyMessage::sptps_handshake("beta", "alpha", b"not-a-record", 0);
    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::AnswerKey(
                    bad_answer,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    assert!(runtime.meta_connections[0].bytes_written > first_written);
    let restarted_events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        is_sptps_initial_req_key(event, "alpha", "beta")
    });
    assert!(
        restarted_events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta")),
        "C ans_key_h() restarts SPTPS with a fresh REQ_KEY after a bad ANS_KEY older than 10s"
    );
    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(beta.status.waiting_for_key);
    assert!(!beta.status.valid_key);
    assert!(runtime.sptps_last_req_key.contains_key("beta"));
    assert!(
        runtime
            .key_exchange
            .as_ref()
            .unwrap()
            .pending_session("beta")
            .is_some()
    );
}

#[test]
fn runtime_sptps_ans_key_applies_reflexive_address_and_sends_mtu_info_like_tinc() {
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
    beta.status.sptps = true;
    beta.route.next_hop = Some("gamma".to_owned());
    beta.route.via = Some("beta".to_owned());
    beta.options = (PROT_MINOR as u32) << 24;
    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.status.sptps = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("gamma".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;
    *runtime.packet_codec.ids_mut() = NodeIdTable::from_network_state(&runtime.state);

    let request = runtime
        .start_sptps_key_exchange("beta")
        .unwrap()
        .into_iter()
        .find_map(|message| match message {
            MetaMessage::RequestKey(request) => Some(request),
            _ => None,
        })
        .expect("expected initial SPTPS REQ_KEY from alpha to beta");
    let mut beta_kex =
        SptpsKeyExchange::new("beta", beta_key, SPTPS_UDP_ROUTER_PACKET_TYPE).unwrap();
    beta_kex.insert_peer_public_key("alpha", alpha_key.public_key());
    let first_beta_answer = beta_kex
        .receive_meta_message(&MetaMessage::RequestKey(request))
        .unwrap()
        .outbound
        .into_iter()
        .find_map(|message| match message {
            MetaMessage::AnswerKey(answer) => Some(answer),
            _ => None,
        })
        .expect("expected SPTPS ANS_KEY answer");

    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::AnswerKey(
                    first_beta_answer,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    let first_events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha"
                    && answer.to == "beta"
                    && answer.is_sptps_handshake()
        )
    });
    let alpha_answer = first_events
        .iter()
        .find_map(|event| match event {
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha" && answer.to == "beta" =>
            {
                Some(answer.clone())
            }
            _ => None,
        })
        .expect("expected alpha SPTPS handshake answer");
    assert!(
        first_events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                if message.from == "alpha"
                    && message.to == "beta"
                    && message.mtu == DEFAULT_MTU
        )),
        "C ans_key_h() calls send_mtu_info() after accepting a valid SPTPS ANS_KEY"
    );

    let final_beta_answer = beta_kex
        .receive_meta_message(&MetaMessage::AnswerKey(alpha_answer))
        .unwrap()
        .outbound
        .into_iter()
        .find_map(|message| match message {
            MetaMessage::AnswerKey(answer) => Some(answer.with_address("203.0.113.77", "1665")),
            _ => None,
        })
        .expect("expected final SPTPS ANS_KEY answer");

    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::AnswerKey(
                    final_beta_answer,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(beta.status.valid_key);
    assert_eq!(
        Some(&EdgeEndpoint::new("203.0.113.77", "1665")),
        beta.udp_address.as_ref(),
        "C ans_key_h() applies the SPTPS ANS_KEY reflexive UDP address after validkey becomes true"
    );
    assert!(!beta.status.udp_confirmed);

    assert!(runtime.packet_codec.peer("beta").is_some());
}

#[test]
fn runtime_sptps_req_key_success_sends_mtu_info_like_tinc() {
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
    beta.status.sptps = true;
    beta.route.next_hop = Some("gamma".to_owned());
    beta.route.via = Some("beta".to_owned());
    beta.options = (PROT_MINOR as u32) << 24;
    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.status.sptps = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.route.via = Some("gamma".to_owned());
    gamma.options = (PROT_MINOR as u32) << 24;
    *runtime.packet_codec.ids_mut() = NodeIdTable::from_network_state(&runtime.state);

    let mut beta_kex =
        SptpsKeyExchange::new("beta", beta_key, SPTPS_UDP_ROUTER_PACKET_TYPE).unwrap();
    beta_kex.insert_peer_public_key("alpha", alpha_key.public_key());
    let request = beta_kex
        .start_initiator("alpha")
        .unwrap()
        .outbound
        .into_iter()
        .find_map(|message| match message {
            MetaMessage::RequestKey(request) => Some(request),
            _ => None,
        })
        .expect("expected beta initial SPTPS REQ_KEY");

    gamma_stream
        .write_all(
            &gamma_driver
                .send_meta_message(&MetaMessage::RequestKey(request))
                .unwrap(),
        )
        .unwrap();
    runtime.poll_once().unwrap();

    assert!(
        !runtime.state.graph.node("beta").unwrap().status.valid_key,
        "C req_key_ext_h() clears validkey before starting responder SPTPS"
    );
    assert!(
        runtime
            .state
            .graph
            .node("beta")
            .unwrap()
            .status
            .waiting_for_key,
        "C req_key_ext_h() sets waitingforkey while responder SPTPS is pending"
    );

    let events = read_meta_events_until(&mut gamma_stream, &mut gamma_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha"
                    && answer.to == "beta"
                    && answer.is_sptps_handshake()
        ) || matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                if message.from == "alpha"
                    && message.to == "beta"
                    && message.mtu == DEFAULT_MTU
        )
    });

    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha"
                    && answer.to == "beta"
                    && answer.is_sptps_handshake()
        )),
        "valid initial SPTPS REQ_KEY should still send the handshake ANS_KEY"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::MtuInfo(message))
                if message.from == "alpha"
                    && message.to == "beta"
                    && message.mtu == DEFAULT_MTU
        )),
        "C req_key_ext_h() sends MTU_INFO after accepting REQ_SPTPS_START"
    );
}

#[test]
fn runtime_bad_sptps_req_key_start_from_meta_does_not_fail_daemon_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let Some((mut runtime, _beta_stream, _beta_driver)) =
        active_sptps_runtime_waiting_for_beta_key()
    else {
        return;
    };
    let first_written = runtime.meta_connections[0].bytes_written;
    let request = RequestKeyMessage {
        from: "beta".to_owned(),
        to: "alpha".to_owned(),
        extension: Some(RequestKeyExtension {
            request: Request::RequestKey.number(),
            payload: Some("not-base64!".to_owned()),
        }),
    };

    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::RequestKey(
                    request,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(1, runtime.meta_connections.len());
    assert_eq!(
        first_written, runtime.meta_connections[0].bytes_written,
        "C req_key_ext_h() returns true for invalid REQ_SPTPS_START data"
    );
    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(beta.status.waiting_for_key);
    assert!(!beta.status.valid_key);
}

#[test]
fn runtime_bad_sptps_packet_from_meta_waits_before_restart_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let Some((mut runtime, _beta_stream, _beta_driver)) =
        active_sptps_runtime_waiting_for_beta_key()
    else {
        return;
    };
    let first_written = runtime.meta_connections[0].bytes_written;
    let request = RequestKeyMessage::sptps_tcp_packet("beta", "alpha", b"not-a-record");

    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::RequestKey(
                    request,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(1, runtime.meta_connections.len());
    assert_eq!(
        first_written, runtime.meta_connections[0].bytes_written,
        "C req_key_ext_h() returns true for bad SPTPS_PACKET without restarting inside 10s"
    );
    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(beta.status.waiting_for_key);
    assert!(!beta.status.valid_key);
}

#[test]
fn runtime_bad_sptps_packet_from_meta_restarts_after_ten_seconds_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let Some((mut runtime, mut beta_stream, mut beta_driver)) =
        active_sptps_runtime_waiting_for_beta_key()
    else {
        return;
    };
    let first_written = runtime.meta_connections[0].bytes_written;
    runtime.sptps_last_req_key.insert(
        "beta".to_owned(),
        Instant::now() - SPTPS_REQ_KEY_INTERVAL - StdDuration::from_secs(1),
    );
    let request = RequestKeyMessage::sptps_tcp_packet("beta", "alpha", b"not-a-record");

    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::RequestKey(
                    request,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    assert!(runtime.meta_connections[0].bytes_written > first_written);
    let restarted_events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        is_sptps_initial_req_key(event, "alpha", "beta")
    });
    assert!(
        restarted_events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta")),
        "C req_key_ext_h() restarts SPTPS with send_req_key() after stale bad SPTPS_PACKET"
    );
    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(beta.status.waiting_for_key);
    assert!(!beta.status.valid_key);
}

#[test]
fn runtime_sptps_missing_peer_ed25519_requests_pubkey_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.status.sptps = true;
    beta.route.next_hop = Some("beta".to_owned());

    runtime
        .handle_sptps_key_actions(vec![RuntimeSptpsKeyAction {
            peer: "beta".to_owned(),
            next_hop: "beta".to_owned(),
        }])
        .unwrap();

    let events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha"
                    && request.to == "beta"
                    && request.extension.as_ref().is_some_and(|extension| {
                        extension.request == Request::RequestPublicKey.number()
                            && extension.payload.is_none()
                    })
        )
    });
    assert!(events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha"
                    && request.to == "beta"
                    && request.extension.as_ref().is_some_and(|extension| {
                        extension.request == Request::RequestPublicKey.number()
                            && extension.payload.is_none()
                    })
        )
    }));
    let beta = runtime.state.graph.node("beta").unwrap();
    assert!(!beta.status.waiting_for_key);
    assert!(!runtime.sptps_last_req_key.contains_key("beta"));
    assert!(
        runtime
            .key_exchange
            .as_ref()
            .unwrap()
            .pending_session("beta")
            .is_none()
    );
}

#[test]
fn runtime_learns_extended_ans_pubkey_and_appends_config_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-ans-pubkey-config");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let beta_public = beta_key.public_key().to_base64();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key.clone())
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.set_confbase(confbase.clone());
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());

    let answer = MetaMessage::RequestKey(RequestKeyMessage {
        from: "beta".to_owned(),
        to: "alpha".to_owned(),
        extension: Some(RequestKeyExtension {
            request: Request::AnswerPublicKey.number(),
            payload: Some(beta_public.clone()),
        }),
    });
    let wire = beta_driver.send_meta_message(&answer).unwrap();
    beta_stream.write_all(&wire).unwrap();
    runtime.poll_once().unwrap();

    assert_eq!(
        Some(beta_key.public_key()),
        runtime.keys.peer_public_keys.get("beta").copied()
    );
    let host = fs::read_to_string(confbase.join("hosts").join("beta")).unwrap();
    assert!(host.contains(&format!(
        "\n# The following line was automatically added by tinc\nEd25519PublicKey = {beta_public}\n"
    )));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_starts_sptps_after_learning_ans_pubkey_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-ans-pubkey-retry");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let beta_public = beta_key.public_key().to_base64();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.set_confbase(confbase.clone());
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);
    runtime.state.graph.ensure_node("beta");
    let beta = runtime.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.status.sptps = true;
    beta.route.next_hop = Some("beta".to_owned());

    runtime
        .handle_sptps_key_actions(vec![RuntimeSptpsKeyAction {
            peer: "beta".to_owned(),
            next_hop: "beta".to_owned(),
        }])
        .unwrap();
    let pubkey_events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha"
                    && request.to == "beta"
                    && request.extension.as_ref().is_some_and(|extension| {
                        extension.request == Request::RequestPublicKey.number()
                            && extension.payload.is_none()
                    })
        )
    });
    assert!(pubkey_events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha"
                    && request.to == "beta"
                    && request.extension.as_ref().is_some_and(|extension| {
                        extension.request == Request::RequestPublicKey.number()
                            && extension.payload.is_none()
                    })
        )
    }));

    let answer = MetaMessage::RequestKey(RequestKeyMessage {
        from: "beta".to_owned(),
        to: "alpha".to_owned(),
        extension: Some(RequestKeyExtension {
            request: Request::AnswerPublicKey.number(),
            payload: Some(beta_public),
        }),
    });
    let wire = beta_driver.send_meta_message(&answer).unwrap();
    beta_stream.write_all(&wire).unwrap();
    runtime.poll_once().unwrap();

    runtime
        .handle_sptps_key_actions(vec![RuntimeSptpsKeyAction {
            peer: "beta".to_owned(),
            next_hop: "beta".to_owned(),
        }])
        .unwrap();
    let sptps_events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        is_sptps_initial_req_key(event, "alpha", "beta")
    });
    assert!(
        sptps_events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta"))
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
    assert!(runtime.sptps_last_req_key.contains_key("beta"));
    assert!(
        runtime
            .key_exchange
            .as_ref()
            .unwrap()
            .pending_session("beta")
            .is_some()
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_accepts_invitation_over_sptps_tcp() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-invitation");
    let listen_socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind invitation listener: {error}"),
    };
    let listen_addr = listen_socket.info().address;
    let server_key = test_key(1);
    let invitation_key = test_key(2);
    let throwaway_key = test_key(3);
    let final_key = test_key(4);
    let cookie = [9u8; INVITATION_COOKIE_LEN];
    let invitations_dir = confbase.join("invitations");

    fs::create_dir_all(&invitations_dir).unwrap();
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nAddressFamily = IPv4\nInvitationExpire = 604800\n",
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), server_key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.1.0.0/16\n",
    )
    .unwrap();
    fs::write(
        invitations_dir.join("ed25519_key.priv"),
        invitation_key.to_pem(),
    )
    .unwrap();

    let invitation_public = invitation_key.public_key().to_base64();
    let invitation_filename = invitation_cookie_filename(&cookie, &invitation_public);
    let invitation_data = format!(
        "Name = beta\n\
ConnectTo = alpha\n\
#---------------------------------------------------------------#\n\
Name = alpha\n\
Address = {} {}\n\
Ed25519PublicKey = {}\n",
        listen_addr.ip(),
        listen_addr.port(),
        server_key.public_key().to_base64()
    );
    fs::write(
        invitations_dir.join(&invitation_filename),
        invitation_data.as_bytes(),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = load_runtime_keys(&options).unwrap();
    let mut runtime = RuntimeDaemonState::new(vec![listen_socket], &config, keys);
    runtime
        .enable_invitations(confbase.clone(), &config)
        .unwrap();

    let mut client = TcpStream::connect(listen_addr).unwrap();
    client.set_nodelay(true).unwrap();
    client
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    client
        .set_write_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    runtime.poll_once().unwrap();

    client
        .write_all(
            format!(
                "{} ?{} {}.1\n",
                Request::Id.number(),
                throwaway_key.public_key().to_base64(),
                PROT_MAJOR
            )
            .as_bytes(),
        )
        .unwrap();
    runtime.poll_once().unwrap();

    let mut buffer = Vec::new();
    let id_line = read_test_tcp_line(&mut client, &mut buffer);
    let MetaMessage::Id(id) = parse_meta_message(&id_line).unwrap() else {
        panic!("expected invitation ID response");
    };
    assert_eq!("alpha", id.name);
    assert_eq!(PROT_MAJOR as i32, id.protocol_major);

    let ack_line = read_test_tcp_line(&mut client, &mut buffer);
    let MetaMessage::Ack(tinc_core::protocol::AckMessage::Payload(public_key)) =
        parse_meta_message(&ack_line).unwrap()
    else {
        panic!("expected invitation ACK response");
    };
    assert_eq!(invitation_public, public_key);

    let mut session = SptpsHandshakeSession::start_tcp(
        true,
        throwaway_key,
        invitation_key.public_key(),
        INVITATION_LABEL,
    )
    .unwrap();
    let mut decoder = MetaStreamDecoder::new();
    decoder.push(&std::mem::take(&mut buffer));

    for record in session.drain_outbound() {
        client.write_all(&record).unwrap();
    }

    let mut received_invitation = Vec::new();
    let mut sent_cookie = false;
    let mut accepted = process_invitation_client_frames(
        &mut session,
        &mut decoder,
        &mut client,
        &cookie,
        &final_key,
        &mut received_invitation,
        &mut sent_cookie,
    );

    for _ in 0..20 {
        if accepted {
            break;
        }

        thread::sleep(StdDuration::from_millis(25));
        runtime.poll_once().unwrap();
        read_test_tcp_available(&mut client, &mut buffer);
        decoder.push(&std::mem::take(&mut buffer));
        accepted = process_invitation_client_frames(
            &mut session,
            &mut decoder,
            &mut client,
            &cookie,
            &final_key,
            &mut received_invitation,
            &mut sent_cookie,
        );
    }

    assert!(
        accepted,
        "invitation did not complete: sent_cookie={sent_cookie} received_invitation_len={} host_exists={} remaining_connections={}",
        received_invitation.len(),
        confbase.join("hosts").join("beta").exists(),
        runtime.meta_connections.len()
    );
    assert_eq!(invitation_data.as_bytes(), received_invitation.as_slice());
    assert!(!invitations_dir.join(&invitation_filename).exists());
    assert!(
        !invitations_dir
            .join(format!("{invitation_filename}.used"))
            .exists()
    );

    let beta_host = fs::read_to_string(confbase.join("hosts").join("beta")).unwrap();
    assert_eq!(
        format!(
            "Ed25519PublicKey = {}\n",
            final_key.public_key().to_base64()
        ),
        beta_host
    );
    assert_eq!(
        Some(final_key.public_key()),
        runtime.keys.peer_public_keys.get("beta").copied()
    );
    assert_eq!(
        Some(final_key.public_key()),
        runtime
            .key_exchange
            .as_ref()
            .unwrap()
            .peer_public_key("beta")
    );
    assert!(runtime.state.graph.node("beta").is_some());

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_expired_invitation_is_renamed_and_left_used_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-invitation-expired");
    let invitations_dir = confbase.join("invitations");
    let invitation_key = test_key(2);
    let cookie = [7u8; INVITATION_COOKIE_LEN];

    fs::create_dir_all(&invitations_dir).unwrap();
    let invitation_public = invitation_key.public_key().to_base64();
    let invitation_filename = invitation_cookie_filename(&cookie, &invitation_public);
    let invitation_path = invitations_dir.join(&invitation_filename);
    fs::write(&invitation_path, "Name = beta\n").unwrap();
    set_file_mtime(&invitation_path, 1);

    let context = RuntimeInvitationContext {
        confbase: confbase.clone(),
        key: invitation_key,
        expire: Duration::from_secs(604800),
    };
    let error = read_runtime_invitation_file(&context, "alpha", &cookie).unwrap_err();
    let used_path = invitations_dir.join(format!("{invitation_filename}.used"));

    assert!(
        format!("{error}").contains("has expired"),
        "unexpected invitation error: {error}"
    );
    assert!(!invitation_path.exists());
    assert!(used_path.exists());
    assert_eq!("Name = beta\n", fs::read_to_string(&used_path).unwrap());

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_legacy_authentication_times_out_at_ping_timeout_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind legacy keepalive test listener: {error}"),
    };
    let _remote_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (daemon_stream, daemon_peer) = listener.accept().unwrap();
    daemon_stream.set_nonblocking(true).unwrap();

    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(alpha_rsa.clone())),
        peer_rsa_public_keys: BTreeMap::from([("beta".to_owned(), RsaPublicKey::from(&beta_rsa))]),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let driver = RuntimeMetaDriver::legacy(LegacyMetaConnectionDriver::new(
        LegacyMetaAuth::new(
            "alpha",
            true,
            LegacyMetaPrivateKey::Pem(alpha_rsa),
            RsaPublicKey::from(&beta_rsa),
            "655",
            0,
            0,
        )
        .with_protocol_minor(LEGACY_META_PROTOCOL_MINOR),
    ));
    runtime.meta_connections.push(RuntimeMetaConnection {
        id: 7,
        stream: daemon_stream,
        peer: daemon_peer,
        local: listener.local_addr().unwrap(),
        bytes_read: 0,
        bytes_written: 0,
        outbound: Vec::new(),
        outbound_offset: 0,
        status: CONNECTION_STATUS_ACTIVE,
        options: 0,
        outgoing_autoconnect: false,
        close_requested: false,
        last_activity: Instant::now() - runtime.ping_timeout,
        last_ping_sent: None,
        exec_proxy: None,
        kind: RuntimeMetaConnectionKind::Active {
            driver,
            name: Some("beta".to_owned()),
            proxy: ProxyHandshake::None,
        },
    });

    runtime.send_meta_keepalives().unwrap();

    assert_eq!(
        0,
        runtime.meta_connection_infos().len(),
        "C tinc closes named legacy connections that are still authenticating at PingTimeout"
    );
}

#[test]
fn runtime_answers_plain_legacy_req_key_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let server = config_tree(&[
        ("Name", "alpha"),
        ("ExperimentalProtocol", "no"),
        ("StrictSubnets", "yes"),
    ]);
    let beta_host = config_tree(&[("Subnet", "10.2.0.0/16")]);
    let config =
        RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta_host)]).unwrap();
    let keys = RuntimeKeys {
        private_key: None,
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &config, keys);
    let beta = alpha.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());

    let (next_hop, response) = alpha
        .handle_legacy_request_key_message(&RequestKeyMessage::new("beta", "alpha"))
        .unwrap()
        .unwrap();
    assert_eq!("beta", next_hop);
    let MetaMessage::AnswerKey(answer) = response else {
        panic!("expected legacy ANS_KEY");
    };

    assert_eq!("alpha", answer.from);
    assert_eq!("beta", answer.to);
    assert_eq!(96, answer.key.len());
    assert_eq!(LegacyCipherAlgorithm::Aes256Cbc.nid(), answer.cipher);
    assert_eq!(LegacyDigest::Sha256 { length: 4 }.nid(), answer.digest);
    assert_eq!(4, answer.mac_length);
    assert_eq!(0, answer.compression);
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key_in);

    let mut beta_codec = LegacyUdpCodec::default();
    beta_codec.insert_peer(
        "alpha",
        LegacyPeerState::from_legacy_answer_key(&answer, alpha.legacy_codec.replay_window_bytes())
            .unwrap(),
    );
    let packet = VpnPacket::new(b"legacy packet after REQ_KEY".to_vec()).unwrap();
    let datagram = beta_codec.encode("alpha", &packet).unwrap();

    assert_eq!(
        packet,
        alpha.legacy_codec.decode("beta", &datagram).unwrap()
    );
}

#[test]
fn runtime_sends_plain_legacy_ans_key_to_source_next_hop_like_tinc() {
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
    alpha.meta_connections.push(beta_connection);
    alpha.state.graph.ensure_node("beta");
    let beta = alpha.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());

    let request = MetaMessage::RequestKey(RequestKeyMessage::new("beta", "alpha"));
    let wire = beta_driver.send_meta_message(&request).unwrap();
    beta_stream.write_all(&wire).unwrap();
    alpha.poll_once().unwrap();

    let mut buffer = [0u8; 1024];
    let len = beta_stream.read(&mut buffer).unwrap();
    let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();

    assert!(step.events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
            if answer.from == "alpha"
                && answer.to == "beta"
                && answer.cipher == LegacyCipherAlgorithm::Aes256Cbc.nid()
                && answer.digest == (LegacyDigest::Sha256 { length: 4 }).nid()
                && answer.mac_length == 4
                && answer.compression == 0
    )));
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key_in);
}

#[test]
fn runtime_legacy_missing_outgoing_key_falls_back_to_tcp_and_requests_key_like_tinc() {
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
    alpha.meta_connections.push(beta_connection);
    let beta = alpha.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let mut events = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + StdDuration::from_secs(1);
    while Instant::now() < deadline {
        match beta_stream.read(&mut buffer) {
            Ok(len) => {
                events.extend(beta_driver.receive_bytes(&buffer[..len]).unwrap().events);
                if events.iter().any(|event| {
                    matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
                }) && events.iter().any(|event| {
                    matches!(
                        event,
                        MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                            if answer.from == "alpha" && answer.to == "beta"
                    )
                }) && events.iter().any(|event| {
                    matches!(
                        event,
                        MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                            if request.from == "alpha" && request.to == "beta" && request.extension.is_none()
                    )
                }) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to read legacy TCP fallback/key messages: {error}"),
        }
    }

    assert!(events.iter().any(|event| {
        matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha" && answer.to == "beta"
        )
    }));
    assert!(events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha" && request.to == "beta" && request.extension.is_none()
        )
    }));
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key_in);
    assert!(alpha.legacy_last_req_key.contains_key("beta"));
    let first_req_key_sent = *alpha
        .legacy_last_req_key
        .get("beta")
        .expect("initial legacy REQ_KEY timestamp");

    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    let len = beta_stream.read(&mut buffer).unwrap();
    let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();

    assert!(step.events.iter().any(|event| {
        matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
    }));
    assert!(!step.events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha" && request.to == "beta"
        )
    }));
    assert!(!step.events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha" && answer.to == "beta"
        )
    }));
    assert_eq!(
        alpha.legacy_last_req_key.get("beta").copied(),
        Some(first_req_key_sent)
    );

    alpha.legacy_last_req_key.insert(
        "beta".to_owned(),
        Instant::now() - LEGACY_REQ_KEY_INTERVAL - StdDuration::from_secs(1),
    );
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let mut repeated_events = Vec::new();
    let deadline = Instant::now() + StdDuration::from_secs(1);
    while Instant::now() < deadline {
        match beta_stream.read(&mut buffer) {
            Ok(len) => {
                repeated_events.extend(beta_driver.receive_bytes(&buffer[..len]).unwrap().events);
                if repeated_events.iter().any(|event| {
                    matches!(
                        event,
                        MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                            if request.from == "alpha" && request.to == "beta"
                    )
                }) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => panic!("failed to read repeated legacy REQ_KEY: {error}"),
        }
    }
    assert!(repeated_events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                if request.from == "alpha" && request.to == "beta"
        )
    }));
}

#[test]
fn runtime_legacy_peer_without_inbound_key_falls_back_to_tcp_and_answers_key_like_tinc() {
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
    alpha.meta_connections.push(beta_connection);
    {
        let beta = alpha.state.graph.node_mut("beta").unwrap();
        beta.status.reachable = true;
        beta.status.sptps = false;
        beta.status.valid_key_in = false;
        beta.route.next_hop = Some("beta".to_owned());
        beta.route.via = Some("beta".to_owned());
        beta.options = (PROT_MINOR as u32) << 24;
        beta.min_mtu = DEFAULT_MTU;
    }

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
    assert!(!alpha.state.graph.node("beta").unwrap().status.valid_key_in);

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 42]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();

    let events = read_meta_events_until(&mut beta_stream, &mut beta_driver, |event| {
        matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
            || matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                    if answer.from == "alpha" && answer.to == "beta"
            )
    });
    assert!(
        events.iter().any(
            |event| matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
        ),
        "when the peer does not have our legacy key yet, data must use meta TCP instead of an immediately dropped UDP packet"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AnswerKey(answer))
                if answer.from == "alpha" && answer.to == "beta" && !answer.is_sptps_handshake()
        )),
        "legacy TCP fallback must also send ANS_KEY so the peer can accept later UDP packets"
    );
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key_in);
    assert!(!alpha.legacy_last_req_key.contains_key("beta"));
}

#[test]
fn runtime_bad_legacy_ans_key_clears_old_outgoing_key_like_tinc() {
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
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        return;
    };
    let mut alpha = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    alpha.meta_connections.push(beta_connection);
    alpha.state.graph.ensure_node("beta");
    let beta = alpha.state.graph.node_mut("beta").unwrap();
    beta.status.reachable = true;
    beta.route.next_hop = Some("beta".to_owned());

    let valid_answer = AnswerKeyMessage {
        from: "beta".to_owned(),
        to: "alpha".to_owned(),
        key: "42".repeat(48),
        cipher: LegacyCipherAlgorithm::Aes256Cbc.nid(),
        digest: LegacyDigest::Sha256 { length: 4 }.nid(),
        mac_length: 4,
        compression: 0,
        address: None,
    };
    alpha
        .apply_legacy_answer_key_message(&valid_answer)
        .unwrap();
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key);
    assert!(
        alpha
            .legacy_codec
            .encode(
                "beta",
                &VpnPacket::new(test_ipv4_ethernet_packet([10, 2, 0, 42])).unwrap(),
            )
            .is_ok()
    );

    let mut bad_answer = valid_answer.clone();
    bad_answer.key = "42".repeat(47);
    let error = alpha.apply_legacy_answer_key_message(&bad_answer);

    assert!(
        matches!(
            error,
            Err(TincdError::LegacyPacket(
                LegacyPacketError::InvalidKeyMaterialLength {
                    expected: 48,
                    actual: 47,
                }
            ))
        ),
        "invalid ANS_KEY should be rejected after clearing old C outcipher/outdigest state"
    );
    assert!(
        !alpha.state.graph.node("beta").unwrap().status.valid_key,
        "C ans_key_h() clears validkey before validating the new legacy key"
    );

    let packet = test_ipv4_ethernet_packet([10, 2, 0, 43]);
    alpha
        .push_device_packet(VpnPacket::new(packet.clone()).unwrap())
        .unwrap();
    alpha.poll_once().unwrap();
    let events = read_meta_events_until(
        &mut beta_stream,
        &mut beta_driver,
        |event| matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet),
    );

    assert!(
        events.iter().any(|event| {
            matches!(event, MetaConnectionEvent::TcpPacket(payload) if payload == &packet)
        }),
        "after a bad ANS_KEY, C send_udppacket() sees validkey=false and falls back to TCP"
    );
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::RequestKey(request))
                    if request.from == "alpha" && request.to == "beta" && request.extension.is_none()
            )
        }),
        "bad ANS_KEY should force a fresh legacy REQ_KEY instead of reusing the old outgoing key"
    );
}

#[test]
fn runtime_bad_legacy_ans_key_from_meta_does_not_fail_daemon_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_legacy_runtime_connection("beta", alpha_rsa.clone(), beta_rsa.clone())
    else {
        return;
    };
    let mut alpha = legacy_ans_key_test_daemon(alpha_rsa, &beta_rsa);
    beta_connection.id = 1;
    alpha.meta_connections.push(beta_connection);

    let valid_answer = legacy_ans_key_test_message();
    alpha
        .apply_legacy_answer_key_message(&valid_answer)
        .unwrap();
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key);

    let mut bad_answer = valid_answer;
    bad_answer.key = "42".repeat(47);
    alpha
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::AnswerKey(
                    bad_answer,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(1, alpha.meta_connections.len());
    assert!(!alpha.meta_connections[0].close_requested);
    assert!(
        !alpha.state.graph.node("beta").unwrap().status.valid_key,
        "C ans_key_h() clears validkey before treating wrong keylength as handled"
    );
}

#[test]
fn runtime_lzo_legacy_ans_key_from_meta_matches_tinc_build_feature_semantics() {
    tinc_test_support::assert_can_create_netns();
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_legacy_runtime_connection("beta", alpha_rsa.clone(), beta_rsa.clone())
    else {
        return;
    };
    let mut alpha = legacy_ans_key_test_daemon(alpha_rsa, &beta_rsa);
    beta_connection.id = 1;
    alpha.meta_connections.push(beta_connection);

    let valid_answer = legacy_ans_key_test_message();
    alpha
        .apply_legacy_answer_key_message(&valid_answer)
        .unwrap();
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key);

    let mut lzo_answer = valid_answer;
    lzo_answer.compression = CompressionLevel::LzoLow as i32;
    alpha
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::AnswerKey(
                    lzo_answer,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(1, alpha.meta_connections.len());
    assert!(!alpha.meta_connections[0].close_requested);
    if legacy_compression_is_available(CompressionLevel::LzoLow) {
        assert!(
            alpha.state.graph.node("beta").unwrap().status.valid_key,
            "C ans_key_h() accepts LZO ANS_KEY when built with HAVE_LZO"
        );
    } else {
        assert!(
            !alpha.state.graph.node("beta").unwrap().status.valid_key,
            "C ans_key_h() clears validkey before treating unavailable LZO compression as handled"
        );
    }
}

#[test]
fn runtime_unknown_compression_legacy_ans_key_from_meta_does_not_fail_daemon_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_legacy_runtime_connection("beta", alpha_rsa.clone(), beta_rsa.clone())
    else {
        return;
    };
    let mut alpha = legacy_ans_key_test_daemon(alpha_rsa, &beta_rsa);
    beta_connection.id = 1;
    alpha.meta_connections.push(beta_connection);

    let valid_answer = legacy_ans_key_test_message();
    alpha
        .apply_legacy_answer_key_message(&valid_answer)
        .unwrap();
    assert!(alpha.state.graph.node("beta").unwrap().status.valid_key);

    let mut unknown_compression_answer = valid_answer;
    unknown_compression_answer.compression = 13;
    alpha
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                events: vec![MetaConnectionEvent::Message(MetaMessage::AnswerKey(
                    unknown_compression_answer,
                ))],
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(1, alpha.meta_connections.len());
    assert!(!alpha.meta_connections[0].close_requested);
    assert!(
        !alpha.state.graph.node("beta").unwrap().status.valid_key,
        "C ans_key_h() clears validkey before treating unrecognized compression as handled"
    );
}

#[test]
fn runtime_unsupported_legacy_ans_key_from_meta_closes_connection_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    assert_legacy_ans_key_meta_connection_closes_like_tinc(
        "unknown cipher",
        |answer| {
            answer.cipher = 999_999;
        },
        "C ans_key_h() returns false for unknown cipher, terminating only the bad meta connection",
    );
}

#[test]
fn runtime_unknown_legacy_ans_key_digest_from_meta_closes_connection_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    assert_legacy_ans_key_meta_connection_closes_like_tinc(
        "unknown digest",
        |answer| {
            answer.digest = 999_999;
        },
        "C ans_key_h() returns false for unknown digest, terminating only the bad meta connection",
    );
}

#[test]
fn runtime_bogus_legacy_ans_key_mac_length_from_meta_closes_connection_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    assert_legacy_ans_key_meta_connection_closes_like_tinc(
        "bogus MAC length",
        |answer| {
            answer.mac_length = 99;
        },
        "C ans_key_h() returns false for bogus MAC length, terminating only the bad meta connection",
    );
}

#[test]
fn runtime_forwards_legacy_ans_key_with_reflexive_address_like_tinc() {
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
    beta.udp_address = Some(EdgeEndpoint::new("203.0.113.5", "655"));
    runtime.state.graph.ensure_node("gamma");
    let gamma = runtime.state.graph.node_mut("gamma").unwrap();
    gamma.status.reachable = true;
    gamma.route.next_hop = Some("gamma".to_owned());
    gamma.min_mtu = 1400;

    let answer = AnswerKeyMessage {
        from: "beta".to_owned(),
        to: "gamma".to_owned(),
        key: "00".to_owned(),
        cipher: 0,
        digest: 0,
        mac_length: 0,
        compression: 0,
        address: None,
    };
    runtime.forward_answer_key_message(&answer).unwrap();

    let mut buffer = [0u8; 512];
    let len = gamma_stream.read(&mut buffer).unwrap();
    let step = gamma_driver.receive_bytes(&buffer[..len]).unwrap();

    assert!(step.events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::AnswerKey(message))
            if message.from == "beta"
                && message.to == "gamma"
                && message.address.as_ref().is_some_and(|endpoint|
                    endpoint.address == "203.0.113.5" && endpoint.port == "655")
    )));
}

#[test]
fn runtime_replies_to_meta_ping_with_pong() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-ping-pong");
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
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind ping test listener: {error}"),
    };
    let mut remote_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (daemon_stream, peer) = listener.accept().unwrap();
    daemon_stream.set_nonblocking(true).unwrap();
    remote_stream
        .set_read_timeout(Some(StdDuration::from_secs(1)))
        .unwrap();
    let local = daemon_stream.local_addr().unwrap();
    let (alpha_driver, mut beta_driver) =
        established_meta_driver_pair(alpha_key.clone(), beta_key.clone());
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    runtime.meta_connections.push(RuntimeMetaConnection {
        id: 1,
        stream: daemon_stream,
        peer,
        local,
        bytes_read: 0,
        bytes_written: 0,
        outbound: Vec::new(),
        outbound_offset: 0,
        status: CONNECTION_STATUS_ACTIVE,
        options: (PROT_MINOR as u32) << 24,
        outgoing_autoconnect: false,
        close_requested: false,
        last_activity: Instant::now(),
        last_ping_sent: None,
        exec_proxy: None,
        kind: RuntimeMetaConnectionKind::Active {
            driver: RuntimeMetaDriver::modern(alpha_driver),
            name: Some("beta".to_owned()),
            proxy: ProxyHandshake::None,
        },
    });

    let ping = beta_driver.send_meta_message(&MetaMessage::Ping).unwrap();
    remote_stream.write_all(&ping).unwrap();
    runtime.poll_once().unwrap();

    let mut buffer = [0u8; 512];
    let len = remote_stream.read(&mut buffer).unwrap();
    let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();

    assert!(
        step.events
            .contains(&MetaConnectionEvent::Message(MetaMessage::Pong))
    );
    assert!(runtime.meta_connection_infos()[0].bytes_read > 0);
    assert!(runtime.meta_connection_infos()[0].bytes_written > 0);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_routes_plain_tcp_packet_from_meta_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("Subnet", "10.0.0.0/8"),
    ]))
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

    let packet = test_ipv4_ethernet_packet([10, 0, 0, 42]);
    let tcp_packet = flatten_outbound(beta_driver.send_tcp_packet(&packet).unwrap());
    beta_stream.write_all(&tcp_packet).unwrap();
    runtime.poll_once().unwrap();

    assert_eq!(1, runtime.device_writes().len());
    assert_eq!(packet, runtime.device_writes()[0].data);
    assert_eq!(-1, runtime.device_writes()[0].priority);
}

#[test]
fn runtime_random_early_drops_tcp_packets_when_meta_outbuf_is_large_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let Some((_beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        return;
    };

    beta_connection.outbound = vec![0x55; 8];
    beta_connection.outbound_offset = 0;
    let before = beta_connection.outbound.clone();

    send_plain_tcp_packet_on_connection(&mut beta_connection, b"abcd", 8).unwrap();

    assert_eq!(before, beta_connection.outbound);
    assert_eq!(0, beta_connection.bytes_written);
}

#[test]
#[cfg(unix)]
fn runtime_marks_meta_connection_closed_on_tcp_fallback_write_error_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let Some((beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        return;
    };
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            beta_stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of_val(&linger) as libc::socklen_t,
        )
    };
    assert_eq!(
        0,
        result,
        "failed to configure reset-on-close: {}",
        io::Error::last_os_error()
    );
    drop(beta_stream);

    let mut marked = false;
    for _ in 0..20 {
        match send_sptps_tcp_packet_on_connection(
            &mut beta_connection,
            b"packet over stale meta connection",
            usize::MAX,
        ) {
            Ok(()) => {}
            Err(error) => {
                marked = mark_meta_connection_closed_on_scoped_error_like_tinc(
                    &mut beta_connection,
                    error,
                )
                .unwrap();
                break;
            }
        }
        thread::sleep(StdDuration::from_millis(10));
    }

    assert!(
        marked || beta_connection.close_requested,
        "C handle_meta_write() closes stale meta connections on write errors instead of making data-plane TCP fallback fatal"
    );
}

#[test]
#[cfg(unix)]
fn runtime_closes_meta_connection_on_write_error_like_tinc() {
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
    let Some((beta_stream, _beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        return;
    };
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            beta_stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of_val(&linger) as libc::socklen_t,
        )
    };
    assert_eq!(
        0,
        result,
        "failed to configure reset-on-close: {}",
        io::Error::last_os_error()
    );
    drop(beta_stream);

    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    beta_connection
        .outbound
        .extend_from_slice(b"pending metadata");
    runtime.meta_connections.push(beta_connection);

    let deadline = Instant::now() + StdDuration::from_secs(1);
    while !runtime.meta_connections.is_empty() && Instant::now() < deadline {
        runtime.flush_meta_outputs().unwrap();
        if let Some(connection) = runtime.meta_connections.get_mut(0) {
            connection.outbound.extend_from_slice(b"pending metadata");
        }
        thread::sleep(StdDuration::from_millis(10));
    }

    assert!(runtime.meta_connection_infos().is_empty());
}

#[test]
fn runtime_closes_meta_connection_on_terminate_request() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-termreq");
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
    let mut config = load_runtime_config(&options).unwrap();
    config.state.graph.ensure_node("gamma");
    config
        .state
        .graph
        .add_edge(
            tinc_core::graph::Edge::new("alpha", "gamma", 7)
                .with_address(EdgeEndpoint::new("198.51.100.9", "655"))
                .with_local_address(EdgeEndpoint::new("10.0.0.1", "655")),
        )
        .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind termreq test listener: {error}"),
    };
    let mut remote_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (daemon_stream, peer) = listener.accept().unwrap();
    daemon_stream.set_nonblocking(true).unwrap();
    let local = daemon_stream.local_addr().unwrap();
    let (alpha_driver, mut beta_driver) =
        established_meta_driver_pair(alpha_key.clone(), beta_key.clone());
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    runtime.meta_connections.push(RuntimeMetaConnection {
        id: 1,
        stream: daemon_stream,
        peer,
        local,
        bytes_read: 0,
        bytes_written: 0,
        outbound: Vec::new(),
        outbound_offset: 0,
        status: CONNECTION_STATUS_ACTIVE,
        options: (PROT_MINOR as u32) << 24,
        outgoing_autoconnect: false,
        close_requested: false,
        last_activity: Instant::now(),
        last_ping_sent: None,
        exec_proxy: None,
        kind: RuntimeMetaConnectionKind::Active {
            driver: RuntimeMetaDriver::modern(alpha_driver),
            name: Some("beta".to_owned()),
            proxy: ProxyHandshake::None,
        },
    });

    let termreq = beta_driver
        .send_meta_message(&MetaMessage::TerminateRequest)
        .unwrap();
    remote_stream.write_all(&termreq).unwrap();
    runtime.poll_once().unwrap();

    assert!(runtime.meta_connection_infos().is_empty());

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_applies_meta_state_messages_to_control_dumps() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-state-message");
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
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            fs::remove_dir_all(confbase).unwrap();
            return;
        }
        Err(error) => panic!("failed to bind state message test listener: {error}"),
    };
    let mut remote_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (daemon_stream, peer) = listener.accept().unwrap();
    daemon_stream.set_nonblocking(true).unwrap();
    let local = daemon_stream.local_addr().unwrap();
    let (alpha_driver, mut beta_driver) =
        established_meta_driver_pair(alpha_key.clone(), beta_key.clone());
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    runtime.meta_connections.push(RuntimeMetaConnection {
        id: 1,
        stream: daemon_stream,
        peer,
        local,
        bytes_read: 0,
        bytes_written: 0,
        outbound: Vec::new(),
        outbound_offset: 0,
        status: CONNECTION_STATUS_ACTIVE,
        options: (PROT_MINOR as u32) << 24,
        outgoing_autoconnect: false,
        close_requested: false,
        last_activity: Instant::now(),
        last_ping_sent: None,
        exec_proxy: None,
        kind: RuntimeMetaConnectionKind::Active {
            driver: RuntimeMetaDriver::modern(alpha_driver),
            name: Some("beta".to_owned()),
            proxy: ProxyHandshake::None,
        },
    });

    let add_subnet = beta_driver
        .send_meta_message(&parse_meta_message("10 123 beta 10.2.0.0/16").unwrap())
        .unwrap();
    remote_stream.write_all(&add_subnet).unwrap();
    runtime.poll_once().unwrap();

    let mut stop = false;
    let subnets =
        handle_control_request_line("18 5", &mut stop, Some(&config), Some(&mut runtime)).unwrap();

    assert!(subnets.contains("18 5 10.2.0.0/16 beta\n"));
    assert!(
        runtime
            .state()
            .subnets
            .owner_subnets("beta")
            .next()
            .is_some()
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_broadcasts_meta_state_messages_to_other_peers() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-state-broadcast");
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
        peer_public_keys: BTreeMap::from([
            ("beta".to_owned(), beta_key.public_key()),
            ("gamma".to_owned(), gamma_key.public_key()),
        ]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", alpha_key.clone(), beta_key.clone())
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let Some((mut gamma_stream, mut gamma_driver, mut gamma_connection)) =
        active_runtime_connection("gamma", alpha_key.clone(), gamma_key.clone())
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    beta_connection.id = 1;
    gamma_connection.id = 2;
    runtime.meta_connections.push(beta_connection);
    runtime.meta_connections.push(gamma_connection);

    let message = parse_meta_message("10 123 beta 10.2.0.0/16").unwrap();
    let add_subnet = beta_driver.send_meta_message(&message).unwrap();
    beta_stream.write_all(&add_subnet).unwrap();
    runtime.poll_once().unwrap();

    let mut buffer = [0u8; 512];
    let len = gamma_stream.read(&mut buffer).unwrap();
    let step = gamma_driver.receive_bytes(&buffer[..len]).unwrap();

    assert!(
        step.events
            .contains(&MetaConnectionEvent::Message(message.clone()))
    );
    assert!(
        runtime
            .state()
            .subnets
            .owner_subnets("beta")
            .next()
            .is_some()
    );
    assert!(runtime.meta_connection_infos()[1].bytes_written > 0);

    let duplicate = beta_driver.send_meta_message(&message).unwrap();
    beta_stream.write_all(&duplicate).unwrap();
    runtime.poll_once().unwrap();

    let mut extra = Vec::new();
    assert_eq!(0, read_test_tcp_available(&mut gamma_stream, &mut extra));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_syncs_existing_subnets_when_meta_connection_activates() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-activation-sync");
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
    let mut config = load_runtime_config(&options).unwrap();
    config.state.graph.ensure_node("gamma");
    config
        .state
        .graph
        .upsert_edge(
            tinc_core::graph::Edge::new("alpha", "gamma", 7)
                .with_address(EdgeEndpoint::new("198.51.100.9", "655"))
                .with_local_address(EdgeEndpoint::new("10.0.0.1", "655")),
        )
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
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 1;
    runtime.meta_connections.push(beta_connection);

    runtime
        .apply_meta_step(
            0,
            tinc_runtime::meta::MetaConnectionStep {
                outbound: Vec::new(),
                events: vec![MetaConnectionEvent::Auth(MetaAuthEvent::Activated {
                    peer: "beta".to_owned(),
                    port: "655".to_owned(),
                    weight: 0,
                    options: (PROT_MINOR as u32) << 24,
                })],
            },
        )
        .unwrap();

    let mut events = Vec::new();
    let mut buffer = [0u8; 512];
    let deadline = Instant::now() + Duration::from_secs(1);

    while Instant::now() < deadline {
        let len = match beta_stream.read(&mut buffer) {
            Ok(len) => len,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) => panic!("failed to read activation sync bytes: {error}"),
        };
        let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();
        events.extend(step.events);

        if events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddSubnet(message))
                    if message.owner == "alpha" && message.subnet.to_string() == "10.0.0.0/8"
            )
        }) && events.iter().any(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                    if message.edge.from == "alpha"
                        && message.edge.to == "gamma"
                        && message.address == "198.51.100.9"
                        && message.port == "655"
            )
        }) && events
            .iter()
            .any(|event| is_sptps_initial_req_key(event, "alpha", "beta"))
        {
            break;
        }
    }

    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::AddSubnet(message))
            if message.owner == "alpha" && message.subnet.to_string() == "10.0.0.0/8"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
            if message.edge.from == "alpha"
                && message.edge.to == "gamma"
                && message.address == "198.51.100.9"
                && message.port == "655"
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
            if message.edge.from == "beta" && message.edge.to == "alpha"
    )));
    let subnet_pos = events
        .iter()
        .position(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddSubnet(message))
                    if message.owner == "alpha" && message.subnet.to_string() == "10.0.0.0/8"
            )
        })
        .unwrap();
    let edge_pos = events
        .iter()
        .position(|event| {
            matches!(
                event,
                MetaConnectionEvent::Message(MetaMessage::AddEdge(message))
                    if message.edge.from == "alpha"
                        && message.edge.to == "gamma"
                        && message.address == "198.51.100.9"
                        && message.port == "655"
            )
        })
        .unwrap();
    let req_pos = events
        .iter()
        .position(|event| is_sptps_initial_req_key(event, "alpha", "beta"))
        .unwrap();
    assert!(subnet_pos < req_pos);
    assert!(edge_pos < req_pos);

    fs::remove_dir_all(confbase).unwrap();
}
