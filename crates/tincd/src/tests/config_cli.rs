use super::*;

#[test]
fn runtime_local_options_follow_tinc_tcp_only_and_pmtu_rules() {
    tinc_test_support::assert_can_create_netns();
    let defaults = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    assert_eq!(
        ((PROT_MINOR as u32) << 24) | OPTION_PMTU_DISCOVERY | OPTION_CLAMP_MSS,
        runtime_local_options(&defaults)
    );

    let tcp_only =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("TCPOnly", "yes")]))
            .unwrap();
    assert_eq!(
        ((PROT_MINOR as u32) << 24) | OPTION_TCPONLY | OPTION_INDIRECT | OPTION_CLAMP_MSS,
        runtime_local_options(&tcp_only)
    );

    let indirect = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("IndirectData", "yes"),
        ("ClampMSS", "no"),
    ]))
    .unwrap();
    assert_eq!(
        ((PROT_MINOR as u32) << 24) | OPTION_INDIRECT | OPTION_PMTU_DISCOVERY,
        runtime_local_options(&indirect)
    );

    let no_experimental = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("ExperimentalProtocol", "no"),
    ]))
    .unwrap();
    assert_eq!(
        OPTION_PMTU_DISCOVERY | OPTION_CLAMP_MSS,
        runtime_local_options(&no_experimental)
    );
}

#[test]
fn runtime_sptps_packet_type_matches_tinc_routing_mode() {
    tinc_test_support::assert_can_create_netns();
    let router =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Mode", "router")]))
            .unwrap();
    assert_eq!(
        SPTPS_UDP_ROUTER_PACKET_TYPE,
        runtime_sptps_packet_type(&router)
    );

    let switch =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Mode", "switch")]))
            .unwrap();
    assert_eq!(SPTPS_PACKET_TYPE_MAC, runtime_sptps_packet_type(&switch));
}

#[test]
fn effective_debug_level_uses_loglevel_only_when_cli_level_is_zero_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "4")]))
            .unwrap();
    let mut options = TincdOptions::new("tincd".to_owned());

    assert_eq!(4, effective_debug_level(&config, &options));

    options.debug_level = Some(None);
    assert_eq!(1, effective_debug_level(&config, &options));

    options.debug_level = Some(Some(0));
    assert_eq!(4, effective_debug_level(&config, &options));

    options.debug_level = Some(Some(5));
    assert_eq!(5, effective_debug_level(&config, &options));
}

#[test]
fn runtime_replay_window_configures_legacy_and_sptps_windows_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let default_config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let default_keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let default_runtime = RuntimeDaemonState::new(Vec::new(), &default_config, default_keys);

    assert_eq!(
        DEFAULT_SPTPS_REPLAY_WINDOW_BYTES,
        default_runtime
            .key_exchange
            .as_ref()
            .unwrap()
            .replay_window_bytes()
    );
    assert_eq!(
        DEFAULT_REPLAY_WINDOW_BYTES,
        default_runtime.legacy_codec.replay_window_bytes()
    );

    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("ReplayWindow", "7")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(2)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert_eq!(
        7,
        runtime.key_exchange.as_ref().unwrap().replay_window_bytes()
    );
    assert_eq!(7, runtime.legacy_codec.replay_window_bytes());
}

#[test]
fn runtime_local_port_matches_tinc_myport_setup_rules() {
    tinc_test_support::assert_can_create_netns();
    let service_config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Port", "http")]))
            .unwrap();
    let service_runtime = RuntimeDaemonState::new(
        Vec::new(),
        &service_config,
        RuntimeKeys {
            private_key: Some(test_key(1)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    assert_eq!("80", service_runtime.local_port);

    let default_config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind dynamic local port socket: {error}"),
    };
    let bound_port = socket.info().address.port().to_string();
    let default_runtime = RuntimeDaemonState::new(
        vec![socket],
        &default_config,
        RuntimeKeys {
            private_key: Some(test_key(2)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    assert_eq!(bound_port, default_runtime.local_port);
    assert!(
        dump_nodes(
            &default_config,
            default_runtime.state(),
            Some(&default_runtime)
        )
        .contains(&format!(" MYSELF port {bound_port} "))
    );

    let zero_config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Port", "0")])).unwrap();
    let socket = match test_runtime_listen_socket() {
        Ok(socket) => socket,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to bind zero local port socket: {error}"),
    };
    let bound_port = socket.info().address.port().to_string();
    let zero_runtime = RuntimeDaemonState::new(
        vec![socket],
        &zero_config,
        RuntimeKeys {
            private_key: Some(test_key(3)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    assert_eq!(bound_port, zero_runtime.local_port);
}

#[test]
fn runtime_reload_keeps_existing_local_port_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let initial_config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Port", "12345")]))
            .unwrap();
    let reloaded_config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Port", "54321")]))
            .unwrap();
    let mut runtime = RuntimeDaemonState::new(
        Vec::new(),
        &initial_config,
        RuntimeKeys {
            private_key: Some(test_key(4)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );

    runtime
        .apply_reloaded_config(
            &reloaded_config,
            RuntimeKeys {
                private_key: Some(test_key(5)),
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        )
        .unwrap();

    assert_eq!("12345", runtime.local_port);
}

#[test]
fn runtime_udp_discovery_options_reload_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let initial_config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("LocalDiscovery", "no"),
        ("UDPDiscovery", "no"),
        ("UDPDiscoveryKeepaliveInterval", "19"),
        ("UDPDiscoveryInterval", "23"),
        ("UDPDiscoveryTimeout", "29"),
    ]))
    .unwrap();
    let reloaded_config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("LocalDiscovery", "yes"),
        ("UDPDiscovery", "yes"),
        ("UDPDiscoveryKeepaliveInterval", "31"),
        ("UDPDiscoveryInterval", "37"),
        ("UDPDiscoveryTimeout", "41"),
    ]))
    .unwrap();

    let mut runtime = RuntimeDaemonState::new(
        Vec::new(),
        &initial_config,
        RuntimeKeys {
            private_key: Some(test_key(1)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );

    assert!(!runtime.local_discovery);
    assert!(!runtime.udp_discovery);
    assert_eq!(
        StdDuration::from_secs(19),
        runtime.udp_discovery_keepalive_interval
    );
    assert_eq!(StdDuration::from_secs(23), runtime.udp_discovery_interval);
    assert_eq!(StdDuration::from_secs(29), runtime.udp_discovery_timeout);

    runtime
        .apply_reloaded_config(
            &reloaded_config,
            RuntimeKeys {
                private_key: Some(test_key(2)),
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        )
        .unwrap();

    assert!(runtime.local_discovery);
    assert!(runtime.udp_discovery);
    assert_eq!(
        StdDuration::from_secs(31),
        runtime.udp_discovery_keepalive_interval
    );
    assert_eq!(StdDuration::from_secs(37), runtime.udp_discovery_interval);
    assert_eq!(StdDuration::from_secs(41), runtime.udp_discovery_timeout);
}

#[test]
fn runtime_outgoing_retry_backoff_uses_max_timeout_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let probe = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("failed to reserve retry address: {error}"),
    };
    let remote_addr = probe.local_addr().unwrap();
    drop(probe);

    let server = config_tree(&[
        ("Name", "alpha"),
        ("ConnectTo", "beta"),
        ("MaxTimeout", "8"),
    ]);
    let beta = config_tree(&[(
        "Address",
        &format!("{} {}", remote_addr.ip(), remote_addr.port()),
    )]);
    let config = RuntimeConfig::from_config_tree_with_hosts(&server, [("beta", &beta)]).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    assert_eq!(1, runtime.retry_configured_peers(&config).unwrap());
    assert_eq!(1, runtime.meta_connection_infos().len());
    drive_until_no_meta_connections(&mut runtime);
    let retry = runtime.outgoing_retry.get("beta").unwrap();
    assert_eq!(5, retry.timeout_secs);
    let now = Instant::now();
    let retry_delay = retry.next_attempt.saturating_duration_since(now);
    assert!(retry.next_attempt > now);
    assert!(
        retry_delay
            < StdDuration::from_secs(5) + StdDuration::from_micros(TINC_TIMER_JITTER_US as u64),
        "C retry_outgoing() schedules timeout seconds plus jitter() microseconds"
    );

    runtime.outgoing_retry.get_mut("beta").unwrap().next_attempt =
        Instant::now() - StdDuration::from_secs(1);
    assert_eq!(1, runtime.retry_configured_peers(&config).unwrap());
    assert_eq!(1, runtime.meta_connection_infos().len());
    drive_until_no_meta_connections(&mut runtime);
    assert_eq!(8, runtime.outgoing_retry.get("beta").unwrap().timeout_secs);

    runtime.outgoing_retry.get_mut("beta").unwrap().next_attempt =
        Instant::now() - StdDuration::from_secs(1);
    assert_eq!(1, runtime.retry_configured_peers(&config).unwrap());
    assert_eq!(1, runtime.meta_connection_infos().len());
    drive_until_no_meta_connections(&mut runtime);
    assert_eq!(8, runtime.outgoing_retry.get("beta").unwrap().timeout_secs);

    let remote_listener = match TcpListener::bind(remote_addr) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => return,
        Err(error) => panic!("failed to bind retry listener: {error}"),
    };
    assert_eq!(0, runtime.retry_configured_peers(&config).unwrap());
    assert!(runtime.meta_connection_infos().is_empty());

    assert_eq!(1, runtime.retry_configured_peers_now(&config).unwrap());
    let (remote_stream, _) = accept_after_runtime_progress(&remote_listener, &mut runtime);
    drive_outgoing_meta_output(&mut runtime);
    let mut reader = BufReader::new(remote_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!("0 alpha 17.7\n", line);
    assert_eq!(0, runtime.outgoing_retry.get("beta").unwrap().timeout_secs);
}

#[test]
fn experimental_protocol_no_forces_legacy_rsa_meta_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("ExperimentalProtocol", "no"),
    ]))
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: Some(RuntimeRsaPrivateKey::Pem(alpha_rsa)),
        peer_rsa_public_keys: BTreeMap::from([("beta".to_owned(), RsaPublicKey::from(&beta_rsa))]),
    };
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    let outgoing = runtime.meta_driver_for_peer("beta", true).unwrap().unwrap();
    assert!(matches!(outgoing, RuntimeMetaDriver::Legacy(_)));
    assert_eq!(
        "0 alpha 17.0\n",
        String::from_utf8(outgoing.initial_id_bytes()).unwrap()
    );

    let mut incoming = runtime
        .meta_driver_for_incoming_peer("beta", Some(PROT_MINOR as i32))
        .unwrap()
        .unwrap();
    assert!(matches!(incoming, RuntimeMetaDriver::Legacy(_)));
    let step = incoming
        .receive_bytes(format!("0 beta 17.{PROT_MINOR}\n").as_bytes())
        .unwrap();
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
fn parses_core_tincd_options_and_command_line_config() {
    tinc_test_support::assert_can_create_netns();
    let command = parse_args(args(&[
        "tincd",
        "-c",
        "/tmp/vpn",
        "--net=prod",
        "-D",
        "-L",
        "--syslog",
        "--pidfile=/tmp/tinc.pid",
        "--bypass-security",
        "--chroot",
        "--user",
        "nobody",
        "-o",
        "Name=alpha",
        "--option=alpha.Subnet=10.0.0.0/8",
    ]))
    .unwrap();

    let ParsedCommand::Run(options) = command else {
        panic!("expected run command");
    };

    assert_eq!(Some(PathBuf::from("/tmp/vpn")), options.confbase);
    assert_eq!(Some("prod".to_owned()), options.netname);
    assert!(options.no_detach);
    assert!(options.lock_memory);
    assert!(options.use_syslog);
    assert_eq!(None, options.logfile);
    assert_eq!(Some(PathBuf::from("/tmp/tinc.pid")), options.pidfile);
    assert!(options.bypass_security);
    assert!(options.chroot);
    assert_eq!(Some("nobody".to_owned()), options.user);
    assert_eq!(2, options.command_line_options.len());
    assert_eq!("Name", options.command_line_options[0].variable);
    assert_eq!("alpha.Subnet", options.command_line_options[1].variable);
}

#[test]
fn parses_help_version_and_rejects_invalid_options() {
    tinc_test_support::assert_can_create_netns();
    assert!(matches!(
        parse_args(args(&["tincd", "--help"])),
        Ok(ParsedCommand::Help(_))
    ));
    assert_eq!(
        Ok(ParsedCommand::Version),
        parse_args(args(&["tincd", "--version"]))
    );
    assert_eq!(
        Err(TincdError::UnknownOption("--bad".to_owned())),
        parse_args(args(&["tincd", "--bad"]))
    );
    assert_eq!(
        Err(TincdError::MissingArgument {
            option: "-c".to_owned()
        }),
        parse_args(args(&["tincd", "-c"]))
    );
}

#[test]
fn normalizes_and_validates_netname_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let ParsedCommand::Run(options) = parse_args(args(&["tincd", "-n", "."])).unwrap() else {
        panic!("expected run command");
    };
    assert_eq!(None, options.netname);
    assert_eq!(
        Err(TincdError::InvalidNetname("bad/name".to_owned())),
        parse_args(args(&["tincd", "-n", "bad/name"]))
    );
}

#[test]
fn optional_arguments_do_not_consume_following_options() {
    tinc_test_support::assert_can_create_netns();
    let ParsedCommand::Run(options) =
        parse_args(args(&["tincd", "--logfile", "--net", "prod", "-d", "-D"])).unwrap()
    else {
        panic!("expected run command");
    };

    assert_eq!(Some(None), options.logfile);
    assert_eq!(Some("prod".to_owned()), options.netname);
    assert_eq!(Some(None), options.debug_level);
    assert!(options.no_detach);

    let ParsedCommand::Run(options) =
        parse_args(args(&["tincd", "-d", "-d", "--debug=5", "-d"])).unwrap()
    else {
        panic!("expected run command");
    };

    assert_eq!(Some(Some(6)), options.debug_level);

    let ParsedCommand::Run(options) =
        parse_args(args(&["tincd", "--logfile", "tinc.log", "-d", "5"])).unwrap()
    else {
        panic!("expected run command");
    };

    assert_eq!(Some(Some(PathBuf::from("tinc.log"))), options.logfile);
    assert_eq!(Some(Some(5)), options.debug_level);
}

#[test]
fn syslog_and_logfile_options_override_each_other_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let ParsedCommand::Run(options) =
        parse_args(args(&["tincd", "--logfile=/tmp/tinc.log", "--syslog"])).unwrap()
    else {
        panic!("expected run command");
    };
    assert!(options.use_syslog);
    assert_eq!(None, options.logfile);

    let ParsedCommand::Run(options) =
        parse_args(args(&["tincd", "--syslog", "--logfile=/tmp/tinc.log"])).unwrap()
    else {
        panic!("expected run command");
    };
    assert!(!options.use_syslog);
    assert_eq!(Some(Some(PathBuf::from("/tmp/tinc.log"))), options.logfile);
}

#[test]
fn systemd_activation_env_parses_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    assert!(systemd_listen_pid_matches_current_process(
        Some("1234"),
        1234
    ));
    assert!(!systemd_listen_pid_matches_current_process(
        Some("1234"),
        5678
    ));
    assert!(!systemd_listen_pid_matches_current_process(
        Some("bad"),
        1234
    ));
    assert_eq!(Some(2), parse_systemd_listen_fds(Some("2")));
    assert_eq!(None, parse_systemd_listen_fds(Some("bad")));
    assert_eq!(
        Some(Duration::from_micros(2_000_000)),
        parse_systemd_watchdog_usec(Some("2000000"))
    );
    assert_eq!(None, parse_systemd_watchdog_usec(Some("0")));
    assert!(systemd_watchdog_pid_matches_current_process(
        Some("0"),
        1234
    ));
    assert!(systemd_watchdog_pid_matches_current_process(
        Some("1234"),
        1234
    ));
    assert!(!systemd_watchdog_pid_matches_current_process(
        Some("5678"),
        1234
    ));
}

#[cfg(unix)]
#[test]
fn runtime_watchdog_interval_matches_tinc_half_timeout() {
    tinc_test_support::assert_can_create_netns();
    let now = Instant::now();
    let watchdog = RuntimeWatchdog::from_timeout(Some(Duration::from_micros(2_000_000)), now);
    assert_eq!(Duration::from_micros(1_000_000), watchdog.interval);
    assert_eq!(now + Duration::from_micros(1_000_000), watchdog.next_ping);

    let disabled = RuntimeWatchdog::from_timeout(None, now);
    assert_eq!(Duration::ZERO, disabled.interval);
    assert_eq!(now, disabled.next_ping);
}

#[cfg(unix)]
#[test]
fn runtime_watchdog_logs_start_state_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys.clone());
    runtime.set_debug_level(0);
    RuntimeWatchdog::from_timeout(None, Instant::now()).start(&mut runtime);
    assert!(
        runtime
            .test_log_entries(0, false)
            .iter()
            .any(|entry| entry.contains("Watchdog is disabled"))
    );

    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.set_debug_level(0);
    RuntimeWatchdog::from_timeout(Some(Duration::from_millis(1500)), Instant::now())
        .start(&mut runtime);
    let entries = runtime.test_log_entries(0, false);
    assert!(
        entries
            .iter()
            .any(|entry| entry.contains("Consider using a higher watchdog timeout"))
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.contains("Watchdog started"))
    );
}

#[test]
fn help_and_version_include_tincd_compatibility_surface() {
    tinc_test_support::assert_can_create_netns();
    let help = match run(args(&["tincd", "--help"])).unwrap() {
        CliAction::Exit { output, .. } => output,
        _ => panic!("expected help exit"),
    };

    assert!(help.contains("-L, --mlock"));
    assert!(help.contains("--logfile[=FILENAME]"));
    assert!(help.contains("--pidfile=FILENAME"));
    assert!(help.contains("--bypass-security"));
    assert!(help.contains("-R, --chroot"));
    assert!(help.contains("-U, --user=USER"));
    assert!(help.contains("Report bugs to tinc@tinc-vpn.org."));

    let version = match run(args(&["tincd", "--version"])).unwrap() {
        CliAction::Exit { output, .. } => output,
        _ => panic!("expected version exit"),
    };

    assert!(version.contains("tincd version"));
    assert!(version.contains("protocol 17.7"));
    assert!(version.contains("ABSOLUTELY NO WARRANTY"));
}

#[test]
fn resolves_default_and_netname_config_directories() {
    tinc_test_support::assert_can_create_netns();
    let mut options = TincdOptions::new("tincd".to_owned());
    assert_eq!(PathBuf::from(DEFAULT_CONFDIR), resolve_confbase(&options));

    options.netname = Some("prod".to_owned());
    assert_eq!(
        Path::new(DEFAULT_CONFDIR).join("prod"),
        resolve_confbase(&options)
    );

    options.confbase = Some(PathBuf::from("/tmp/tinc"));
    assert_eq!(PathBuf::from("/tmp/tinc"), resolve_confbase(&options));
}

#[test]
fn resolves_logfile_path_like_tinc_fallback() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("resolve-logfile");
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    assert_eq!(None, resolve_logfile(&options));

    options.logfile = Some(None);
    assert_eq!(Some(confbase.join("log")), resolve_logfile(&options));

    let explicit = confbase.join("custom.log");
    options.logfile = Some(Some(explicit.clone()));
    assert_eq!(Some(explicit), resolve_logfile(&options));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn parses_umbilical_fd_and_color_flag_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    assert_eq!(
        Some(UmbilicalSpec {
            fd: 17,
            colorize: true
        }),
        parse_umbilical_spec(Some("17 1"))
    );
    assert_eq!(
        Some(UmbilicalSpec {
            fd: 17,
            colorize: false
        }),
        parse_umbilical_spec(Some("17 0"))
    );
    assert_eq!(
        Some(UmbilicalSpec {
            fd: 17,
            colorize: false
        }),
        parse_umbilical_spec(Some("17"))
    );
    assert_eq!(None, parse_umbilical_spec(Some("bad 1")));
}

#[test]
fn runtime_keys_load_default_private_key_and_peer_public_keys() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-keys");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let gamma_key = test_key(3);
    let delta_key = test_key(4);
    let delta_public = confbase.join("delta.pub");

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        format!(
            "Subnet = 10.0.0.0/8\nEd25519PublicKey = {}\n",
            alpha_key.public_key().to_base64()
        ),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = 192.0.2.2 655\nEd25519PublicKey = {}\n",
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("gamma"),
        gamma_key.public_key().to_pem(),
    )
    .unwrap();
    fs::write(&delta_public, delta_key.public_key().to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("delta"),
        format!("Ed25519PublicKeyFile = {}\n", delta_public.display()),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let keys = load_runtime_keys(&options).unwrap();

    assert_eq!(
        alpha_key.public_key(),
        keys.private_key.as_ref().unwrap().public_key()
    );
    assert_eq!(3, keys.peer_public_keys.len());
    assert_eq!(
        Some(&beta_key.public_key()),
        keys.peer_public_keys.get("beta")
    );
    assert_eq!(
        Some(&gamma_key.public_key()),
        keys.peer_public_keys.get("gamma")
    );
    assert_eq!(
        Some(&delta_key.public_key()),
        keys.peer_public_keys.get("delta")
    );
    assert!(!keys.peer_public_keys.contains_key("alpha"));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_keys_load_default_rsa_private_and_peer_public_pem_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-rsa-keys");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_rsa = test_rsa_key();
    let beta_rsa = test_rsa_key();
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("rsa_key.priv"),
        alpha_rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_str(),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        format!(
            "Ed25519PublicKey = {}\n{}",
            alpha_key.public_key().to_base64(),
            alpha_rsa_public.to_pkcs1_pem(LineEnding::LF).unwrap()
        ),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = 192.0.2.2 655\nEd25519PublicKey = {}\n{}",
            beta_key.public_key().to_base64(),
            beta_rsa_public.to_pkcs1_pem(LineEnding::LF).unwrap()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let keys = load_runtime_keys(&options).unwrap();

    assert_eq!(
        Some(alpha_rsa_public),
        keys.rsa_private_key
            .as_ref()
            .map(RuntimeRsaPrivateKey::public_key)
    );
    assert_eq!(
        Some(&beta_rsa_public),
        keys.peer_rsa_public_keys.get("beta")
    );
    assert!(!keys.peer_rsa_public_keys.contains_key("alpha"));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_keys_treat_rsa_only_peer_host_as_missing_ed25519_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-rsa-only-peer-host");
    let alpha_key = test_key(1);
    let alpha_rsa = test_rsa_key();
    let beta_rsa = test_rsa_key();
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("rsa_key.priv"),
        alpha_rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_str(),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        format!(
            "Ed25519PublicKey = {}\n{}",
            alpha_key.public_key().to_base64(),
            alpha_rsa_public.to_pkcs1_pem(LineEnding::LF).unwrap()
        ),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Address = 192.0.2.2 655\n{}",
            beta_rsa_public.to_pkcs1_pem(LineEnding::LF).unwrap()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let keys = load_runtime_keys(&options).unwrap();

    assert!(keys.private_key.is_some());
    assert!(!keys.peer_public_keys.contains_key("beta"));
    assert_eq!(
        Some(&beta_rsa_public),
        keys.peer_rsa_public_keys.get("beta")
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_keys_load_rsa_key_file_overrides_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-rsa-key-files");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_rsa = test_rsa_key();
    let beta_rsa = test_rsa_key();
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);
    let private_path = confbase.join("custom-rsa.priv");
    let beta_public_path = confbase.join("beta-rsa.pub");

    fs::write(
        confbase.join("tinc.conf"),
        format!(
            "Name = alpha\nPrivateKeyFile = {}\n",
            private_path.display()
        ),
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        &private_path,
        alpha_rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_str(),
    )
    .unwrap();
    fs::write(
        &beta_public_path,
        beta_rsa_public.to_pkcs1_pem(LineEnding::LF).unwrap(),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        format!(
            "Ed25519PublicKey = {}\n",
            alpha_key.public_key().to_base64()
        ),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "Ed25519PublicKey = {}\nPublicKeyFile = {}\n",
            beta_key.public_key().to_base64(),
            beta_public_path.display()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let keys = load_runtime_keys(&options).unwrap();

    assert_eq!(
        Some(alpha_rsa_public),
        keys.rsa_private_key
            .as_ref()
            .map(RuntimeRsaPrivateKey::public_key)
    );
    assert_eq!(
        Some(&beta_rsa_public),
        keys.peer_rsa_public_keys.get("beta")
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_keys_load_legacy_hex_rsa_keys_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-rsa-legacy-hex");
    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let alpha_rsa = test_legacy_rsa_key();
    let beta_rsa = test_legacy_rsa_key();
    let alpha_rsa_public = RsaPublicKey::from(&alpha_rsa);
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);

    fs::write(
        confbase.join("tinc.conf"),
        format!("Name = alpha\nPrivateKey = {}\n", rsa_hex(alpha_rsa.d())),
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        format!(
            "PublicKey = {}\nEd25519PublicKey = {}\n",
            rsa_hex(alpha_rsa.n()),
            alpha_key.public_key().to_base64()
        ),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta"),
        format!(
            "PublicKey = {}\nEd25519PublicKey = {}\n",
            rsa_hex(beta_rsa.n()),
            beta_key.public_key().to_base64()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let keys = load_runtime_keys(&options).unwrap();

    assert_eq!(
        Some(alpha_rsa_public),
        keys.rsa_private_key
            .as_ref()
            .map(RuntimeRsaPrivateKey::public_key)
    );
    assert_eq!(
        Some(&beta_rsa_public),
        keys.peer_rsa_public_keys.get("beta")
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_rsa_private_key_decrypts_pem_legacy_meta_block_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let private = test_rsa_key();
    let public = RsaPublicKey::from(&private);
    let runtime_key = RuntimeRsaPrivateKey::Pem(private);
    let size = runtime_key.rsa_size();
    let plaintext = legacy_meta_generate_rsa_key_material(size, |bytes| {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(17) & 0xff) as u8;
        }
    })
    .unwrap();
    let encrypted = legacy_meta_public_encrypt(&public, &plaintext).unwrap();

    assert_eq!(size, encrypted.len());
    assert_eq!(
        plaintext,
        runtime_key.decrypt_legacy_meta_block(&encrypted).unwrap()
    );
    assert!(matches!(
        runtime_key.decrypt_legacy_meta_block(&encrypted[1..]),
        Err(LegacyMetaError::InvalidRsaBlockLength { expected, actual })
            if expected == size && actual == size - 1
    ));
}

#[test]
fn runtime_rsa_private_key_decrypts_legacy_hex_meta_block_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let private = test_legacy_rsa_key();
    let public = RsaPublicKey::from(&private);
    let runtime_key = RuntimeRsaPrivateKey::LegacyHex {
        public_key: public.clone(),
        private_exponent: private.d().clone(),
    };
    let size = runtime_key.rsa_size();
    let plaintext = legacy_meta_generate_rsa_key_material(size, |bytes| {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (0xa5 ^ index.wrapping_mul(13)) as u8;
        }
    })
    .unwrap();
    let encrypted = legacy_meta_public_encrypt(&public, &plaintext).unwrap();

    assert_eq!(size, encrypted.len());
    assert_eq!(
        plaintext,
        runtime_key.decrypt_legacy_meta_block(&encrypted).unwrap()
    );
    assert_eq!(legacy_rsa_exponent(), *public.e());
}

#[test]
fn runtime_keys_allow_default_rsa_only_startup_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-keys-default-rsa-only");
    let alpha_rsa = test_rsa_key();

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("rsa_key.priv"),
        alpha_rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_str(),
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
    let keys = load_runtime_keys(&options).unwrap();

    assert!(config.experimental_protocol.is_none());
    assert!(config.state.experimental);
    assert!(keys.private_key.is_none());
    assert!(keys.rsa_private_key.is_some());

    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys.clone());
    assert!(!runtime.state.experimental);
    assert!(!runtime.state.graph.node("alpha").unwrap().status.sptps);
    assert!(runtime.key_exchange.is_none());

    let action = run(args(&["tincd", "-D", "-c", confbase.to_str().unwrap()])).unwrap();
    let CliAction::RunForeground { config, keys, .. } = action else {
        panic!("expected foreground action");
    };
    assert!(!config.state.experimental);
    assert!(!config.state.graph.node("alpha").unwrap().status.sptps);
    assert!(keys.private_key.is_none());

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn experimental_protocol_no_allows_rsa_only_and_ignores_ed25519_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-keys-exp-no-rsa-only");
    let alpha_key = test_key(1);
    let alpha_rsa = test_rsa_key();
    let beta_rsa = test_rsa_key();
    let beta_rsa_public = RsaPublicKey::from(&beta_rsa);

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nExperimentalProtocol = no\n",
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("rsa_key.priv"),
        alpha_rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_str(),
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
            "Address = 192.0.2.2 655\nSubnet = 10.1.0.0/16\n{}",
            beta_rsa_public.to_pkcs1_pem(LineEnding::LF).unwrap()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let config = load_runtime_config(&options).unwrap();
    let keys = load_runtime_keys(&options).unwrap();
    let runtime = RuntimeDaemonState::new(Vec::new(), &config, keys.clone());

    assert_eq!(Some(false), config.experimental_protocol);
    assert!(!config.state.experimental);
    assert!(keys.private_key.is_none());
    assert!(keys.rsa_private_key.is_some());
    assert!(keys.peer_public_keys.is_empty());
    assert_eq!(
        Some(&beta_rsa_public),
        keys.peer_rsa_public_keys.get("beta")
    );
    assert!(!runtime.state.experimental);
    assert!(runtime.key_exchange.is_none());

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn experimental_protocol_yes_requires_ed25519_private_key_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-keys-exp-yes-missing-ed25519");
    let alpha_rsa = test_rsa_key();

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nExperimentalProtocol = yes\n",
    )
    .unwrap();
    fs::write(
        confbase.join("rsa_key.priv"),
        alpha_rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_str(),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let error = load_runtime_keys(&options).unwrap_err();

    assert!(matches!(
        error,
        TincdError::KeyIo { path, .. } if path == confbase.join("ed25519_key.priv")
    ));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn experimental_protocol_no_requires_rsa_private_key_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-keys-exp-no-missing-rsa");
    let alpha_key = test_key(1);

    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nExperimentalProtocol = no\n",
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let error = load_runtime_keys(&options).unwrap_err();

    assert!(matches!(
        error,
        TincdError::RuntimeState(message)
            if message == "No private keys available, cannot start tinc!"
    ));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_keys_report_missing_all_private_keys_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-keys-missing-all-private");
    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let error = load_runtime_keys(&options).unwrap_err();

    assert!(matches!(
        error,
        TincdError::RuntimeState(message)
            if message == "No private keys available, cannot start tinc!"
    ));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn connection_dump_includes_runtime_meta_connections() {
    tinc_test_support::assert_can_create_netns();
    let infos = vec![RuntimeMetaConnectionInfo {
        id: 42,
        name: Some("beta".to_owned()),
        peer: "192.0.2.10:655".parse().unwrap(),
        local: "10.0.0.1:655".parse().unwrap(),
        bytes_read: 12,
        bytes_written: 0,
        status: CONNECTION_DUMP_STATUS_PINGED,
        options: 0x24,
    }];

    assert_eq!(
        "18 6 beta 192.0.2.10 port 655 24 42 1\n",
        format_runtime_connection_dump(&infos, false)
    );
}

#[test]
fn hostnames_option_reverse_resolves_dump_hosts_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree_with_hosts(
        &config_tree(&[("Name", "alpha"), ("Hostnames", "yes")]),
        [(
            "beta",
            &config_tree(&[
                ("Address", "127.0.0.1 0"),
                ("Ed25519PublicKey", &test_key(2).public_key().to_base64()),
            ]),
        )],
    )
    .unwrap();
    assert!(config.daemon.hostnames);
    let runtime = RuntimeDaemonState::new(
        Vec::new(),
        &config,
        RuntimeKeys {
            private_key: Some(test_key(1)),
            peer_public_keys: BTreeMap::from([("beta".to_owned(), test_key(2).public_key())]),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );

    let nodes = dump_nodes(&config, runtime.state(), Some(&runtime));
    assert!(
        nodes.contains("18 3 beta ") && nodes.contains(" unknown port unknown "),
        "C dump_nodes() uses n->hostname for live runtime node dumps and falls back to unknown without a learned UDP address: {nodes}"
    );
    let infos = vec![RuntimeMetaConnectionInfo {
        id: 7,
        name: Some("beta".to_owned()),
        peer: "127.0.0.1:0".parse().unwrap(),
        local: "127.0.0.1:0".parse().unwrap(),
        bytes_read: 0,
        bytes_written: 0,
        status: CONNECTION_DUMP_STATUS_PINGED,
        options: 0,
    }];
    assert_eq!(
        "18 6 beta localhost port 0 0 7 1\n",
        format_runtime_connection_dump(&infos, true)
    );

    let reloaded =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Hostnames", "no")]))
            .unwrap();
    let mut runtime = runtime;
    runtime
        .apply_reloaded_config(
            &reloaded,
            RuntimeKeys {
                private_key: Some(test_key(1)),
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        )
        .unwrap();
    assert!(!runtime.hostnames);
}

#[test]
fn runtime_connection_dump_status_bits_match_tinc() {
    tinc_test_support::assert_can_create_netns();
    let Some((mut beta_stream, mut beta_driver, mut beta_connection)) =
        active_runtime_connection("beta", test_key(1), test_key(2))
    else {
        return;
    };
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("Subnet", "10.0.0.0/8"),
    ]))
    .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), test_key(2).public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    beta_connection.id = 7;
    runtime.meta_connections.push(beta_connection);

    assert_eq!(0, runtime.meta_connection_infos()[0].status);

    runtime.meta_connections[0].edge_peer = Some("beta".to_owned());
    runtime.local_edge_connections.insert("beta".to_owned(), 7);
    runtime.meta_connections[0].last_ping_time = Instant::now() - runtime.ping_interval;
    runtime.next_meta_ping_check = Instant::now() - StdDuration::from_secs(1);
    runtime.poll_once().unwrap();
    runtime.flush_meta_outputs().unwrap();
    assert_eq!(
        CONNECTION_DUMP_STATUS_PINGED,
        runtime.meta_connection_infos()[0].status
    );

    let mut buffer = [0u8; 512];
    let len = beta_stream.read(&mut buffer).unwrap();
    let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();
    assert!(
        step.events
            .contains(&MetaConnectionEvent::Message(MetaMessage::Ping))
    );
}

#[test]
fn listen_address_resolves_service_names_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let listen = ListenAddress {
        address: Some("localhost".to_owned()),
        port: "http".to_owned(),
        bind_to: false,
    };

    let targets = resolve_listen_targets(&listen, ListenAddressFamily::Ipv4, None).unwrap();

    assert_eq!(vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()], targets);
}

#[cfg(unix)]
#[test]
fn systemd_watchdog_keeps_pinging_after_control_reload_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    use std::os::unix::net::{UnixDatagram, UnixStream};

    let confbase = temp_confbase("systemd-watchdog-reload");
    let notify_socket = confbase.join("notify.sock");
    let notify = UnixDatagram::bind(&notify_socket).unwrap();
    notify
        .set_read_timeout(Some(StdDuration::from_millis(100)))
        .unwrap();

    let key = test_key(1);
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nDeviceType = dummy\nAddressFamily = IPv4\nBindToAddress = 127.0.0.1 0\nAutoConnect = no\nLogLevel = 5\n",
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        format!(
            "Ed25519PublicKey = {}\nSubnet = 10.0.0.0/8\n",
            key.public_key().to_base64()
        ),
    )
    .unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    options.no_detach = true;
    let config = load_runtime_config(&options).unwrap();
    let keys = load_runtime_keys(&options).unwrap();
    let endpoint = ControlEndpoint::new(&options);
    let server_endpoint = endpoint.clone();
    let server_options = options.clone();

    let _notify_guard = EnvVarGuard::set("NOTIFY_SOCKET", notify_socket.as_os_str());
    let _watchdog_guard = EnvVarGuard::set("WATCHDOG_USEC", "200000");
    let _watchdog_pid_guard = EnvVarGuard::set("WATCHDOG_PID", std::process::id().to_string());
    let server_handle = thread::spawn(move || {
        run_foreground_server(&config, &server_endpoint, keys, &server_options)
    });

    let mut before_stop = wait_for_systemd_notify(&notify, "READY=1", "foreground READY notify");
    before_stop.extend(wait_for_systemd_notify(
        &notify,
        "WATCHDOG=1",
        "initial watchdog notify",
    ));
    before_stop.extend(drain_systemd_notify(&notify));
    assert!(
        !before_stop.iter().any(|message| message == "STOPPING=1"),
        "C watchdog_stop() must not run before reload completes: {before_stop:?}"
    );

    let reload = send_control_request_for_test(&endpoint, REQ_RELOAD);
    assert_eq!(
        format!("{} {REQ_RELOAD} 0\n", Request::Control.number()),
        reload
    );

    let mut after_reload = drain_systemd_notify(&notify);
    after_reload.extend(wait_for_systemd_notify(
        &notify,
        "WATCHDOG=1",
        "watchdog notify after reload",
    ));
    assert!(
        !after_reload.iter().any(|message| message == "STOPPING=1"),
        "reload must not send STOPPING before daemon shutdown: {after_reload:?}"
    );

    let stop = send_control_request_for_test(&endpoint, REQ_STOP);
    assert_eq!(
        format!("{} {REQ_STOP} 0\n", Request::Control.number()),
        stop
    );
    let stopping = wait_for_systemd_notify(&notify, "STOPPING=1", "foreground STOPPING notify");
    assert!(stopping.iter().any(|message| message == "STOPPING=1"));
    assert_eq!(Ok(()), server_handle.join().unwrap());

    fs::remove_dir_all(confbase).unwrap();

    fn send_control_request_for_test(endpoint: &ControlEndpoint, request: i32) -> String {
        let mut stream = UnixStream::connect(&endpoint.socket).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        let id = Request::Id.number();
        let ack = Request::Ack.number();
        let control = Request::Control.number();

        reader.read_line(&mut line).unwrap();
        assert_eq!(format!("{id} alpha {PROT_MAJOR}.{PROT_MINOR}\n"), line);
        write!(
            stream,
            "{id} ^{} {TINC_CTL_VERSION_CURRENT}\n",
            endpoint.cookie
        )
        .unwrap();
        stream.flush().unwrap();

        line.clear();
        reader.read_line(&mut line).unwrap();
        assert_eq!(
            format!("{ack} {TINC_CTL_VERSION_CURRENT} {}\n", endpoint.pid),
            line
        );

        write!(stream, "{control} {request}\n").unwrap();
        stream.flush().unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        line
    }

    fn wait_for_systemd_notify(notify: &UnixDatagram, expected: &str, label: &str) -> Vec<String> {
        let deadline = Instant::now() + StdDuration::from_secs(2);
        let mut messages = Vec::new();
        while Instant::now() < deadline {
            match read_systemd_notify(notify) {
                Ok(message) => {
                    let matched = message == expected;
                    messages.push(message);
                    if matched {
                        return messages;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => panic!("failed reading {label}: {error}"),
            }
        }

        panic!("timed out waiting for {label} {expected:?}; saw {messages:?}");
    }

    fn drain_systemd_notify(notify: &UnixDatagram) -> Vec<String> {
        let mut messages = Vec::new();
        loop {
            match read_systemd_notify(notify) {
                Ok(message) => messages.push(message),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return messages;
                }
                Err(error) => panic!("failed draining systemd notify socket: {error}"),
            }
        }
    }

    fn read_systemd_notify(notify: &UnixDatagram) -> io::Result<String> {
        let mut buffer = [0u8; 256];
        let len = notify.recv(&mut buffer)?;
        Ok(String::from_utf8_lossy(&buffer[..len]).into_owned())
    }
}

#[test]
fn loads_runtime_config_from_confbase_and_host_file() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("load-runtime");
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nMode = switch\nConnectTo = beta\n",
    )
    .unwrap();
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

    assert_eq!("alpha", config.name);
    assert_eq!(vec!["beta"], config.connect_to);
    assert_eq!(1, config.state.subnets.owner_subnets("alpha").count());
    assert!(config.state.graph.node("beta").unwrap().status.has_address);
    assert_eq!(
        Some("192.0.2.7:777".parse().unwrap()),
        config.addresses.address("beta")
    );
    assert_eq!(0, config.state.subnets.owner_subnets("beta").count());

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn load_runtime_config_handles_lzo_compression_like_tincd_build_features() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("load-runtime-lzo-compression");
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nExperimentalProtocol = no\nCompression = 10\n",
    )
    .unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());

    if legacy_compression_is_available(CompressionLevel::LzoLow) {
        assert_eq!(
            CompressionLevel::LzoLow,
            load_runtime_config(&options)
                .unwrap()
                .daemon
                .legacy_compression
        );
    } else {
        assert_eq!(
            Err(TincdError::UnsupportedLegacyCompression(
                CompressionLevel::LzoLow
            )),
            load_runtime_config(&options)
        );
        let error = load_runtime_config(&options).unwrap_err().to_string();
        assert!(error.contains("Bogus compression level!"));
        assert!(error.contains("LZO compression is unavailable on this node."));
    }

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn command_line_options_override_server_and_host_config() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("override");
    fs::write(confbase.join("tinc.conf"), "Name = alpha\nMode = router\n").unwrap();
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
    options.command_line_options = vec![
        Config::new("Mode", "hub", ConfigSource::command_line(1)),
        Config::new("StrictSubnets", "yes", ConfigSource::command_line(2)),
        Config::new(
            "alpha.Subnet",
            "192.0.2.0/24",
            ConfigSource::command_line(3),
        ),
    ];

    let config = load_runtime_config(&options).unwrap();

    assert_eq!(
        tinc_core::route::RoutingMode::Hub,
        config.engine.route.routing_mode
    );
    assert_eq!(
        vec!["192.0.2.0/24", "10.0.0.0/8"],
        config
            .state
            .subnets
            .owner_subnets("alpha")
            .map(|subnet| subnet.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        vec!["10.2.0.0/16"],
        config
            .state
            .subnets
            .owner_subnets("beta")
            .map(|subnet| subnet.to_string())
            .collect::<Vec<_>>()
    );

    fs::remove_dir_all(confbase).unwrap();
}
