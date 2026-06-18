use super::*;

#[test]
fn daemon_script_exports_tinc_environment() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("daemon-script-env");
    let output = confbase.join("script.env");
    fs::write(
        confbase.join("tinc-up.sh"),
        "printf 'NAME=%s\\nNETNAME=%s\\nDEVICE=%s\\nINTERFACE=%s\\nDEBUG=%s\\nREMOTEADDRESS=%s\\n' \"$NAME\" \"$NETNAME\" \"$DEVICE\" \"$INTERFACE\" \"$DEBUG\" \"$REMOTEADDRESS\" > \"$SCRIPT_OUT\"\n",
    )
    .unwrap();

    let mut tree = ConfigTree::new();
    tree.add(Config::new(
        "Name",
        "alpha",
        ConfigSource::file("tinc.conf", 1),
    ));
    tree.add(Config::new(
        "ScriptsInterpreter",
        "/bin/sh",
        ConfigSource::file("tinc.conf", 2),
    ));
    tree.add(Config::new(
        "ScriptsExtension",
        ".sh",
        ConfigSource::file("tinc.conf", 3),
    ));
    let config = RuntimeConfig::from_config_tree(&tree).unwrap();
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    options.netname = Some("prod".to_owned());
    options.debug_level = Some(None);
    let device_info = DeviceInfo::new(
        DeviceKind::Tun,
        "/dev/net/tun",
        Some("vpn0".to_owned()),
        "TUN device",
    );

    assert!(
        run_daemon_script(
            "tinc-up",
            &config,
            &options,
            &device_info,
            &[
                ("REMOTEADDRESS", "198.51.100.10".to_owned()),
                ("SCRIPT_OUT", output.display().to_string()),
            ],
        )
        .unwrap()
    );

    assert_eq!(
        "NAME=alpha\nNETNAME=prod\nDEVICE=/dev/net/tun\nINTERFACE=vpn0\nDEBUG=1\nREMOTEADDRESS=198.51.100.10\n",
        fs::read_to_string(&output).unwrap()
    );
    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_invitation_accepted_script_matches_tinc_environment() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-invitation-accepted-script");
    let output = confbase.join("accepted.env");
    fs::write(
        confbase.join("invitation-accepted.sh"),
        format!(
            "printf 'NAME=%s\\nNETNAME=%s\\nNODE=%s\\nREMOTEADDRESS=%s\\n' \"$NAME\" \"$NETNAME\" \"$NODE\" \"$REMOTEADDRESS\" > {}\n",
            output.display()
        ),
    )
    .unwrap();

    let mut tree = ConfigTree::new();
    tree.add(Config::new(
        "Name",
        "alpha",
        ConfigSource::file("tinc.conf", 1),
    ));
    tree.add(Config::new(
        "ScriptsInterpreter",
        "/bin/sh",
        ConfigSource::file("tinc.conf", 2),
    ));
    tree.add(Config::new(
        "ScriptsExtension",
        ".sh",
        ConfigSource::file("tinc.conf", 3),
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
    runtime.accept_invited_peer(
        "beta",
        test_key(2).public_key(),
        "198.51.100.25:1665".parse().unwrap(),
    );

    assert_eq!(
        "NAME=alpha\nNETNAME=prod\nNODE=beta\nREMOTEADDRESS=198.51.100.25\n",
        fs::read_to_string(output).unwrap()
    );
    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_meta_events_run_host_and_subnet_scripts() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-event-scripts");
    let output = confbase.join("events.out");
    let output_arg = output.display().to_string();
    for script in ["host-up", "host-down", "subnet-up", "subnet-down"] {
        fs::write(
            confbase.join(format!("{script}.sh")),
            event_script(script, &output_arg),
        )
        .unwrap();
    }
    fs::write(
        confbase.join("hosts").join("beta-up.sh"),
        event_script("hosts/beta-up", &output_arg),
    )
    .unwrap();
    fs::write(
        confbase.join("hosts").join("beta-down.sh"),
        event_script("hosts/beta-down", &output_arg),
    )
    .unwrap();

    let mut tree = ConfigTree::new();
    tree.add(Config::new(
        "Name",
        "alpha",
        ConfigSource::file("tinc.conf", 1),
    ));
    tree.add(Config::new(
        "ScriptsInterpreter",
        "/bin/sh",
        ConfigSource::file("tinc.conf", 2),
    ));
    tree.add(Config::new(
        "ScriptsExtension",
        ".sh",
        ConfigSource::file("tinc.conf", 3),
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

    runtime
        .apply_runtime_meta_message(parse_meta_message("10 1 beta 10.2.0.0/16#5").unwrap())
        .unwrap();
    assert!(!output.exists());

    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 2 alpha beta 127.0.0.1 1234 0 1").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(
            parse_meta_message("12 3 beta alpha 127.0.0.1 4321 0 1").unwrap(),
        )
        .unwrap();
    runtime
        .apply_runtime_meta_message(parse_meta_message("11 4 beta 10.2.0.0/16#5").unwrap())
        .unwrap();
    runtime
        .apply_runtime_meta_message(parse_meta_message("13 5 beta alpha").unwrap())
        .unwrap();
    runtime
        .apply_runtime_meta_message(parse_meta_message("13 6 alpha beta").unwrap())
        .unwrap();

    let events = fs::read_to_string(&output).unwrap();
    assert!(events.contains(
        "host-up NAME=alpha NETNAME=prod NODE=beta SUBNET= WEIGHT= REMOTEADDRESS=127.0.0.1 REMOTEPORT=1234"
    ));
    assert!(events.contains(
        "hosts/beta-up NAME=alpha NETNAME=prod NODE=beta SUBNET= WEIGHT= REMOTEADDRESS=127.0.0.1 REMOTEPORT=1234"
    ));
    assert!(events.contains(
        "subnet-up NAME=alpha NETNAME=prod NODE=beta SUBNET=10.2.0.0/16 WEIGHT=5 REMOTEADDRESS=127.0.0.1 REMOTEPORT=1234"
    ));
    assert!(events.contains(
        "subnet-down NAME=alpha NETNAME=prod NODE=beta SUBNET=10.2.0.0/16 WEIGHT=5 REMOTEADDRESS=127.0.0.1 REMOTEPORT=1234"
    ));
    assert!(events.contains(
        "host-down NAME=alpha NETNAME=prod NODE=beta SUBNET= WEIGHT= REMOTEADDRESS=127.0.0.1 REMOTEPORT=1234"
    ));
    assert!(events.contains(
        "hosts/beta-down NAME=alpha NETNAME=prod NODE=beta SUBNET= WEIGHT= REMOTEADDRESS=127.0.0.1 REMOTEPORT=1234"
    ));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_learned_mac_subnets_run_scripts_broadcast_and_expire_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-mac-expire");
    let output = confbase.join("events.out");
    let output_arg = output.display().to_string();
    for script in ["subnet-up", "subnet-down"] {
        fs::write(
            confbase.join(format!("{script}.sh")),
            event_script(script, &output_arg),
        )
        .unwrap();
    }

    let alpha_key = test_key(1);
    let beta_key = test_key(2);
    let mut tree = ConfigTree::new();
    tree.add(Config::new(
        "Name",
        "alpha",
        ConfigSource::file("tinc.conf", 1),
    ));
    tree.add(Config::new(
        "ScriptsInterpreter",
        "/bin/sh",
        ConfigSource::file("tinc.conf", 2),
    ));
    tree.add(Config::new(
        "ScriptsExtension",
        ".sh",
        ConfigSource::file("tinc.conf", 3),
    ));
    let config = RuntimeConfig::from_config_tree(&tree).unwrap();
    let keys = RuntimeKeys {
        private_key: Some(alpha_key.clone()),
        peer_public_keys: BTreeMap::from([("beta".to_owned(), beta_key.public_key())]),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let Some((mut beta_stream, mut beta_driver, beta_connection)) =
        active_runtime_connection("beta", alpha_key, beta_key)
    else {
        fs::remove_dir_all(confbase).unwrap();
        return;
    };
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    options.netname = Some("prod".to_owned());
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_scripts(&config, &options);
    runtime.meta_connections.push(beta_connection);

    let subnet = Subnet::mac(tinc_core::subnet::MacAddr::new([0, 1, 2, 3, 4, 5]))
        .with_owner("alpha")
        .with_expiry(100);
    runtime.state.subnets.add(subnet.clone());
    runtime
        .handle_engine_events(vec![EngineEvent::LearnedSubnet {
            subnet: subnet.clone(),
        }])
        .unwrap();

    let mut buffer = [0u8; 512];
    let len = beta_stream.read(&mut buffer).unwrap();
    let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();
    assert!(step.events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::AddSubnet(SubnetMessage {
                owner,
                subnet,
                ..
            })) if owner == "alpha"
                && subnet
                    == &Subnet::mac(tinc_core::subnet::MacAddr::new([0, 1, 2, 3, 4, 5]))
        )
    }));

    runtime.expire_dynamic_mac_subnets_at(101).unwrap();
    assert!(
        runtime
            .state
            .subnets
            .lookup_owner_subnet("alpha", &subnet)
            .is_none()
    );
    let len = beta_stream.read(&mut buffer).unwrap();
    let step = beta_driver.receive_bytes(&buffer[..len]).unwrap();
    assert!(step.events.iter().any(|event| {
        matches!(
            event,
            MetaConnectionEvent::Message(MetaMessage::DeleteSubnet(SubnetMessage {
                owner,
                subnet,
                ..
            })) if owner == "alpha"
                && subnet
                    == &Subnet::mac(tinc_core::subnet::MacAddr::new([0, 1, 2, 3, 4, 5]))
        )
    }));

    let events = fs::read_to_string(&output).unwrap();
    assert!(events.contains(
        "subnet-up NAME=alpha NETNAME=prod NODE=alpha SUBNET=00:01:02:03:04:05 WEIGHT= REMOTEADDRESS= REMOTEPORT="
    ));
    assert!(events.contains(
        "subnet-down NAME=alpha NETNAME=prod NODE=alpha SUBNET=00:01:02:03:04:05 WEIGHT= REMOTEADDRESS= REMOTEPORT="
    ));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_packet_diag_formats_only_sampled_entries() {
    tinc_test_support::assert_can_create_netns();
    let config = RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha")])).unwrap();
    let mut runtime = RuntimeDaemonState::new(
        Vec::new(),
        &config,
        RuntimeKeys {
            private_key: Some(test_key(1)),
            peer_public_keys: BTreeMap::new(),
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        },
    );
    let calls = std::cell::Cell::new(0);

    for _ in 0..9 {
        runtime.record_packet_diag("packet", |count| {
            calls.set(calls.get() + 1);
            format!("diag packet count={count}")
        });
    }

    assert_eq!(8, calls.get());
    assert_eq!(Some(&9), runtime.packet_diag_counts.get("packet"));
}

#[test]
fn runtime_logfile_writes_c_style_filtered_entries() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-logfile");
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "4")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let logfile = confbase.join("log");
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_logfile(&logfile).unwrap();
    runtime.record_log_with_priority(3, LOG_ERR, "visible file log");
    runtime.record_log_with_priority(5, LOG_DEBUG, "hidden file log");

    let output = fs::read_to_string(&logfile).unwrap();
    assert!(output.contains("tinc["));
    assert!(output.contains("]: visible file log"));
    assert!(!output.contains("ERROR"));
    assert!(!output.contains("hidden file log"));

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn runtime_stderr_log_writes_pretty_filtered_entries_like_tinc_no_detach() {
    tinc_test_support::assert_can_create_netns();
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "4")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let output = SharedLogBuffer::new();
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_log_writer_for_test(Box::new(output.clone()), false);

    runtime.record_log_with_priority(3, LOG_ERR, "visible stderr log");
    runtime.record_log_with_priority(5, LOG_DEBUG, "hidden stderr log");

    let output = output.output();
    assert!(
        output.contains(" ERROR   visible stderr log"),
        "C LOGMODE_STDERR writes pretty priority-tagged log lines"
    );
    assert!(!output.contains("tinc["));
    assert!(!output.contains("hidden stderr log"));
}

#[test]
fn runtime_stderr_log_can_colorize_like_tinc_no_detach() {
    tinc_test_support::assert_can_create_netns();
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "4")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let output = SharedLogBuffer::new();
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_log_writer_for_test(Box::new(output.clone()), true);

    runtime.record_log_with_priority(3, LOG_WARNING, "color stderr log");

    let output = output.output();
    assert!(output.contains("\x1b[90m"));
    assert!(output.contains("\x1b[33;1m"));
    assert!(output.contains("\x1b[0m"));
    assert!(output.contains("WARNING"));
    assert!(output.contains("color stderr log"));
}

#[cfg(unix)]
#[test]
fn runtime_umbilical_forwards_pretty_logs_until_success_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "4")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut fds = [-1; 2];
    assert_eq!(0, unsafe { libc::pipe(fds.as_mut_ptr()) });
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_umbilical_log_from_spec_for_test(fds[1], true);

    runtime.record_log_with_priority(3, LOG_ERR, "visible umbilical log");
    runtime.record_log_with_priority(5, LOG_DEBUG, "hidden umbilical log");
    runtime.notify_umbilical_success_and_close().unwrap();
    runtime.record_log_with_priority(3, LOG_ERR, "after success");
    let _ = unsafe { libc::close(fds[1]) };

    let mut output = Vec::new();
    let mut buffer = [0u8; 256];
    loop {
        let read = unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) };
        if read <= 0 {
            break;
        }
        output.extend_from_slice(&buffer[..read as usize]);
    }
    let _ = unsafe { libc::close(fds[0]) };
    assert_eq!(
        Some(&0),
        output.last(),
        "C tincd writes a NUL success byte after startup logs"
    );
    let text = String::from_utf8_lossy(&output[..output.len() - 1]);
    assert!(text.contains("\x1b[90m"));
    assert!(text.contains("\x1b[31;1m"));
    assert!(text.contains("ERROR"));
    assert!(text.contains("visible umbilical log"));
    assert!(!text.contains("hidden umbilical log"));
    assert!(!text.contains("after success"));
}

#[cfg(unix)]
#[test]
fn runtime_logfile_reopen_switches_to_new_file_after_rotation_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-logfile-reopen");
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "4")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let logfile = confbase.join("log");
    let rotated = confbase.join("log.1");
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_logfile(&logfile).unwrap();
    runtime.record_log(3, "before rotate");
    fs::rename(&logfile, &rotated).unwrap();

    runtime.reopen_logger();
    runtime.record_log(3, "after rotate");

    let old_output = fs::read_to_string(&rotated).unwrap();
    let new_output = fs::read_to_string(&logfile).unwrap();
    assert!(old_output.contains("before rotate"));
    assert!(!old_output.contains("after rotate"));
    assert!(new_output.contains("after rotate"));

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn runtime_logfile_reopen_failure_keeps_old_file_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-logfile-reopen-fail");
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "4")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let logfile = confbase.join("log");
    let rotated = confbase.join("log.1");
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_logfile(&logfile).unwrap();
    runtime.record_log(3, "before failed reopen");
    fs::rename(&logfile, &rotated).unwrap();
    fs::create_dir(&logfile).unwrap();

    runtime.reopen_logger();
    runtime.record_log(3, "after failed reopen");

    let old_output = fs::read_to_string(&rotated).unwrap();
    assert!(old_output.contains("before failed reopen"));
    assert!(old_output.contains("Unable to reopen log file"));
    assert!(old_output.contains("after failed reopen"));
    assert!(logfile.is_dir());

    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn runtime_sighup_reopens_logfile_before_reload_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("runtime-sighup-log-reopen");
    let key = test_key(1);
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nLogLevel = 4\nDeviceType = dummy\n",
    )
    .unwrap();
    fs::write(confbase.join("ed25519_key.priv"), key.to_pem()).unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    let mut config = load_runtime_config(&options).unwrap();
    let keys = load_runtime_keys(&options).unwrap();
    let logfile = confbase.join("log");
    let rotated = confbase.join("log.1");
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);
    runtime.enable_logfile(&logfile).unwrap();
    runtime.record_log(3, "before sighup");
    fs::rename(&logfile, &rotated).unwrap();

    let mut fds = [-1; 2];
    assert_eq!(0, unsafe { libc::pipe(fds.as_mut_ptr()) });
    set_raw_fd_nonblocking(fds[0], true).unwrap();
    let signals = RuntimeSignalHandlers {
        read_fd: fds[0],
        write_fd: fds[1],
        old_handlers: Vec::new(),
    };
    let signal = [libc::SIGHUP as u8];
    assert_eq!(1, unsafe {
        libc::write(fds[1], signal.as_ptr().cast::<libc::c_void>(), signal.len())
    });

    assert!(!handle_runtime_signal_actions(&mut config, &mut runtime, &options, &signals).unwrap());
    runtime.record_log(3, "after sighup");

    let old_output = fs::read_to_string(&rotated).unwrap();
    let new_output = fs::read_to_string(&logfile).unwrap();
    assert!(old_output.contains("before sighup"));
    assert!(old_output.contains("Got SIGHUP signal"));
    assert!(!old_output.contains("after sighup"));
    assert!(new_output.contains("after sighup"));

    drop(signals);
    fs::remove_dir_all(confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn runtime_syslog_enables_syslog_backend_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("LogLevel", "4")]))
            .unwrap();
    let keys = RuntimeKeys {
        private_key: Some(test_key(1)),
        peer_public_keys: BTreeMap::new(),
        rsa_private_key: None,
        peer_rsa_public_keys: BTreeMap::new(),
    };
    let mut runtime = RuntimeDaemonState::new(Vec::new(), &config, keys);

    runtime.enable_syslog().unwrap();

    assert!(matches!(
        runtime.log_sink.as_ref().map(|sink| &sink.backend),
        Some(RuntimeLogBackend::Syslog(_))
    ));
}

#[test]
fn pretty_log_entry_formats_priority_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let entry = format_pretty_log_entry(LOG_WARNING, "hello", false);
    assert!(entry.contains(" WARNING hello"));
}

#[cfg(unix)]
#[test]
fn pretty_log_entry_colorizes_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    let entry = format_pretty_log_entry(LOG_ERR, "hello", true);
    assert!(entry.contains("\x1b[90m"));
    assert!(entry.contains("\x1b[31;1m"));
    assert!(entry.contains("\x1b[0m"));
    assert!(entry.contains("ERROR"));
}

#[cfg(unix)]
#[test]
fn syslog_priority_maps_like_tinc() {
    tinc_test_support::assert_can_create_netns();
    assert_eq!(
        libc::LOG_EMERG,
        syslog_priority_from_tinc_priority(LOG_EMERG)
    );
    assert_eq!(
        libc::LOG_ALERT,
        syslog_priority_from_tinc_priority(LOG_ALERT)
    );
    assert_eq!(libc::LOG_CRIT, syslog_priority_from_tinc_priority(LOG_CRIT));
    assert_eq!(libc::LOG_ERR, syslog_priority_from_tinc_priority(LOG_ERR));
    assert_eq!(
        libc::LOG_WARNING,
        syslog_priority_from_tinc_priority(LOG_WARNING)
    );
    assert_eq!(
        libc::LOG_NOTICE,
        syslog_priority_from_tinc_priority(LOG_NOTICE)
    );
    assert_eq!(libc::LOG_INFO, syslog_priority_from_tinc_priority(LOG_INFO));
    assert_eq!(
        libc::LOG_DEBUG,
        syslog_priority_from_tinc_priority(LOG_DEBUG)
    );
}

#[cfg(unix)]
#[test]
fn umbilical_start_still_prepares_daemon_runtime_like_tincctl_start() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("daemon-action-umbilical");
    let alpha_key = test_key(1);

    fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
    fs::write(confbase.join("ed25519_key.priv"), alpha_key.to_pem()).unwrap();
    fs::write(
        confbase.join("hosts").join("alpha"),
        "Subnet = 10.0.0.0/8\n",
    )
    .unwrap();

    let _guard = EnvVarGuard::set("TINC_UMBILICAL", "17 0");
    let action = run(args(&[
        "tincd",
        "--config",
        confbase.to_str().unwrap(),
        "--pidfile",
        confbase.join("custom.pid").to_str().unwrap(),
    ]))
    .unwrap();

    let CliAction::RunDaemon {
        config, control, ..
    } = action
    else {
        panic!("expected daemon action");
    };

    assert_eq!("alpha", config.name);
    assert_eq!(confbase.join("custom.pid"), control.pidfile);

    fs::remove_dir_all(confbase).unwrap();
}
