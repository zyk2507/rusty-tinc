use super::*;

#[cfg(unix)]
#[test]
fn process_priority_values_match_tinc_nice_levels() {
    tinc_test_support::assert_can_create_netns();
    assert_eq!(0, process_priority_nice_value(ProcessPriority::Normal));
    assert_eq!(10, process_priority_nice_value(ProcessPriority::Low));
    assert_eq!(-10, process_priority_nice_value(ProcessPriority::High));
}

#[cfg(unix)]
#[test]
fn memory_lock_matches_tinc_mlockall_request_semantics() {
    tinc_test_support::assert_can_create_netns();
    use std::cell::Cell;

    let called = Cell::new(false);
    apply_memory_lock_with(false, || {
        called.set(true);
        Ok(())
    })
    .unwrap();
    assert!(!called.get());

    apply_memory_lock_with(true, || Ok(())).unwrap();

    let error = apply_memory_lock_with(true, || Err(io::Error::from_raw_os_error(libc::EPERM)))
        .unwrap_err();

    assert!(
        matches!(error, TincdError::RuntimeState(message) if message.contains("System call `mlockall` failed"))
    );
}

#[test]
fn sandbox_action_permissions_match_c_openbsd_levels() {
    tinc_test_support::assert_can_create_netns();
    assert!(sandbox_can_start_processes_after_enter(SandboxLevel::Off));
    assert!(sandbox_can_start_processes_after_enter(
        SandboxLevel::Normal
    ));
    assert!(!sandbox_can_start_processes_after_enter(SandboxLevel::High));

    let use_new_paths = !sandbox_supported_for_runtime();
    assert_eq!(
        use_new_paths,
        sandbox_can_use_new_paths_after_enter(SandboxLevel::Normal)
    );
    assert_eq!(
        use_new_paths,
        sandbox_can_use_new_paths_after_enter(SandboxLevel::High)
    );
}

#[test]
fn sandbox_off_does_not_enter_platform_sandbox_like_c_none() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("sandbox-off");
    let config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Sandbox", "off")]))
            .unwrap();
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());

    let mut called = false;
    apply_sandbox_with(&config, &options, |_| {
        called = true;
        Ok(())
    })
    .unwrap();
    assert!(!called);

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn sandbox_high_rejects_exec_proxy_like_c_start_processes_policy() {
    tinc_test_support::assert_can_create_netns();
    let mut config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("Sandbox", "off"),
        ("Proxy", "exec /usr/local/bin/tinc-proxy"),
    ]))
    .unwrap();

    config.daemon.sandbox = SandboxLevel::Normal;
    assert_eq!(Ok(()), validate_sandbox_policy(&config));

    config.daemon.sandbox = SandboxLevel::High;
    assert!(matches!(
        validate_sandbox_policy(&config),
        Err(TincdError::SandboxPolicy(message))
            if message == "Cannot use exec proxies with current sandbox level."
    ));
}

#[cfg(not(target_os = "openbsd"))]
#[test]
fn sandbox_non_off_is_rejected_without_openbsd_support_like_c_without_have_sandbox() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("sandbox-unsupported-runtime");
    let mut config =
        RuntimeConfig::from_config_tree(&config_tree(&[("Name", "alpha"), ("Sandbox", "off")]))
            .unwrap();
    config.daemon.sandbox = SandboxLevel::Normal;
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());

    assert_eq!(
        Err(TincdError::RuntimeConfig(
            RuntimeConfigError::UnsupportedSandboxLevel(SandboxLevel::Normal)
        )),
        apply_sandbox_with(&config, &options, |_| Ok(()))
    );

    fs::remove_dir_all(confbase).unwrap();
}

#[test]
fn openbsd_sandbox_profile_uses_c_runtime_paths() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("sandbox-profile");
    let config = RuntimeConfig::from_config_tree(&config_tree(&[
        ("Name", "alpha"),
        ("Sandbox", "off"),
        ("DeviceType", "fd"),
        ("Device", "/tmp/tincfd"),
        ("ScriptsInterpreter", "/bin/sh"),
        ("Proxy", "exec /usr/local/bin/tinc-proxy"),
    ]))
    .unwrap();
    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());
    options.pidfile = Some(confbase.join("custom.pid"));
    options.logfile = Some(None);

    let profile = openbsd_sandbox_profile(&config, &options);

    assert_eq!(SandboxLevel::Off, profile.level);
    assert_eq!(confbase, profile.confbase);
    assert_eq!(Some("/tmp/tincfd".to_owned()), profile.device);
    assert_eq!(Some(profile.confbase.join("log")), profile.logfile);
    assert_eq!(profile.confbase.join("custom.pid"), profile.pidfile);
    assert_eq!(profile.confbase.join("custom.socket"), profile.unix_socket);
    assert_eq!(Some("/bin/sh".to_owned()), profile.script_interpreter);
    assert_eq!(
        Some("/usr/local/bin/tinc-proxy".to_owned()),
        profile.exec_proxy_command
    );

    fs::remove_dir_all(profile.confbase).unwrap();
}

#[cfg(unix)]
#[test]
fn user_switch_without_chroot_keeps_tinc_privilege_drop_order() {
    tinc_test_support::assert_can_create_netns();
    use std::cell::RefCell;

    let calls = RefCell::new(Vec::new());
    let prepared = prepare_user_switch_with(
        Some("nobody"),
        |user| {
            calls.borrow_mut().push(format!("lookup:{user}"));
            Ok(UnixUser { uid: 42, gid: 24 })
        },
        |user, gid| {
            calls.borrow_mut().push(format!("groups:{user}:{gid}"));
            Ok(())
        },
    )
    .unwrap();
    finish_user_switch_with(prepared, |uid| {
        calls.borrow_mut().push(format!("uid:{uid}"));
        Ok(())
    })
    .unwrap();

    assert_eq!(
        vec![
            "lookup:nobody".to_owned(),
            "groups:nobody:24".to_owned(),
            "uid:42".to_owned(),
        ],
        calls.into_inner()
    );
}

#[cfg(unix)]
#[test]
fn chroot_runs_between_setgid_and_setuid_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    use std::cell::RefCell;

    let calls = RefCell::new(Vec::new());
    let prepared = prepare_user_switch_with(
        Some("nobody"),
        |user| {
            calls.borrow_mut().push(format!("lookup:{user}"));
            Ok(UnixUser { uid: 42, gid: 24 })
        },
        |user, gid| {
            calls.borrow_mut().push(format!("groups:{user}:{gid}"));
            Ok(())
        },
    )
    .unwrap();
    let chrooted = apply_chroot_with(
        true,
        Path::new("/etc/tinc/prod"),
        || calls.borrow_mut().push("tzset".to_owned()),
        |path| {
            calls
                .borrow_mut()
                .push(format!("chroot:{}", path.display()));
            Ok(())
        },
    )
    .unwrap();
    finish_user_switch_with(prepared, |uid| {
        calls.borrow_mut().push(format!("uid:{uid}"));
        Ok(())
    })
    .unwrap();

    assert!(chrooted);
    assert_eq!(
        vec![
            "lookup:nobody".to_owned(),
            "groups:nobody:24".to_owned(),
            "tzset".to_owned(),
            "chroot:/etc/tinc/prod".to_owned(),
            "uid:42".to_owned(),
        ],
        calls.into_inner()
    );
}

#[cfg(unix)]
#[test]
fn chroot_reports_tinc_style_system_call_failures_and_resets_confbase() {
    tinc_test_support::assert_can_create_netns();
    use std::cell::Cell;

    let called = Cell::new(false);
    assert!(
        !apply_chroot_with(
            false,
            Path::new("/etc/tinc"),
            || called.set(true),
            |_| Ok(())
        )
        .unwrap()
    );
    assert!(!called.get());

    let error = apply_chroot_with(
        true,
        Path::new("/etc/tinc"),
        || {},
        |_| Err(io::Error::from_raw_os_error(libc::EPERM)),
    )
    .unwrap_err();
    assert!(
        matches!(error, TincdError::RuntimeState(message) if message.contains("System call `chroot` failed"))
    );

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(PathBuf::from("/etc/tinc/prod"));
    assert_eq!(
        PathBuf::from("/etc/tinc/prod"),
        resolve_confbase(&runtime_options_after_chroot(&options, false))
    );
    assert_eq!(
        PathBuf::new(),
        resolve_confbase(&runtime_options_after_chroot(&options, true))
    );
}

#[cfg(unix)]
#[test]
fn user_switch_reports_tinc_style_system_call_failures() {
    tinc_test_support::assert_can_create_netns();
    let groups_error = prepare_user_switch_with(
        Some("nobody"),
        |_| Ok(UnixUser { uid: 42, gid: 24 }),
        |_, _| Err(io::Error::from_raw_os_error(libc::EPERM)),
    )
    .unwrap_err();
    assert!(
        matches!(groups_error, TincdError::RuntimeState(message) if message.contains("System call `initgroups` failed"))
    );

    let setuid_error = finish_user_switch_with(Some(PreparedUnixUserSwitch { uid: 42 }), |_| {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    })
    .unwrap_err();
    assert!(
        matches!(setuid_error, TincdError::RuntimeState(message) if message.contains("System call `setuid` failed"))
    );
}

#[cfg(unix)]
#[test]
fn runtime_signal_actions_match_tinc_signal_handlers() {
    tinc_test_support::assert_can_create_netns();
    assert_eq!(
        vec![
            RuntimeSignalAction::Reload(libc::SIGHUP),
            RuntimeSignalAction::Terminate(libc::SIGTERM),
            RuntimeSignalAction::Terminate(libc::SIGQUIT),
            RuntimeSignalAction::Terminate(libc::SIGINT),
            RuntimeSignalAction::Retry(libc::SIGALRM),
        ],
        runtime_signal_actions_from_bytes(&[
            libc::SIGHUP as u8,
            libc::SIGTERM as u8,
            libc::SIGQUIT as u8,
            libc::SIGINT as u8,
            libc::SIGALRM as u8,
            0,
        ])
    );
    assert_eq!("SIGHUP", runtime_signal_name(libc::SIGHUP));
    assert_eq!("SIGTERM", runtime_signal_name(libc::SIGTERM));
    assert_eq!("SIGALRM", runtime_signal_name(libc::SIGALRM));
}

#[test]
fn load_runtime_config_rejects_unsupported_sandbox_like_tincd() {
    tinc_test_support::assert_can_create_netns();
    let confbase = temp_confbase("load-runtime-sandbox");
    fs::write(
        confbase.join("tinc.conf"),
        "Name = alpha\nSandbox = normal\n",
    )
    .unwrap();
    fs::write(confbase.join("hosts").join("alpha"), "").unwrap();

    let mut options = TincdOptions::new("tincd".to_owned());
    options.confbase = Some(confbase.clone());

    assert_eq!(
        Err(TincdError::RuntimeConfig(
            RuntimeConfigError::UnsupportedSandboxLevel(SandboxLevel::Normal)
        )),
        load_runtime_config(&options)
    );

    fs::remove_dir_all(confbase).unwrap();
}
