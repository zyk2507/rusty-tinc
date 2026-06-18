use crate::*;

#[cfg(unix)]
unsafe extern "C" {
    fn tzset();
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OpenBsdSandboxProfile {
    pub(crate) level: SandboxLevel,
    pub(crate) confbase: PathBuf,
    pub(crate) device: Option<String>,
    pub(crate) logfile: Option<PathBuf>,
    pub(crate) pidfile: PathBuf,
    pub(crate) unix_socket: PathBuf,
    pub(crate) script_interpreter: Option<String>,
    pub(crate) exec_proxy_command: Option<String>,
}

pub(crate) fn openbsd_sandbox_profile(
    config: &RuntimeConfig,
    options: &TincdOptions,
) -> OpenBsdSandboxProfile {
    let pidfile = resolve_pidfile(options);
    OpenBsdSandboxProfile {
        level: config.daemon.sandbox,
        confbase: resolve_confbase(options),
        device: runtime_sandbox_device_path(config).map(str::to_owned),
        logfile: resolve_logfile(options),
        unix_socket: control_socket_path(&pidfile),
        pidfile,
        script_interpreter: config.daemon.scripts.interpreter.clone(),
        exec_proxy_command: match &config.daemon.proxy {
            ProxyConfig::Exec { command } => Some(command.clone()),
            _ => None,
        },
    }
}

pub(crate) fn runtime_sandbox_device_path(config: &RuntimeConfig) -> Option<&str> {
    if config.daemon.device.device_type == DeviceType::Dummy {
        None
    } else {
        config.daemon.device.device.as_deref()
    }
}

#[cfg(target_os = "openbsd")]
pub(crate) fn openbsd_sandbox_enter(profile: OpenBsdSandboxProfile) -> Result<(), TincdError> {
    if profile.level == SandboxLevel::Off {
        return Ok(());
    }

    let can_exec = sandbox_can_start_processes_after_enter(profile.level);
    openbsd_sandbox_paths(profile, can_exec)?;
    openbsd_pledge(
        openbsd_tincd_promises(can_exec),
        if can_exec { None } else { Some("") },
    )
}

#[cfg(target_os = "openbsd")]
pub(crate) fn openbsd_tincd_promises(can_exec: bool) -> &'static str {
    if can_exec {
        "stdio rpath wpath cpath dns inet unix proc exec"
    } else {
        "stdio rpath wpath cpath dns inet unix"
    }
}

#[cfg(target_os = "openbsd")]
pub(crate) fn openbsd_sandbox_paths(
    profile: OpenBsdSandboxProfile,
    can_exec: bool,
) -> Result<(), TincdError> {
    if profile.confbase.as_os_str().is_empty() {
        return Ok(());
    }

    openbsd_unveil(Path::new("/dev/random"), "r")?;
    openbsd_unveil(Path::new("/dev/urandom"), "r")?;
    openbsd_unveil(&profile.confbase, if can_exec { "rx" } else { "r" })?;
    if let Some(device) = profile.device {
        openbsd_unveil(Path::new(&device), "rw")?;
    }
    if let Some(logfile) = profile.logfile {
        openbsd_unveil(&logfile, "rwc")?;
    }
    openbsd_unveil(&profile.pidfile, "rwc")?;
    openbsd_unveil(&profile.unix_socket, "rwc")?;
    openbsd_unveil(&profile.confbase.join("cache"), "rwc")?;
    openbsd_unveil(
        &profile.confbase.join("hosts"),
        if can_exec { "rwxc" } else { "rwc" },
    )?;
    openbsd_unveil(&profile.confbase.join("invitations"), "rwc")?;

    if can_exec {
        for path in [
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
        ] {
            openbsd_unveil(Path::new(path), "rx")?;
        }
        if let Some(interpreter) = profile.script_interpreter {
            openbsd_unveil(Path::new(&interpreter), "rx")?;
        }
        if let Some(command) = profile.exec_proxy_command
            && command.find(char::is_whitespace).is_none()
        {
            openbsd_unveil(Path::new(&command), "rx")?;
        }
    }

    Ok(())
}

#[cfg(target_os = "openbsd")]
pub(crate) fn openbsd_unveil(path: &Path, permissions: &str) -> Result<(), TincdError> {
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        TincdError::RuntimeState(format!("invalid sandbox path {}: {error}", path.display()))
    })?;
    let permissions = CString::new(permissions).map_err(|error| {
        TincdError::RuntimeState(format!("invalid sandbox permissions: {error}"))
    })?;

    if unsafe { libc::unveil(path.as_ptr(), permissions.as_ptr()) } != 0 {
        return Err(TincdError::RuntimeState(format!(
            "unveil failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
pub(crate) fn openbsd_pledge(promises: &str, execpromises: Option<&str>) -> Result<(), TincdError> {
    let promises = CString::new(promises)
        .map_err(|error| TincdError::RuntimeState(format!("invalid pledge promises: {error}")))?;
    let execpromises = execpromises
        .map(CString::new)
        .transpose()
        .map_err(|error| TincdError::RuntimeState(format!("invalid pledge promises: {error}")))?;
    let execpromises = execpromises
        .as_ref()
        .map_or(std::ptr::null(), |promises| promises.as_ptr());

    if unsafe { libc::pledge(promises.as_ptr(), execpromises) } != 0 {
        return Err(TincdError::RuntimeState(format!(
            "pledge failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "openbsd"))]
pub(crate) fn openbsd_sandbox_enter(_profile: OpenBsdSandboxProfile) -> Result<(), TincdError> {
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnixUser {
    pub(crate) uid: libc::uid_t,
    pub(crate) gid: libc::gid_t,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PreparedUnixUserSwitch {
    pub(crate) uid: libc::uid_t,
}

#[cfg(unix)]
pub(crate) fn prepare_user_switch(
    user: Option<&str>,
) -> Result<Option<PreparedUnixUserSwitch>, TincdError> {
    prepare_user_switch_with(user, lookup_unix_user, init_groups_and_set_gid_system_call)
}

#[cfg(unix)]
pub(crate) fn prepare_user_switch_with(
    user: Option<&str>,
    lookup: impl FnOnce(&str) -> Result<UnixUser, TincdError>,
    init_groups_and_set_gid: impl FnOnce(&str, libc::gid_t) -> io::Result<()>,
) -> Result<Option<PreparedUnixUserSwitch>, TincdError> {
    let Some(user) = user else {
        return Ok(None);
    };

    let account = lookup(user)?;
    init_groups_and_set_gid(user, account.gid).map_err(|error| {
        TincdError::RuntimeState(format!("System call `initgroups` failed: {error}"))
    })?;

    Ok(Some(PreparedUnixUserSwitch { uid: account.uid }))
}

#[cfg(unix)]
pub(crate) fn finish_user_switch(
    prepared: Option<PreparedUnixUserSwitch>,
) -> Result<(), TincdError> {
    finish_user_switch_with(prepared, set_uid_system_call)
}

#[cfg(unix)]
pub(crate) fn finish_user_switch_with(
    prepared: Option<PreparedUnixUserSwitch>,
    set_uid: impl FnOnce(libc::uid_t) -> io::Result<()>,
) -> Result<(), TincdError> {
    let Some(prepared) = prepared else {
        return Ok(());
    };

    set_uid(prepared.uid)
        .map_err(|error| TincdError::RuntimeState(format!("System call `setuid` failed: {error}")))
}

#[cfg(unix)]
pub(crate) fn lookup_unix_user(user: &str) -> Result<UnixUser, TincdError> {
    let user = CString::new(user)
        .map_err(|_| TincdError::RuntimeState("unknown user `<invalid>'".to_owned()))?;
    let passwd = unsafe { libc::getpwnam(user.as_ptr()) };

    if passwd.is_null() {
        let name = user.to_string_lossy();
        return Err(TincdError::RuntimeState(format!("unknown user `{name}'")));
    }

    let passwd = unsafe { &*passwd };
    Ok(UnixUser {
        uid: passwd.pw_uid,
        gid: passwd.pw_gid,
    })
}

#[cfg(unix)]
pub(crate) fn init_groups_and_set_gid_system_call(user: &str, gid: libc::gid_t) -> io::Result<()> {
    let user = CString::new(user).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid user name: {error}"),
        )
    })?;

    if unsafe { libc::initgroups(user.as_ptr(), gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(io::Error::last_os_error());
    }

    unsafe {
        libc::endgrent();
        libc::endpwent();
    }

    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_uid_system_call(uid: libc::uid_t) -> io::Result<()> {
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(unix)]
pub(crate) fn apply_chroot(chroot: bool, confbase: &Path) -> Result<bool, TincdError> {
    apply_chroot_with(chroot, confbase, timezone_system_call, chroot_system_call)
}

#[cfg(unix)]
pub(crate) fn apply_chroot_with(
    chroot: bool,
    confbase: &Path,
    set_timezone: impl FnOnce(),
    chroot_and_chdir: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<bool, TincdError> {
    if !chroot {
        return Ok(false);
    }

    set_timezone();
    chroot_and_chdir(confbase).map_err(|error| {
        TincdError::RuntimeState(format!("System call `chroot` failed: {error}"))
    })?;
    Ok(true)
}

#[cfg(unix)]
pub(crate) fn timezone_system_call() {
    unsafe {
        tzset();
    }
}

#[cfg(unix)]
pub(crate) fn chroot_system_call(confbase: &Path) -> io::Result<()> {
    let confbase = CString::new(confbase.as_os_str().as_bytes()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid chroot path: {error}"),
        )
    })?;

    if unsafe { libc::chroot(confbase.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::chdir(b"/\0".as_ptr().cast::<libc::c_char>()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub(crate) fn runtime_options_after_chroot(options: &TincdOptions, chrooted: bool) -> TincdOptions {
    let mut options = options.clone();
    if chrooted {
        options.confbase = Some(PathBuf::new());
    }
    options
}

#[cfg(unix)]
pub(crate) fn apply_memory_lock(lock_memory: bool) -> Result<(), TincdError> {
    apply_memory_lock_with(lock_memory, memory_lock_system_call)
}

#[cfg(not(unix))]
pub(crate) fn apply_memory_lock(lock_memory: bool) -> Result<(), TincdError> {
    if lock_memory {
        return Err(TincdError::RuntimeState(
            "System call `mlockall` is not available on this platform".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn apply_memory_lock_with(
    lock_memory: bool,
    lock: impl FnOnce() -> io::Result<()>,
) -> Result<(), TincdError> {
    if !lock_memory {
        return Ok(());
    }

    lock().map_err(|error| {
        TincdError::RuntimeState(format!("System call `mlockall` failed: {error}"))
    })
}

#[cfg(unix)]
pub(crate) fn memory_lock_system_call() -> io::Result<()> {
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub(crate) fn effective_debug_level(config: &RuntimeConfig, options: &TincdOptions) -> i32 {
    let mut level = DEBUG_NOTHING;

    if let Some(option) = options.debug_level {
        level = option.unwrap_or(level + 1);
    }

    if level == DEBUG_NOTHING {
        config.daemon.log_level.unwrap_or(DEBUG_NOTHING)
    } else {
        level
    }
}

pub(crate) fn runtime_local_port(
    config: &RuntimeConfig,
    listen_sockets: &[RuntimeListenSocket],
) -> String {
    let configured_port = config.daemon.port.parse::<u16>().ok();
    if (configured_port == Some(0) || !config.daemon.port_specified)
        && let Some(socket) = listen_sockets.first()
    {
        return socket.info().address.port().to_string();
    }

    runtime_local_port_from_config(config)
}

pub(crate) fn runtime_local_port_from_config(config: &RuntimeConfig) -> String {
    if let Ok(port) = config.daemon.port.parse::<u16>() {
        return port.to_string();
    }
    if let Ok(targets) = resolve_named_listen_targets(
        "localhost",
        &config.daemon.port,
        config.daemon.address_family,
    ) && let Some(target) = targets.first()
    {
        return target.port().to_string();
    }

    config.daemon.port.clone()
}

pub(crate) fn systemd_listen_pid_matches_current_process_env() -> bool {
    let value = env::var("LISTEN_PID").ok();
    let matches = systemd_listen_pid_matches_current_process(value.as_deref(), std::process::id());
    if value.is_some() {
        // SAFETY: tincd consumes LISTEN_PID during single-threaded startup, matching
        // C tinc's unsetenv("LISTEN_PID") after the activation check.
        unsafe {
            env::remove_var("LISTEN_PID");
        }
    }
    matches
}

pub(crate) fn systemd_listen_pid_matches_current_process(value: Option<&str>, pid: u32) -> bool {
    value
        .and_then(|value| value.trim().parse::<u32>().ok())
        .is_some_and(|listen_pid| listen_pid == pid)
}

#[cfg(unix)]
pub(crate) fn systemd_listen_fds_env() -> Option<usize> {
    parse_systemd_listen_fds(env::var("LISTEN_FDS").ok().as_deref())
}

pub(crate) fn parse_systemd_listen_fds(value: Option<&str>) -> Option<usize> {
    value.and_then(|value| value.trim().parse::<usize>().ok())
}

#[cfg(unix)]
pub(crate) fn unset_systemd_activation_env() {
    // SAFETY: tincd mutates process-wide activation variables during single-threaded
    // startup, matching C tinc's unsetenv() cleanup after consuming them.
    unsafe {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
    }
}

#[cfg(unix)]
pub(crate) fn systemd_notify(message: &str) {
    let Some(socket) = env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let path = PathBuf::from(socket);
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        return;
    }

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return;
    }

    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let mut length = std::mem::size_of_val(&address.sun_family) as libc::socklen_t
        + bytes.len() as libc::socklen_t;

    if bytes[0] == b'@' {
        if bytes.len() > address.sun_path.len() {
            unsafe {
                libc::close(fd);
            }
            return;
        }
        address.sun_path[0] = 0;
        for (index, byte) in bytes.iter().enumerate().skip(1) {
            address.sun_path[index] = *byte as libc::c_char;
        }
    } else {
        if bytes.len() >= address.sun_path.len() {
            unsafe {
                libc::close(fd);
            }
            return;
        }
        for (index, byte) in bytes.iter().enumerate() {
            address.sun_path[index] = *byte as libc::c_char;
        }
        length += 1;
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    let flags = libc::MSG_NOSIGNAL;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let flags = 0;

    unsafe {
        libc::sendto(
            fd,
            message.as_bytes().as_ptr().cast(),
            message.len(),
            flags,
            (&address as *const libc::sockaddr_un).cast(),
            length,
        );
        libc::close(fd);
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeWatchdog {
    pub(crate) interval: Duration,
    pub(crate) next_ping: Instant,
}

#[cfg(unix)]
impl RuntimeWatchdog {
    pub(crate) fn from_env() -> Self {
        let timeout = parse_systemd_watchdog_usec(env::var("WATCHDOG_USEC").ok().as_deref());
        let enabled = systemd_watchdog_pid_matches_current_process(
            env::var("WATCHDOG_PID").ok().as_deref(),
            std::process::id(),
        ) && timeout.is_some();
        let timeout = timeout.filter(|_| enabled);
        Self::from_timeout(timeout, Instant::now())
    }

    pub(crate) fn from_timeout(timeout: Option<Duration>, now: Instant) -> Self {
        let interval = timeout
            .map(|timeout| timeout.div_f64(2.0))
            .filter(|interval| !interval.is_zero())
            .unwrap_or(Duration::ZERO);
        Self {
            interval,
            next_ping: now + interval,
        }
    }

    pub(crate) fn start(&mut self, runtime: &mut RuntimeDaemonState) {
        systemd_notify("READY=1");
        if self.interval.is_zero() {
            runtime.record_log_with_priority(0, LOG_INFO, "Watchdog is disabled");
        } else {
            if self.interval < Duration::from_secs(1) {
                runtime.record_log_with_priority(
                    0,
                    LOG_WARNING,
                    "Consider using a higher watchdog timeout. Spurious failures may occur.",
                );
            }
            systemd_notify("WATCHDOG=1");
            self.next_ping = Instant::now() + self.interval;
            runtime.record_log_with_priority(0, LOG_INFO, "Watchdog started");
        }
    }

    pub(crate) fn maybe_ping(&mut self, now: Instant) {
        if self.interval.is_zero() || now < self.next_ping {
            return;
        }

        systemd_notify("WATCHDOG=1");
        self.next_ping = now + self.interval;
    }

    pub(crate) fn stop(&self) {
        systemd_notify("STOPPING=1");
    }
}

pub(crate) fn parse_systemd_watchdog_usec(value: Option<&str>) -> Option<Duration> {
    let micros = value?.trim().parse::<u64>().ok()?;
    if micros == 0 {
        None
    } else {
        Some(Duration::from_micros(micros))
    }
}

pub(crate) fn systemd_watchdog_pid_matches_current_process(value: Option<&str>, pid: u32) -> bool {
    value
        .and_then(|value| value.trim().parse::<u32>().ok())
        .map(|watchdog_pid| watchdog_pid == 0 || watchdog_pid == pid)
        .unwrap_or(true)
}
