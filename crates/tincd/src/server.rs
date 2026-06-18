use crate::*;

#[cfg(unix)]
pub fn run_foreground_server(
    config: &RuntimeConfig,
    endpoint: &ControlEndpoint,
    keys: RuntimeKeys,
    options: &TincdOptions,
) -> Result<(), TincdError> {
    let mut config = runtime_config_for_keys(config, &keys);
    apply_memory_lock(options.lock_memory)?;
    let listen_sockets = match bind_runtime_listeners(&config) {
        Ok(sockets) => sockets,
        Err(error) => {
            write_startup_error_to_umbilical_like_tinc(&error);
            return Err(error);
        }
    };
    let mut runtime = RuntimeDaemonState::new_configured(listen_sockets, &config, keys)?;
    runtime.set_bypass_security(options.bypass_security);
    runtime.set_debug_level(effective_debug_level(&config, options));
    if options.use_syslog {
        runtime.enable_syslog()?;
    } else if let Some(logfile) = resolve_logfile(options) {
        runtime.enable_logfile(&logfile)?;
    } else {
        runtime.enable_stderr_log(stderr_supports_ansi_escapes());
    }
    runtime.enable_umbilical_log_from_env();
    apply_process_priority(config.daemon.process_priority)?;
    let runtime_endpoint = endpoint.for_runtime_listeners(&runtime.listen_sockets);
    write_control_pidfile(&runtime_endpoint)?;
    let control_listener = match bind_control_socket(endpoint) {
        Ok(listener) => listener,
        Err(error) => {
            remove_control_files(&runtime_endpoint);
            return Err(error);
        }
    };
    let prepared_user = prepare_user_switch(options.user.as_deref())?;
    let chrooted = apply_chroot(options.chroot, &resolve_confbase(options))?;
    let runtime_options = runtime_options_after_chroot(options, chrooted);
    finish_user_switch(prepared_user)?;
    let runtime_confbase = resolve_confbase(&runtime_options);
    runtime.set_confbase(runtime_confbase.clone());
    runtime.enable_scripts(&config, &runtime_options);
    runtime.enable_invitations(runtime_confbase, &config)?;

    let signals = RuntimeSignalHandlers::install()?;

    let result = control_listener
        .set_nonblocking(true)
        .map_err(control_io)
        .and_then(|()| {
            if !runtime.device_standby {
                runtime
                    .device
                    .enable()
                    .map_err(|error| device_error("enable", error))?;
                run_daemon_script(
                    "tinc-up",
                    &config,
                    &runtime_options,
                    runtime.device.info(),
                    &[],
                )?;
            }
            runtime.run_local_subnet_up_scripts();
            apply_sandbox(&config, &runtime_options)?;
            initialize_upnp_like_tinc(&mut runtime, &config);
            runtime.record_log_with_priority(0, LOG_NOTICE, "Ready");
            runtime.notify_umbilical_success_and_close()?;
            runtime.retry_configured_peers(&config)?;
            Ok(())
        })
        .and_then(|()| {
            run_foreground_event_loop(
                &mut config,
                &runtime_endpoint,
                &control_listener,
                &mut runtime,
                &runtime_options,
                &signals,
            )
        });
    let down_result = if runtime.device_standby {
        Ok(false)
    } else {
        run_daemon_script(
            "tinc-down",
            &config,
            &runtime_options,
            runtime.device.info(),
            &[],
        )
        .and_then(|_| {
            runtime
                .device
                .disable()
                .map_err(|error| device_error("disable", error))
                .map(|_| true)
        })
    };
    remove_control_files(&runtime_endpoint);
    result.and(down_result.map(|_| ()))
}

#[cfg(unix)]
pub(crate) fn write_startup_error_to_umbilical_like_tinc(error: &TincdError) {
    let Some(mut sink) = RuntimeUmbilicalLogSink::from_env() else {
        return;
    };
    sink.write_log(LOG_ERR, error.to_string().as_str());
}

#[cfg(not(unix))]
pub(crate) fn write_startup_error_to_umbilical_like_tinc(_error: &TincdError) {}

#[cfg(not(unix))]
pub fn run_foreground_server(
    config: &RuntimeConfig,
    endpoint: &ControlEndpoint,
    keys: RuntimeKeys,
    options: &TincdOptions,
) -> Result<(), TincdError> {
    let mut config = runtime_config_for_keys(config, &keys);
    apply_memory_lock(options.lock_memory)?;
    let listen_sockets = match bind_runtime_listeners(&config) {
        Ok(sockets) => sockets,
        Err(error) => {
            write_startup_error_to_umbilical_like_tinc(&error);
            return Err(error);
        }
    };
    let mut runtime = RuntimeDaemonState::new_configured(listen_sockets, &config, keys)?;
    runtime.set_bypass_security(options.bypass_security);
    runtime.set_debug_level(effective_debug_level(&config, options));
    if let Some(logfile) = resolve_logfile(options) {
        runtime.enable_logfile(&logfile)?;
    } else {
        runtime.enable_stderr_log(false);
    }
    apply_process_priority(config.daemon.process_priority)?;

    let control_listener = bind_tcp_control_socket(endpoint)?;
    let runtime_endpoint = endpoint.for_tcp_control_listener(&control_listener)?;
    write_control_pidfile(&runtime_endpoint)?;

    let runtime_confbase = resolve_confbase(options);
    runtime.set_confbase(runtime_confbase.clone());
    runtime.enable_scripts(&config, options);
    runtime.enable_invitations(runtime_confbase, &config)?;

    let result = control_listener
        .set_nonblocking(true)
        .map_err(control_io)
        .and_then(|()| {
            if !runtime.device_standby {
                runtime
                    .device
                    .enable()
                    .map_err(|error| device_error("enable", error))?;
                run_daemon_script("tinc-up", &config, options, runtime.device.info(), &[])?;
            }
            runtime.run_local_subnet_up_scripts();
            apply_sandbox(&config, options)?;
            initialize_upnp_like_tinc(&mut runtime, &config);
            runtime.record_log_with_priority(0, LOG_NOTICE, "Ready");
            notify_umbilical_success()?;
            runtime.retry_configured_peers(&config)?;
            Ok(())
        })
        .and_then(|()| {
            run_tcp_foreground_event_loop(
                &mut config,
                &runtime_endpoint,
                &control_listener,
                &mut runtime,
                options,
            )
        });
    let down_result = if runtime.device_standby {
        Ok(false)
    } else {
        run_daemon_script("tinc-down", &config, options, runtime.device.info(), &[]).and_then(
            |_| {
                runtime
                    .device
                    .disable()
                    .map_err(|error| device_error("disable", error))
                    .map(|_| true)
            },
        )
    };
    remove_control_files(&runtime_endpoint);
    result.and(down_result.map(|_| ()))
}

#[cfg(unix)]
pub fn run_daemon_server(
    config: &RuntimeConfig,
    endpoint: &ControlEndpoint,
    keys: RuntimeKeys,
    options: &TincdOptions,
) -> Result<(), TincdError> {
    detach_process_like_tinc()?;
    let mut endpoint = endpoint.clone();
    endpoint.pid = std::process::id();
    let runtime_options = daemon_runtime_options_like_tinc(options);
    run_foreground_server(config, &endpoint, keys, &runtime_options)
}

#[cfg(not(unix))]
pub fn run_daemon_server(
    _config: &RuntimeConfig,
    _endpoint: &ControlEndpoint,
    _keys: RuntimeKeys,
    _options: &TincdOptions,
) -> Result<(), TincdError> {
    Err(TincdError::ControlIo(
        "Windows service runtime is not implemented yet".to_owned(),
    ))
}

#[cfg(unix)]
pub(crate) fn detach_process_like_tinc() -> Result<(), TincdError> {
    ignore_detached_signals_like_tinc();
    if unsafe { libc::daemon(1, 0) } != 0 {
        return Err(TincdError::RuntimeState(format!(
            "Couldn't detach from terminal: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn ignore_detached_signals_like_tinc() {
    for signal in [libc::SIGPIPE, libc::SIGUSR1, libc::SIGUSR2, libc::SIGWINCH] {
        unsafe {
            libc::signal(signal, libc::SIG_IGN);
        }
    }
}

#[cfg(unix)]
pub(crate) fn daemon_runtime_options_like_tinc(options: &TincdOptions) -> TincdOptions {
    let mut options = options.clone();
    if options.logfile.is_none() {
        options.use_syslog = true;
    }
    options
}

#[cfg(unix)]
pub(crate) fn run_foreground_event_loop(
    config: &mut RuntimeConfig,
    endpoint: &ControlEndpoint,
    control_listener: &std::os::unix::net::UnixListener,
    runtime: &mut RuntimeDaemonState,
    options: &TincdOptions,
    signals: &RuntimeSignalHandlers,
) -> Result<(), TincdError> {
    let mut next_autoconnect_check = Instant::now() + AUTOCONNECT_INTERVAL;
    let mut watchdog = RuntimeWatchdog::from_env();
    watchdog.start(runtime);

    let result = (|| -> Result<(), TincdError> {
        loop {
            watchdog.maybe_ping(Instant::now());

            if handle_runtime_signal_actions(config, runtime, options, signals)? {
                return Ok(());
            }

            if accept_control_connections(
                config,
                endpoint,
                control_listener,
                Some(&mut *runtime),
                Some(options),
            )? {
                return Ok(());
            }

            let did_work = runtime.poll_once()?;
            let retried = runtime.retry_configured_peers(config)? > 0;
            let autoconnected = if config.autoconnect && Instant::now() >= next_autoconnect_check {
                next_autoconnect_check = Instant::now() + AUTOCONNECT_INTERVAL;
                runtime.do_autoconnect_like_tinc(config)? > 0
            } else {
                false
            };
            if !did_work && !retried && !autoconnected {
                thread::sleep(FOREGROUND_IDLE_SLEEP);
            }
        }
    })();

    watchdog.stop();
    result
}

#[cfg(not(unix))]
pub(crate) fn run_tcp_foreground_event_loop(
    config: &mut RuntimeConfig,
    endpoint: &ControlEndpoint,
    control_listener: &TcpListener,
    runtime: &mut RuntimeDaemonState,
    options: &TincdOptions,
) -> Result<(), TincdError> {
    let mut next_autoconnect_check = Instant::now() + AUTOCONNECT_INTERVAL;

    loop {
        if accept_tcp_control_connections(
            config,
            endpoint,
            control_listener,
            Some(&mut *runtime),
            Some(options),
        )? {
            return Ok(());
        }

        let did_work = runtime.poll_once()?;
        let retried = runtime.retry_configured_peers(config)? > 0;
        let autoconnected = if config.autoconnect && Instant::now() >= next_autoconnect_check {
            next_autoconnect_check = Instant::now() + AUTOCONNECT_INTERVAL;
            runtime.do_autoconnect_like_tinc(config)? > 0
        } else {
            false
        };
        if !did_work && !retried && !autoconnected {
            thread::sleep(FOREGROUND_IDLE_SLEEP);
        }
    }
}

#[cfg(unix)]
pub(crate) fn handle_runtime_signal_actions(
    config: &mut RuntimeConfig,
    runtime: &mut RuntimeDaemonState,
    options: &TincdOptions,
    signals: &RuntimeSignalHandlers,
) -> Result<bool, TincdError> {
    for action in signals.drain_actions()? {
        match action {
            RuntimeSignalAction::Terminate(signal) => {
                runtime.record_log_with_priority(
                    0,
                    LOG_NOTICE,
                    format!("Got {} signal", runtime_signal_name(signal)),
                );
                return Ok(true);
            }
            RuntimeSignalAction::Reload(signal) => {
                runtime.record_log_with_priority(
                    0,
                    LOG_NOTICE,
                    format!("Got {} signal", runtime_signal_name(signal)),
                );
                runtime.reopen_logger();
                reload_runtime_config(config, runtime, options)?;
            }
            RuntimeSignalAction::Retry(signal) => {
                runtime.record_log_with_priority(
                    0,
                    LOG_NOTICE,
                    format!("Got {} signal", runtime_signal_name(signal)),
                );
                runtime.retry_configured_peers_now(config)?;
            }
        }
    }

    Ok(false)
}

#[cfg(unix)]
pub(crate) fn accept_control_connections(
    config: &mut RuntimeConfig,
    endpoint: &ControlEndpoint,
    listener: &std::os::unix::net::UnixListener,
    mut runtime: Option<&mut RuntimeDaemonState>,
    reload_options: Option<&TincdOptions>,
) -> Result<bool, TincdError> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let name = config.name.clone();
                if handle_control_stream(
                    stream,
                    &name,
                    endpoint,
                    Some(config),
                    runtime.as_deref_mut(),
                    reload_options,
                )? {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(control_io(error)),
        }
    }
}

#[cfg(unix)]
pub fn run_control_server(
    config: &RuntimeConfig,
    endpoint: &ControlEndpoint,
) -> Result<(), TincdError> {
    let mut config = config.clone();
    write_control_pidfile(endpoint)?;
    let listener = match bind_control_socket(endpoint) {
        Ok(listener) => listener,
        Err(error) => {
            remove_control_files(endpoint);
            return Err(error);
        }
    };
    notify_umbilical_success()?;

    let result = loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let name = config.name.clone();
                if handle_control_stream(stream, &name, endpoint, Some(&mut config), None, None)? {
                    break Ok(());
                }
            }
            Err(error) => break Err(control_io(error)),
        }
    };

    remove_control_files(endpoint);
    result
}

#[cfg(not(unix))]
pub fn run_control_server(
    config: &RuntimeConfig,
    endpoint: &ControlEndpoint,
) -> Result<(), TincdError> {
    run_tcp_control_server(config, endpoint)
}

#[cfg(unix)]
pub fn bind_control_socket(
    endpoint: &ControlEndpoint,
) -> Result<std::os::unix::net::UnixListener, TincdError> {
    use std::os::unix::net::UnixListener;

    let _ = fs::remove_file(&endpoint.socket);
    UnixListener::bind(&endpoint.socket).map_err(control_io)
}

pub fn run_tcp_control_server(
    config: &RuntimeConfig,
    endpoint: &ControlEndpoint,
) -> Result<(), TincdError> {
    let listener = bind_tcp_control_socket(endpoint)?;
    run_tcp_control_server_on_listener(config, endpoint, listener)
}

pub(crate) fn bind_tcp_control_socket(
    endpoint: &ControlEndpoint,
) -> Result<TcpListener, TincdError> {
    let targets = resolve_control_listener_addresses(&endpoint.host, &endpoint.port)?;
    let mut last_error = None;

    for target in targets {
        match TcpListener::bind(target) {
            Ok(listener) => return Ok(listener),
            Err(error) => last_error = Some(error),
        }
    }

    Err(TincdError::ControlIo(
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| {
                format!("could not resolve {} port {}", endpoint.host, endpoint.port)
            }),
    ))
}

pub(crate) fn resolve_control_listener_addresses(
    host: &str,
    port: &str,
) -> Result<Vec<SocketAddr>, TincdError> {
    if let Ok(port) = port.parse::<u16>() {
        return (host, port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
            .map_err(control_io);
    }

    resolve_named_listen_targets(host, port, ListenAddressFamily::Any)
}

pub(crate) fn run_tcp_control_server_on_listener(
    config: &RuntimeConfig,
    endpoint: &ControlEndpoint,
    listener: TcpListener,
) -> Result<(), TincdError> {
    let mut config = config.clone();
    let endpoint = endpoint.for_tcp_control_listener(&listener)?;
    write_control_pidfile(&endpoint)?;
    notify_umbilical_success()?;

    let result = loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let name = config.name.clone();
                if handle_control_tcp_stream(
                    stream,
                    &name,
                    &endpoint,
                    Some(&mut config),
                    None,
                    None,
                )? {
                    break Ok(());
                }
            }
            Err(error) => break Err(control_io(error)),
        }
    };

    remove_control_files(&endpoint);
    result
}

#[cfg_attr(unix, allow(dead_code))]
pub(crate) fn accept_tcp_control_connections(
    config: &mut RuntimeConfig,
    endpoint: &ControlEndpoint,
    listener: &TcpListener,
    mut runtime: Option<&mut RuntimeDaemonState>,
    reload_options: Option<&TincdOptions>,
) -> Result<bool, TincdError> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let name = config.name.clone();
                if handle_control_tcp_stream(
                    stream,
                    &name,
                    endpoint,
                    Some(config),
                    runtime.as_deref_mut(),
                    reload_options,
                )? {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(control_io(error)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControlStreamResponse {
    pub(crate) bytes: Vec<u8>,
    pub(crate) close_after_write: bool,
}

impl ControlStreamResponse {
    pub(crate) fn text(text: String) -> Self {
        Self {
            bytes: text.into_bytes(),
            close_after_write: false,
        }
    }

    pub(crate) fn stream(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            close_after_write: true,
        }
    }
}

pub(crate) trait ControlStream: Read + Write {
    fn clone_read(&self) -> io::Result<Box<dyn BufRead>>;
    fn clone_write(&self) -> io::Result<Box<dyn Write + Send>>;
}

impl ControlStream for TcpStream {
    fn clone_read(&self) -> io::Result<Box<dyn BufRead>> {
        self.try_clone()
            .map(|stream| Box::new(BufReader::new(stream)) as Box<dyn BufRead>)
    }

    fn clone_write(&self) -> io::Result<Box<dyn Write + Send>> {
        self.try_clone()
            .map(|stream| Box::new(stream) as Box<dyn Write + Send>)
    }
}

#[cfg(unix)]
impl ControlStream for std::os::unix::net::UnixStream {
    fn clone_read(&self) -> io::Result<Box<dyn BufRead>> {
        self.try_clone()
            .map(|stream| Box::new(BufReader::new(stream)) as Box<dyn BufRead>)
    }

    fn clone_write(&self) -> io::Result<Box<dyn Write + Send>> {
        self.try_clone()
            .map(|stream| Box::new(stream) as Box<dyn Write + Send>)
    }
}

pub(crate) fn handle_control_io<S: ControlStream>(
    stream: S,
    name: &str,
    endpoint: &ControlEndpoint,
    mut config: Option<&mut RuntimeConfig>,
    mut runtime: Option<&mut RuntimeDaemonState>,
    reload_options: Option<&TincdOptions>,
) -> Result<bool, TincdError> {
    let mut stream = stream;
    let mut reader = stream.clone_read().map_err(control_io)?;
    let id = Request::Id.number();
    let ack = Request::Ack.number();

    writeln!(stream, "{id} {name} {PROT_MAJOR}.{PROT_MINOR}").map_err(control_io)?;
    stream.flush().map_err(control_io)?;

    let auth = read_control_line(&mut reader)?;
    let fields = auth.split_whitespace().collect::<Vec<_>>();

    if fields.len() != 3
        || fields[0].parse::<i32>().ok() != Some(id)
        || fields[1] != format!("^{}", endpoint.cookie)
        || fields[2].parse::<i32>().ok() != Some(TINC_CTL_VERSION_CURRENT)
    {
        return Err(TincdError::ControlHandshake(auth));
    }

    writeln!(stream, "{ack} {TINC_CTL_VERSION_CURRENT} {}", endpoint.pid).map_err(control_io)?;
    stream.flush().map_err(control_io)?;

    let mut should_stop = false;

    loop {
        let line = match read_control_line(&mut reader) {
            Ok(line) => line,
            Err(TincdError::ControlIo(_)) => break,
            Err(error) => return Err(error),
        };

        if let Some(runtime) = runtime.as_deref_mut()
            && register_control_live_stream_request(&line, runtime, &stream)?
        {
            break;
        }

        let Some(response) = handle_control_stream_request_line_mut(
            &line,
            &mut should_stop,
            config.as_deref_mut(),
            runtime.as_deref_mut(),
            reload_options,
        ) else {
            break;
        };
        stream.write_all(&response.bytes).map_err(control_io)?;
        stream.flush().map_err(control_io)?;

        if should_stop || response.close_after_write {
            break;
        }
    }

    Ok(should_stop)
}

#[cfg(unix)]
pub fn handle_control_stream(
    stream: std::os::unix::net::UnixStream,
    name: &str,
    endpoint: &ControlEndpoint,
    config: Option<&mut RuntimeConfig>,
    runtime: Option<&mut RuntimeDaemonState>,
    reload_options: Option<&TincdOptions>,
) -> Result<bool, TincdError> {
    handle_control_io(stream, name, endpoint, config, runtime, reload_options)
}

pub fn handle_control_tcp_stream(
    stream: TcpStream,
    name: &str,
    endpoint: &ControlEndpoint,
    config: Option<&mut RuntimeConfig>,
    runtime: Option<&mut RuntimeDaemonState>,
    reload_options: Option<&TincdOptions>,
) -> Result<bool, TincdError> {
    handle_control_io(stream, name, endpoint, config, runtime, reload_options)
}

pub(crate) fn register_control_live_stream_request<S: ControlStream>(
    line: &str,
    runtime: &mut RuntimeDaemonState,
    stream: &S,
) -> Result<bool, TincdError> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let control = Request::Control.number();

    if fields.len() < 2 || fields[0].parse::<i32>().ok() != Some(control) {
        return Ok(false);
    }

    match fields[1].parse::<i32>().ok() {
        Some(REQ_LOG) => {
            let level = fields
                .get(2)
                .and_then(|value| value.parse::<i32>().ok())
                .unwrap_or(DEBUG_UNSET);
            let colorize = fields
                .get(3)
                .and_then(|value| value.parse::<i32>().ok())
                .is_some_and(|value| value != 0);
            runtime.register_control_log_subscriber(
                level,
                colorize,
                stream.clone_write().map_err(control_io)?,
            )?;
            Ok(true)
        }
        Some(REQ_PCAP) => {
            let snaplen = fields
                .get(2)
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or_default();
            runtime.register_control_pcap_subscriber(
                snaplen,
                stream.clone_write().map_err(control_io)?,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub fn handle_control_request_line(
    line: &str,
    should_stop: &mut bool,
    config: Option<&RuntimeConfig>,
    runtime: Option<&mut RuntimeDaemonState>,
) -> Option<String> {
    let mut config = config.cloned();
    handle_control_request_line_mut(line, should_stop, config.as_mut(), runtime, None)
}

pub(crate) fn handle_control_request_line_mut(
    line: &str,
    should_stop: &mut bool,
    config: Option<&mut RuntimeConfig>,
    runtime: Option<&mut RuntimeDaemonState>,
    reload_options: Option<&TincdOptions>,
) -> Option<String> {
    handle_control_stream_request_line_mut(line, should_stop, config, runtime, reload_options)
        .map(|response| String::from_utf8_lossy(&response.bytes).into_owned())
}

pub(crate) fn handle_control_stream_request_line_mut(
    line: &str,
    should_stop: &mut bool,
    mut config: Option<&mut RuntimeConfig>,
    mut runtime: Option<&mut RuntimeDaemonState>,
    reload_options: Option<&TincdOptions>,
) -> Option<ControlStreamResponse> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let control = Request::Control.number();

    if fields.len() < 2 || fields[0].parse::<i32>().ok()? != control {
        return None;
    }

    let request = fields[1].parse::<i32>().ok()?;

    match request {
        REQ_STOP => {
            *should_stop = true;
            Some(ControlStreamResponse::text(format!(
                "{control} {REQ_STOP} 0\n"
            )))
        }
        REQ_DUMP_NODES => config.as_deref().map(|config| {
            ControlStreamResponse::text(dump_nodes(
                config,
                runtime_state(config, runtime.as_deref()),
                runtime.as_deref(),
            ))
        }),
        REQ_DUMP_EDGES => config.as_deref().map(|config| {
            ControlStreamResponse::text(dump_edges(runtime_state(config, runtime.as_deref())))
        }),
        REQ_DUMP_SUBNETS => config.as_deref().map(|config| {
            ControlStreamResponse::text(dump_subnets(runtime_state(config, runtime.as_deref())))
        }),
        REQ_DUMP_CONNECTIONS => Some(ControlStreamResponse::text(dump_connections(
            runtime.as_deref(),
        ))),
        REQ_DUMP_TRAFFIC => config.as_deref().map(|config| {
            ControlStreamResponse::text(dump_traffic(
                runtime_state(config, runtime.as_deref()),
                runtime.as_deref(),
            ))
        }),
        REQ_PCAP => Some(ControlStreamResponse::stream(handle_control_pcap_request(
            &fields,
            runtime.as_deref(),
        ))),
        REQ_LOG => Some(ControlStreamResponse::stream(handle_control_log_request(
            &fields,
            runtime.as_deref(),
        ))),
        REQ_RELOAD => Some(ControlStreamResponse::text(handle_control_reload_request(
            config.as_deref_mut(),
            runtime.as_deref_mut(),
            reload_options,
        ))),
        REQ_PURGE => Some(ControlStreamResponse::text(handle_control_purge_request(
            config.as_deref(),
            runtime.as_deref_mut(),
        ))),
        REQ_SET_DEBUG => Some(ControlStreamResponse::text(
            handle_control_set_debug_request(fields.get(2).copied(), runtime.as_deref_mut())?,
        )),
        REQ_RETRY => Some(ControlStreamResponse::text(handle_control_retry_request(
            config.as_deref(),
            runtime.as_deref_mut(),
        ))),
        REQ_DISCONNECT => Some(ControlStreamResponse::text(
            handle_control_disconnect_request(fields.get(2).copied(), runtime.as_deref_mut()),
        )),
        _ => Some(ControlStreamResponse::text(format!("{control} -1\n"))),
    }
}

pub(crate) fn handle_control_retry_request(
    config: Option<&RuntimeConfig>,
    runtime: Option<&mut RuntimeDaemonState>,
) -> String {
    let control = Request::Control.number();
    let (Some(config), Some(runtime)) = (config, runtime) else {
        return format!("{control} {REQ_RETRY} 0\n");
    };

    match runtime.retry_configured_peers_now(config) {
        Ok(_) => format!("{control} {REQ_RETRY} 0\n"),
        Err(_) => format!("{control} {REQ_RETRY} -1\n"),
    }
}

pub(crate) fn handle_control_reload_request(
    config: Option<&mut RuntimeConfig>,
    runtime: Option<&mut RuntimeDaemonState>,
    options: Option<&TincdOptions>,
) -> String {
    let control = Request::Control.number();
    let (Some(config), Some(runtime), Some(options)) = (config, runtime, options) else {
        return format!("{control} {REQ_RELOAD} 0\n");
    };

    runtime.record_log_with_priority(0, LOG_NOTICE, "Got 'reload' command");

    match reload_runtime_config(config, runtime, options) {
        Ok(_) => format!("{control} {REQ_RELOAD} 0\n"),
        Err(_) => format!("{control} {REQ_RELOAD} -1\n"),
    }
}

pub(crate) fn reload_runtime_config(
    config: &mut RuntimeConfig,
    runtime: &mut RuntimeDaemonState,
    options: &TincdOptions,
) -> Result<(), TincdError> {
    let mut new_config = load_runtime_config(options)?;
    let keys = load_runtime_keys(options)?;
    reconcile_runtime_config_with_keys(&mut new_config, &keys);
    runtime.apply_reloaded_config(&new_config, keys)?;
    let confbase = resolve_confbase(options);
    runtime.set_confbase(confbase.clone());
    runtime.enable_invitations(confbase, &new_config)?;
    *config = new_config;
    runtime.retry_configured_peers_now(config)?;
    Ok(())
}

pub(crate) fn handle_control_purge_request(
    config: Option<&RuntimeConfig>,
    runtime: Option<&mut RuntimeDaemonState>,
) -> String {
    let control = Request::Control.number();
    let (Some(config), Some(runtime)) = (config, runtime) else {
        return format!("{control} {REQ_PURGE} 0\n");
    };

    runtime.purge_unreachable(config);
    format!("{control} {REQ_PURGE} 0\n")
}

pub(crate) fn handle_control_disconnect_request(
    peer: Option<&str>,
    runtime: Option<&mut RuntimeDaemonState>,
) -> String {
    let control = Request::Control.number();
    let Some(peer) = peer else {
        return format!("{control} {REQ_DISCONNECT} -1\n");
    };
    let Some(runtime) = runtime else {
        return format!("{control} {REQ_DISCONNECT} -2\n");
    };

    match runtime.disconnect_peer(peer) {
        Ok(true) => format!("{control} {REQ_DISCONNECT} 0\n"),
        Ok(false) | Err(_) => format!("{control} {REQ_DISCONNECT} -2\n"),
    }
}

pub(crate) fn handle_control_set_debug_request(
    level: Option<&str>,
    runtime: Option<&mut RuntimeDaemonState>,
) -> Option<String> {
    let level = level?.parse::<i32>().ok()?;
    let control = Request::Control.number();
    let old_level = runtime
        .as_deref()
        .map(RuntimeDaemonState::debug_level)
        .unwrap_or(DEBUG_NOTHING);

    if level >= 0
        && let Some(runtime) = runtime
    {
        runtime.set_debug_level(level);
    }

    Some(format!("{control} {REQ_SET_DEBUG} {old_level}\n"))
}

pub(crate) fn handle_control_log_request(
    fields: &[&str],
    runtime: Option<&RuntimeDaemonState>,
) -> Vec<u8> {
    let level = fields
        .get(2)
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(-1);
    let colorize = fields
        .get(3)
        .and_then(|value| value.parse::<i32>().ok())
        .is_some_and(|value| value != 0);
    let entries = runtime
        .map(|runtime| runtime.control_log_entries(level, colorize))
        .unwrap_or_default();

    encode_control_payload_chunks(
        REQ_LOG,
        entries.iter().map(|entry| {
            let bytes = entry.as_bytes();
            &bytes[..bytes.len().min(LOG_CONTROL_BUFFER_SIZE)]
        }),
    )
}

pub(crate) fn handle_control_pcap_request(
    fields: &[&str],
    runtime: Option<&RuntimeDaemonState>,
) -> Vec<u8> {
    let snaplen = fields
        .get(2)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    let packets = runtime
        .map(|runtime| runtime.control_pcap_packets(snaplen))
        .unwrap_or_default();

    encode_control_payload_chunks(REQ_PCAP, packets.iter().map(Vec::as_slice))
}

pub(crate) fn encode_control_payload_chunks<'a>(
    request: i32,
    chunks: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<u8> {
    let control = Request::Control.number();
    let mut output = Vec::new();

    for chunk in chunks {
        output.extend_from_slice(format!("{control} {request} {}\n", chunk.len()).as_bytes());
        output.extend_from_slice(chunk);
    }

    output
}

pub(crate) fn runtime_state<'a>(
    config: &'a RuntimeConfig,
    runtime: Option<&'a RuntimeDaemonState>,
) -> &'a NetworkState {
    runtime
        .map(RuntimeDaemonState::state)
        .unwrap_or(&config.state)
}

pub(crate) fn dump_nodes(
    config: &RuntimeConfig,
    state: &NetworkState,
    runtime: Option<&RuntimeDaemonState>,
) -> String {
    let control = Request::Control.number();
    let mut output = String::new();

    for node in state.graph.nodes() {
        let (host, port) = node_host_port(
            config,
            node,
            runtime.as_ref().map(|runtime| runtime.local_port.as_str()),
            runtime
                .map(|runtime| runtime.hostnames)
                .unwrap_or(config.daemon.hostnames),
        );
        let id = bin_to_hex(node.id.as_bytes()).to_ascii_lowercase();
        let nexthop = node.route.next_hop.as_deref().unwrap_or("-");
        let via = node.route.via.as_deref().unwrap_or("-");
        let distance = node.route.distance.unwrap_or(-1);
        let legacy = dump_node_legacy_fields(runtime, &node.name);
        let counters = runtime
            .and_then(|runtime| runtime.traffic.get(&node.name))
            .cloned()
            .unwrap_or_default();
        let udp_ping_rtt = dump_node_udp_ping_rtt(runtime, &node.name);

        output.push_str(&format!(
            "{control} {REQ_DUMP_NODES} {} {} {} port {} {} {} {} {} {:x} {:x} {} {} {} {} {} {} {} {} {} {} {} {}\n",
            node.name,
            id,
            host,
            port,
            legacy.cipher,
            legacy.digest,
            legacy.mac_length,
            legacy.compression,
            node.options,
            node_status_bits(&node.status),
            nexthop,
            via,
            distance,
            node.mtu,
            node.min_mtu,
            node.max_mtu,
            node.last_state_change,
            udp_ping_rtt,
            counters.in_packets,
            counters.in_bytes,
            counters.out_packets,
            counters.out_bytes,
        ));
    }

    output.push_str(&format!("{control} {REQ_DUMP_NODES}\n"));
    output
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DumpNodeLegacyFields {
    pub(crate) cipher: i32,
    pub(crate) digest: i32,
    pub(crate) mac_length: usize,
    pub(crate) compression: i32,
}

pub(crate) fn dump_node_legacy_fields(
    runtime: Option<&RuntimeDaemonState>,
    node: &str,
) -> DumpNodeLegacyFields {
    let Some(peer) = runtime.and_then(|runtime| runtime.legacy_codec.peer(node)) else {
        return DumpNodeLegacyFields::default();
    };

    DumpNodeLegacyFields {
        cipher: peer.outgoing.cipher.algorithm().nid(),
        digest: peer.outgoing.digest.algorithm().nid(),
        mac_length: peer.outgoing.digest.length(),
        compression: peer.outgoing.compression as i32,
    }
}

pub(crate) fn dump_node_udp_ping_rtt(runtime: Option<&RuntimeDaemonState>, node: &str) -> i32 {
    runtime
        .and_then(|runtime| runtime.udp_probe.get(node))
        .and_then(|probe| probe.udp_ping_rtt)
        .and_then(|rtt| i32::try_from(rtt.as_micros()).ok())
        .unwrap_or(-1)
}

pub(crate) fn dump_edges(state: &NetworkState) -> String {
    let control = Request::Control.number();
    let mut output = String::new();

    for edge in state.graph.edges() {
        let remote = edge
            .address
            .as_ref()
            .cloned()
            .unwrap_or_else(unknown_endpoint);
        let local = edge
            .local_address
            .as_ref()
            .cloned()
            .unwrap_or_else(unknown_endpoint);
        output.push_str(&format!(
            "{control} {REQ_DUMP_EDGES} {} {} {} port {} {} port {} {:x} {}\n",
            edge.from,
            edge.to,
            remote.address,
            remote.port,
            local.address,
            local.port,
            edge.options,
            edge.weight
        ));
    }

    output.push_str(&format!("{control} {REQ_DUMP_EDGES}\n"));
    output
}

pub(crate) fn dump_subnets(state: &NetworkState) -> String {
    let control = Request::Control.number();
    let mut output = String::new();

    for subnet in state.subnets.iter() {
        output.push_str(&format!(
            "{control} {REQ_DUMP_SUBNETS} {} {}\n",
            format_subnet_for_dump(subnet),
            subnet.owner.as_deref().unwrap_or("(broadcast)")
        ));
    }

    output.push_str(&format!("{control} {REQ_DUMP_SUBNETS}\n"));
    output
}

pub(crate) fn dump_connections(runtime: Option<&RuntimeDaemonState>) -> String {
    let control = Request::Control.number();
    let mut output = format!(
        "{control} {REQ_DUMP_CONNECTIONS} <control> localhost port unix 0 0 {:x}\n",
        CONNECTION_DUMP_STATUS_CONTROL
    );

    if let Some(runtime) = runtime {
        output.push_str(&format_runtime_connection_dump(
            &runtime.meta_connection_infos(),
            runtime.hostnames,
        ));
    }

    output.push_str(&format!("{control} {REQ_DUMP_CONNECTIONS}\n"));
    output
}

pub(crate) fn dump_traffic(state: &NetworkState, runtime: Option<&RuntimeDaemonState>) -> String {
    let control = Request::Control.number();
    let mut output = String::new();

    for node in state.graph.nodes() {
        let counters = runtime
            .and_then(|runtime| runtime.traffic.get(&node.name))
            .cloned()
            .unwrap_or_default();
        output.push_str(&format!(
            "{control} {REQ_DUMP_TRAFFIC} {} {} {} {} {}\n",
            node.name,
            counters.in_packets,
            counters.in_bytes,
            counters.out_packets,
            counters.out_bytes
        ));
    }

    output.push_str(&format!("{control} {REQ_DUMP_TRAFFIC}\n"));
    output
}

pub(crate) fn format_runtime_connection_dump(
    infos: &[RuntimeMetaConnectionInfo],
    hostnames: bool,
) -> String {
    let control = Request::Control.number();
    let mut output = String::new();

    for info in infos {
        let name = info
            .name
            .clone()
            .unwrap_or_else(|| format!("<unknown-{}>", info.id));
        let (host, port) = format_socket_addr_for_dump(info.peer, hostnames);
        output.push_str(&format!(
            "{control} {REQ_DUMP_CONNECTIONS} {name} {} port {} {:x} {} {:x}\n",
            host, port, info.options, info.id, info.status
        ));
    }

    output
}

pub(crate) fn node_host_port(
    config: &RuntimeConfig,
    node: &Node,
    runtime_local_port: Option<&str>,
    hostnames: bool,
) -> (String, String) {
    if node.name == config.name {
        return (
            "MYSELF".to_owned(),
            runtime_local_port
                .map(str::to_owned)
                .unwrap_or_else(|| runtime_local_port_from_config(config)),
        );
    }

    if let Some(endpoint) = &node.udp_address {
        return (endpoint.address.clone(), endpoint.port.clone());
    }

    if let Some(address) = config.addresses.address(&node.name) {
        return format_socket_addr_for_dump(address, hostnames);
    }

    ("unknown".to_owned(), "unknown".to_owned())
}

pub(crate) fn format_socket_addr_for_dump(
    address: SocketAddr,
    hostnames: bool,
) -> (String, String) {
    if hostnames {
        return reverse_socket_addr_for_dump(address)
            .unwrap_or_else(|| (address.ip().to_string(), address.port().to_string()));
    }
    (address.ip().to_string(), address.port().to_string())
}

#[cfg(unix)]
pub(crate) fn reverse_socket_addr_for_dump(address: SocketAddr) -> Option<(String, String)> {
    let (raw_address, raw_length) = socket_addr_to_raw(&address);
    let mut host = [0 as libc::c_char; libc::NI_MAXHOST as usize];
    let mut service = [0 as libc::c_char; 32];
    let result = unsafe {
        libc::getnameinfo(
            (&raw_address as *const libc::sockaddr_storage).cast(),
            raw_length,
            host.as_mut_ptr(),
            getnameinfo_buffer_len(host.len()),
            service.as_mut_ptr(),
            getnameinfo_buffer_len(service.len()),
            0,
        )
    };
    if result != 0 {
        return None;
    }
    let host = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let service = unsafe { std::ffi::CStr::from_ptr(service.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Some((host, service))
}

#[cfg(all(
    unix,
    any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    )
))]
pub(crate) fn getnameinfo_buffer_len(len: usize) -> usize {
    len
}

#[cfg(all(
    unix,
    not(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
pub(crate) fn getnameinfo_buffer_len(len: usize) -> libc::socklen_t {
    len.try_into().unwrap_or(libc::socklen_t::MAX)
}

#[cfg(not(unix))]
pub(crate) fn reverse_socket_addr_for_dump(_address: SocketAddr) -> Option<(String, String)> {
    None
}

pub(crate) fn unknown_endpoint() -> EdgeEndpoint {
    EdgeEndpoint::new("unknown", "unknown")
}

pub(crate) fn format_subnet_for_dump(subnet: &Subnet) -> String {
    subnet.to_string()
}

pub(crate) fn node_status_bits(status: &NodeStatus) -> u32 {
    let mut bits = 0u32;

    if status.valid_key {
        bits |= 1 << 1;
    }
    if status.waiting_for_key {
        bits |= 1 << 2;
    }
    if status.visited {
        bits |= 1 << 3;
    }
    if status.reachable {
        bits |= 1 << 4;
    }
    if status.indirect {
        bits |= 1 << 5;
    }
    if status.sptps {
        bits |= 1 << 6;
    }
    if status.udp_confirmed {
        bits |= 1 << 7;
    }
    if status.send_locally {
        bits |= 1 << 8;
    }
    if status.udp_packet {
        bits |= 1 << 9;
    }
    if status.valid_key_in {
        bits |= 1 << 10;
    }
    if status.has_address {
        bits |= 1 << 11;
    }
    if status.ping_sent {
        bits |= 1 << 12;
    }

    bits
}

pub(crate) fn read_control_line(reader: &mut impl BufRead) -> Result<String, TincdError> {
    let mut line = String::new();
    let read = reader.read_line(&mut line).map_err(control_io)?;

    if read == 0 {
        return Err(TincdError::ControlIo(
            "unexpected end of control socket".to_owned(),
        ));
    }

    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

pub(crate) fn generate_control_cookie() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:032x}{:032x}", now, std::process::id())
}

pub(crate) fn control_io(error: io::Error) -> TincdError {
    TincdError::ControlIo(error.to_string())
}

pub(crate) fn listen_io(error: io::Error) -> TincdError {
    TincdError::ListenIo(error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UmbilicalSpec {
    pub(crate) fd: i32,
    pub(crate) colorize: bool,
}

#[cfg(unix)]
pub fn notify_umbilical_success() -> Result<(), TincdError> {
    let Some(fd) = parse_umbilical_fd(env::var("TINC_UMBILICAL").ok().as_deref()) else {
        return Ok(());
    };
    let byte = [0u8; 1];
    // SAFETY: The fd comes from the parent process through TINC_UMBILICAL and
    // is only used for this single write, matching tinc's startup contract.
    let written = unsafe { libc::write(fd, byte.as_ptr().cast(), byte.len()) };

    if written == 1 {
        Ok(())
    } else {
        Err(TincdError::ControlIo(
            io::Error::last_os_error().to_string(),
        ))
    }
}

#[cfg(not(unix))]
pub fn notify_umbilical_success() -> Result<(), TincdError> {
    Ok(())
}

pub(crate) fn parse_umbilical_fd(value: Option<&str>) -> Option<i32> {
    parse_umbilical_spec(value).map(|spec| spec.fd)
}

pub(crate) fn parse_umbilical_spec(value: Option<&str>) -> Option<UmbilicalSpec> {
    let mut fields = value?.split_whitespace();
    let fd = fields.next()?.parse().ok()?;
    let colorize = fields
        .next()
        .and_then(|value| value.parse::<i32>().ok())
        .is_some_and(|value| value != 0);
    Some(UmbilicalSpec { fd, colorize })
}

pub(crate) fn parse_cli_config(input: &str, line: i32) -> Result<Config, TincdError> {
    tinc_core::config::parse_config_line(input, None, line).map_err(TincdError::ConfigOption)
}

pub(crate) fn normalize_netname(netname: Option<String>) -> Result<Option<String>, TincdError> {
    let Some(netname) = netname else {
        return Ok(None);
    };

    if netname.is_empty() || netname == "." {
        return Ok(None);
    }

    if !check_netname(&netname, false) {
        return Err(TincdError::InvalidNetname(netname));
    }

    Ok(Some(netname))
}

pub(crate) fn next_arg(
    args: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, TincdError> {
    args.next().ok_or_else(|| TincdError::MissingArgument {
        option: option.to_owned(),
    })
}

pub(crate) fn next_optional_path<I>(args: &mut Peekable<I>) -> Option<PathBuf>
where
    I: Iterator<Item = String>,
{
    if args.peek().is_some_and(|next| next.starts_with('-')) {
        None
    } else {
        args.next().map(PathBuf::from)
    }
}

pub(crate) fn next_optional_value<I>(args: &mut Peekable<I>) -> Option<String>
where
    I: Iterator<Item = String>,
{
    if args.peek().is_some_and(|next| next.starts_with('-')) {
        None
    } else {
        args.next()
    }
}

pub(crate) fn value_after_equals(argument: &str) -> String {
    argument
        .split_once('=')
        .map(|(_, value)| value)
        .unwrap_or_default()
        .to_owned()
}

pub(crate) fn usage(program_name: &str) -> String {
    format!(
        "Usage: {program_name} [option]...\n\
\n\
  -c, --config=DIR              Read configuration options from DIR.\n\
  -D, --no-detach               Don't fork and detach.\n\
  -d, --debug[=LEVEL]           Increase debug level or set it to LEVEL.\n\
  -n, --net=NETNAME             Connect to net NETNAME.\n\
  -L, --mlock                   Lock tinc into main memory.\n\
      --logfile[=FILENAME]      Write log entries to a logfile.\n\
  -s, --syslog                  Use syslog instead of stderr with --no-detach.\n\
      --pidfile=FILENAME        Write PID and control socket cookie to FILENAME.\n\
      --bypass-security         Disables meta protocol security, for debugging.\n\
  -o, --option[HOST.]KEY=VALUE  Set global/host configuration value.\n\
  -R, --chroot                  chroot to NET dir at startup.\n\
  -U, --user=USER               setuid to given USER at startup.\n\
      --help                    Display this help and exit.\n\
      --version                 Output version information and exit.\n\
\n\
Report bugs to tinc@tinc-vpn.org.\n"
    )
}

pub(crate) fn version() -> String {
    format!(
        "tincd version {} (protocol {PROT_MAJOR}.{PROT_MINOR})\n\
Features: rust\n\
\n\
Copyright (C) 1998-2021 Ivo Timmermans, Guus Sliepen and others.\n\
See the AUTHORS file for a complete list.\n\
\n\
tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n\
and you are welcome to redistribute it under certain conditions;\n\
see the file COPYING for details.\n",
        env!("CARGO_PKG_VERSION")
    )
}
