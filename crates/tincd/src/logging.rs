use crate::*;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TrafficCounters {
    pub(crate) in_packets: u64,
    pub(crate) in_bytes: u64,
    pub(crate) out_packets: u64,
    pub(crate) out_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeLogEntry {
    pub(crate) level: i32,
    pub(crate) priority: i32,
    pub(crate) message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeLogColor {
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    Gray,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeLogPriorityDisplay {
    pub(crate) name: &'static str,
    pub(crate) color: RuntimeLogColor,
}

#[derive(Debug)]
pub(crate) struct RuntimeLogSink {
    pub(crate) backend: RuntimeLogBackend,
}

#[derive(Debug)]
pub(crate) enum RuntimeLogBackend {
    File(RuntimeFileLogSink),
    Pretty(RuntimePrettyLogSink),
    #[cfg(unix)]
    Syslog(RuntimeSyslogSink),
}

#[derive(Debug)]
pub(crate) struct RuntimeFileLogSink {
    pub(crate) path: PathBuf,
    pub(crate) file: File,
    pub(crate) ident: String,
    pub(crate) pid: u32,
}

pub(crate) struct RuntimePrettyLogSink {
    pub(crate) writer: Box<dyn Write + Send>,
    pub(crate) colorize: bool,
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct RuntimeUmbilicalLogSink {
    pub(crate) fd: i32,
    pub(crate) colorize: bool,
}

impl fmt::Debug for RuntimePrettyLogSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimePrettyLogSink")
            .field("colorize", &self.colorize)
            .finish_non_exhaustive()
    }
}

impl RuntimeLogSink {
    pub(crate) fn open(path: &Path, ident: impl Into<String>) -> Result<Self, TincdError> {
        RuntimeFileLogSink::open(path, ident).map(|backend| Self {
            backend: RuntimeLogBackend::File(backend),
        })
    }

    pub(crate) fn stderr(colorize: bool) -> Self {
        Self::pretty(Box::new(io::stderr()), colorize)
    }

    #[cfg(test)]
    pub(crate) fn pretty_for_test(writer: Box<dyn Write + Send>, colorize: bool) -> Self {
        Self::pretty(writer, colorize)
    }

    pub(crate) fn pretty(writer: Box<dyn Write + Send>, colorize: bool) -> Self {
        Self {
            backend: RuntimeLogBackend::Pretty(RuntimePrettyLogSink { writer, colorize }),
        }
    }

    #[cfg(unix)]
    pub(crate) fn syslog(ident: impl Into<String>) -> Result<Self, TincdError> {
        RuntimeSyslogSink::open(ident).map(|backend| Self {
            backend: RuntimeLogBackend::Syslog(backend),
        })
    }

    pub(crate) fn write_entry(&mut self, priority: i32, message: &str) -> io::Result<()> {
        match &mut self.backend {
            RuntimeLogBackend::File(file) => file.write_entry(message),
            RuntimeLogBackend::Pretty(pretty) => pretty.write_entry(priority, message),
            #[cfg(unix)]
            RuntimeLogBackend::Syslog(syslog) => {
                syslog.write_entry(priority, message);
                Ok(())
            }
        }
    }

    pub(crate) fn reopen(&mut self) -> Result<bool, (PathBuf, io::Error)> {
        match &mut self.backend {
            RuntimeLogBackend::File(file) => {
                let path = file.path.clone();
                file.reopen().map(|()| true).map_err(|error| (path, error))
            }
            RuntimeLogBackend::Pretty(_) => Ok(false),
            #[cfg(unix)]
            RuntimeLogBackend::Syslog(_) => Ok(false),
        }
    }
}

impl RuntimeFileLogSink {
    pub(crate) fn open(path: &Path, ident: impl Into<String>) -> Result<Self, TincdError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| TincdError::RuntimeState(error.to_string()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| {
                TincdError::RuntimeState(format!(
                    "Could not open log file {}: {error}",
                    path.display()
                ))
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            ident: ident.into(),
            pid: std::process::id(),
        })
    }

    pub(crate) fn write_entry(&mut self, message: &str) -> io::Result<()> {
        writeln!(
            self.file,
            "{} {}[{}]: {}",
            current_log_timestamp(),
            self.ident,
            self.pid,
            message
        )?;
        self.file.flush()
    }

    pub(crate) fn reopen(&mut self) -> io::Result<()> {
        let _ = self.file.flush();
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.file = new_file;
        Ok(())
    }
}

impl RuntimePrettyLogSink {
    pub(crate) fn write_entry(&mut self, priority: i32, message: &str) -> io::Result<()> {
        writeln!(
            self.writer,
            "{}",
            format_pretty_log_entry(priority, message, self.colorize)
        )?;
        self.writer.flush()
    }
}

#[cfg(unix)]
impl RuntimeUmbilicalLogSink {
    pub(crate) fn from_env() -> Option<Self> {
        let spec = parse_umbilical_spec(env::var("TINC_UMBILICAL").ok().as_deref())?;
        Self::from_spec(spec)
    }

    pub(crate) fn from_spec(spec: UmbilicalSpec) -> Option<Self> {
        if unsafe { libc::fcntl(spec.fd, libc::F_GETFL) } < 0 {
            return None;
        }
        let flags = unsafe { libc::fcntl(spec.fd, libc::F_GETFD) };
        if flags >= 0 {
            let _ = unsafe { libc::fcntl(spec.fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        }
        Some(Self {
            fd: spec.fd,
            colorize: spec.colorize,
        })
    }

    pub(crate) fn write_log(&mut self, priority: i32, message: &str) {
        let line = format!(
            "{}\n",
            format_pretty_log_entry(priority, message, self.colorize)
        );
        let _ = write_all_raw_fd(self.fd, line.as_bytes());
    }

    pub(crate) fn write_success_and_close(self) -> io::Result<()> {
        let result = write_all_raw_fd(self.fd, &[0]);
        let _ = unsafe { libc::close(self.fd) };
        result
    }
}

#[cfg(unix)]
pub(crate) fn write_all_raw_fd(fd: i32, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "umbilical write returned zero",
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct RuntimeSyslogSink {
    pub(crate) _ident: CString,
}

#[cfg(unix)]
impl RuntimeSyslogSink {
    pub(crate) fn open(ident: impl Into<String>) -> Result<Self, TincdError> {
        let ident = CString::new(ident.into())
            .map_err(|error| TincdError::RuntimeState(format!("invalid syslog ident: {error}")))?;
        unsafe {
            libc::openlog(
                ident.as_ptr(),
                libc::LOG_CONS | libc::LOG_PID,
                libc::LOG_DAEMON,
            );
        }
        Ok(Self { _ident: ident })
    }

    pub(crate) fn write_entry(&self, priority: i32, message: &str) {
        let Ok(message) = CString::new(message) else {
            return;
        };
        unsafe {
            libc::syslog(
                syslog_priority_from_tinc_priority(priority),
                b"%s\0".as_ptr().cast::<libc::c_char>(),
                message.as_ptr(),
            );
        }
    }
}

#[cfg(unix)]
impl Drop for RuntimeSyslogSink {
    fn drop(&mut self) {
        unsafe {
            libc::closelog();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OutgoingRetryState {
    pub(crate) timeout_secs: u64,
    pub(crate) next_attempt: Instant,
}

impl OutgoingRetryState {
    pub(crate) fn ready(now: Instant) -> Self {
        Self {
            timeout_secs: 0,
            next_attempt: now,
        }
    }

    pub(crate) fn reset(&mut self, now: Instant) {
        self.timeout_secs = 0;
        self.next_attempt = now;
    }

    pub(crate) fn mark_failed(&mut self, now: Instant, max_timeout_secs: u64) {
        self.timeout_secs =
            (self.timeout_secs + OUTGOING_CONNECT_RETRY_STEP_SECS).min(max_timeout_secs);
        self.next_attempt = now + tinc_timer_jitter(self.timeout_secs);
    }

    pub(crate) fn mark_connected(&mut self, now: Instant) {
        self.reset(now);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConnectionBurstCounter {
    pub(crate) burst: u64,
    pub(crate) last_update: Instant,
}

impl ConnectionBurstCounter {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            burst: 0,
            last_update: now,
        }
    }

    pub(crate) fn increment(&mut self, now: Instant) -> u64 {
        let elapsed = now.saturating_duration_since(self.last_update).as_secs();
        if elapsed > self.burst {
            self.burst = 0;
        } else {
            self.burst -= elapsed;
        }
        self.last_update = now;
        self.burst += 1;
        self.burst
    }

    pub(crate) fn cap(&mut self, maximum: u64) {
        self.burst = maximum;
    }
}

pub(crate) fn record_outbound_traffic(
    traffic: &mut BTreeMap<String, TrafficCounters>,
    target: &str,
    bytes: usize,
) {
    let counters = traffic.entry(target.to_owned()).or_default();
    counters.out_packets = counters.out_packets.saturating_add(1);
    counters.out_bytes = counters.out_bytes.saturating_add(bytes as u64);
}

pub(crate) fn publish_control_pcap_packet(
    subscribers: &mut Vec<RuntimeControlPcapSubscriber>,
    data: &[u8],
) {
    if subscribers.is_empty() {
        return;
    }

    for subscriber in subscribers {
        let len = control_pcap_len(subscriber.snaplen, data.len());
        subscriber.writer.queue_payload(REQ_PCAP, &data[..len]);
    }
}

pub(crate) fn control_pcap_len(snaplen: usize, len: usize) -> usize {
    let limit = if snaplen == 0 {
        PCAP_CONTROL_BUFFER_SIZE
    } else {
        snaplen.min(PCAP_CONTROL_BUFFER_SIZE)
    };
    len.min(limit)
}

pub(crate) fn control_log_level(level: i32, debug_level: i32) -> i32 {
    let level = level.clamp(DEBUG_UNSET, DEBUG_SCARY_THINGS);
    if level == DEBUG_UNSET {
        debug_level
    } else {
        level
    }
}

pub(crate) fn secure_udp_session_missing(target: &str) -> TransportError {
    TransportError::Io(io::Error::new(
        io::ErrorKind::NetworkUnreachable,
        format!("missing SPTPS UDP session for {target}"),
    ))
}

pub(crate) fn runtime_local_weight(config: &RuntimeConfig) -> i32 {
    config.daemon.weight.unwrap_or(0)
}

pub(crate) fn key_expire_delay(key_expire: i32) -> Duration {
    if key_expire < 0 {
        return Duration::ZERO;
    }

    tinc_timer_jitter(key_expire as u64)
}

pub(crate) fn tinc_timer_jitter(seconds: u64) -> Duration {
    Duration::from_secs(seconds) + Duration::from_micros(prng_below(TINC_TIMER_JITTER_US) as u64)
}

pub(crate) fn tinc_timer_jitter_duration(base: Duration) -> Duration {
    base + Duration::from_micros(prng_below(TINC_TIMER_JITTER_US) as u64)
}

pub(crate) fn schedule_next_key_expire(now: Instant, key_expire: i32) -> Option<Instant> {
    if key_expire < 0 {
        None
    } else {
        Some(now + key_expire_delay(key_expire))
    }
}

pub(crate) fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(unix)]
pub(crate) fn current_log_timestamp() -> String {
    let time = current_unix_secs() as libc::time_t;
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&time, &mut local) }.is_null() {
        return current_unix_secs().to_string();
    }

    let mut buffer = [0u8; 20];
    let written = unsafe {
        libc::strftime(
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            b"%Y-%m-%d %H:%M:%S\0".as_ptr().cast(),
            &local,
        )
    };
    if written == 0 {
        return current_unix_secs().to_string();
    }

    String::from_utf8_lossy(&buffer[..written]).into_owned()
}

#[cfg(not(unix))]
pub(crate) fn current_log_timestamp() -> String {
    current_unix_secs().to_string()
}

pub(crate) fn log_priority_display(priority: i32) -> RuntimeLogPriorityDisplay {
    match priority {
        LOG_EMERG => RuntimeLogPriorityDisplay {
            name: "EMERGENCY",
            color: RuntimeLogColor::Magenta,
        },
        LOG_ALERT => RuntimeLogPriorityDisplay {
            name: "ALERT",
            color: RuntimeLogColor::Magenta,
        },
        LOG_CRIT => RuntimeLogPriorityDisplay {
            name: "CRITICAL",
            color: RuntimeLogColor::Magenta,
        },
        LOG_ERR => RuntimeLogPriorityDisplay {
            name: "ERROR",
            color: RuntimeLogColor::Red,
        },
        LOG_WARNING => RuntimeLogPriorityDisplay {
            name: "WARNING",
            color: RuntimeLogColor::Yellow,
        },
        LOG_NOTICE => RuntimeLogPriorityDisplay {
            name: "NOTICE",
            color: RuntimeLogColor::Cyan,
        },
        LOG_INFO => RuntimeLogPriorityDisplay {
            name: "INFO",
            color: RuntimeLogColor::Green,
        },
        LOG_DEBUG => RuntimeLogPriorityDisplay {
            name: "DEBUG",
            color: RuntimeLogColor::Blue,
        },
        _ => RuntimeLogPriorityDisplay {
            name: "UNKNOWN",
            color: RuntimeLogColor::White,
        },
    }
}

pub(crate) fn log_color_ansi(color: RuntimeLogColor) -> &'static str {
    match color {
        RuntimeLogColor::Red => "\x1b[31;1m",
        RuntimeLogColor::Green => "\x1b[32;1m",
        RuntimeLogColor::Yellow => "\x1b[33;1m",
        RuntimeLogColor::Blue => "\x1b[34;1m",
        RuntimeLogColor::Magenta => "\x1b[35;1m",
        RuntimeLogColor::Cyan => "\x1b[36;1m",
        RuntimeLogColor::White => "\x1b[37;1m",
        RuntimeLogColor::Gray => "\x1b[90m",
    }
}

pub(crate) fn format_pretty_log_entry(priority: i32, message: &str, colorize: bool) -> String {
    let display = log_priority_display(priority);
    let timestamp = current_log_timestamp();

    if colorize {
        format!(
            "{}{} {}{:<7}\x1b[0m {}",
            log_color_ansi(RuntimeLogColor::Gray),
            timestamp,
            log_color_ansi(display.color),
            display.name,
            message
        )
    } else {
        format!("{timestamp} {:<7} {message}", display.name)
    }
}

#[cfg(unix)]
pub(crate) fn stderr_supports_ansi_escapes() -> bool {
    let is_tty = unsafe { libc::isatty(libc::STDERR_FILENO) == 1 };
    let term_allows_color = env::var("TERM").is_ok_and(|term| term != "dumb");
    is_tty && term_allows_color
}

#[cfg(not(unix))]
pub(crate) fn stderr_supports_ansi_escapes() -> bool {
    false
}

#[cfg(unix)]
pub(crate) fn syslog_priority_from_tinc_priority(priority: i32) -> libc::c_int {
    match priority {
        LOG_EMERG => libc::LOG_EMERG,
        LOG_ALERT => libc::LOG_ALERT,
        LOG_CRIT => libc::LOG_CRIT,
        LOG_ERR => libc::LOG_ERR,
        LOG_WARNING => libc::LOG_WARNING,
        LOG_NOTICE => libc::LOG_NOTICE,
        LOG_INFO => libc::LOG_INFO,
        LOG_DEBUG => libc::LOG_DEBUG,
        _ => libc::LOG_INFO,
    }
}

#[cfg(unix)]
pub(crate) fn process_priority_nice_value(priority: ProcessPriority) -> i32 {
    match priority {
        ProcessPriority::Normal => 0,
        ProcessPriority::Low => 10,
        ProcessPriority::High => -10,
    }
}

#[cfg(unix)]
pub(crate) fn apply_process_priority(priority: Option<ProcessPriority>) -> Result<(), TincdError> {
    let Some(priority) = priority else {
        return Ok(());
    };
    let value = process_priority_nice_value(priority);
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, value) } != 0 {
        return Err(TincdError::RuntimeState(format!(
            "System call `setpriority` failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn apply_process_priority(_priority: Option<ProcessPriority>) -> Result<(), TincdError> {
    Ok(())
}

pub(crate) fn sandbox_supported_for_runtime() -> bool {
    cfg!(target_os = "openbsd")
}

pub(crate) fn sandbox_can_start_processes_after_enter(level: SandboxLevel) -> bool {
    level < SandboxLevel::High
}

#[cfg(test)]
pub(crate) fn sandbox_can_use_new_paths_after_enter(level: SandboxLevel) -> bool {
    let _ = level;
    !sandbox_supported_for_runtime()
}

pub(crate) fn apply_sandbox(
    config: &RuntimeConfig,
    options: &TincdOptions,
) -> Result<(), TincdError> {
    apply_sandbox_with(config, options, openbsd_sandbox_enter)
}

pub(crate) fn validate_sandbox_policy(config: &RuntimeConfig) -> Result<(), TincdError> {
    let level = config.daemon.sandbox;
    if matches!(config.daemon.proxy, ProxyConfig::Exec { .. })
        && !sandbox_can_start_processes_after_enter(level)
    {
        return Err(TincdError::SandboxPolicy(
            "Cannot use exec proxies with current sandbox level.".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn apply_sandbox_with(
    config: &RuntimeConfig,
    options: &TincdOptions,
    enter: impl FnOnce(OpenBsdSandboxProfile) -> Result<(), TincdError>,
) -> Result<(), TincdError> {
    let level = config.daemon.sandbox;
    if level == SandboxLevel::Off {
        return Ok(());
    }
    if !sandbox_supported_for_runtime() {
        return Err(TincdError::RuntimeConfig(
            RuntimeConfigError::UnsupportedSandboxLevel(level),
        ));
    }
    validate_sandbox_policy(config)?;

    enter(openbsd_sandbox_profile(config, options))
}
