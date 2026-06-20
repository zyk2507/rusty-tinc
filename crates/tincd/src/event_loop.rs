use crate::*;

#[cfg(unix)]
const MAX_EVENTS_PER_LOOP: usize = 32;
#[cfg(unix)]
const UDP_DATAGRAMS_PER_READY: usize = 64;

#[cfg(unix)]
pub(crate) struct RuntimeEventPoll {
    poll: mio::Poll,
    events: mio::Events,
    registered: BTreeMap<RuntimePollKey, RuntimePollRegistration>,
    tokens: BTreeMap<mio::Token, RuntimePollKey>,
    ready: VecDeque<RuntimeReadyEvent>,
    ready_members: BTreeSet<RuntimeReadyEvent>,
    next_token: usize,
}

#[cfg(unix)]
impl RuntimeEventPoll {
    pub(crate) fn new() -> Result<Self, TincdError> {
        Ok(Self {
            poll: mio::Poll::new().map_err(runtime_poll_io)?,
            events: mio::Events::with_capacity(MAX_EVENTS_PER_LOOP),
            registered: BTreeMap::new(),
            tokens: BTreeMap::new(),
            ready: VecDeque::new(),
            ready_members: BTreeSet::new(),
            next_token: 0,
        })
    }

    pub(crate) fn poll_ready(
        &mut self,
        config: &mut RuntimeConfig,
        endpoint: &ControlEndpoint,
        runtime: &mut RuntimeDaemonState,
        control_listener: &std::os::unix::net::UnixListener,
        options: &TincdOptions,
        signals: &RuntimeSignalHandlers,
        timeout: Option<Duration>,
    ) -> Result<RuntimeEventPollOutcome, TincdError> {
        let mut fds = RuntimePollFdSet::new();
        fds.insert(
            RuntimePollKey::Control,
            control_listener.as_raw_fd(),
            RuntimeFdInterest::READABLE,
        );
        fds.insert(
            RuntimePollKey::Signals,
            signals.read_fd(),
            RuntimeFdInterest::READABLE,
        );
        insert_runtime_fds(runtime, &mut fds);
        self.sync_registry(&fds)?;
        let poll_timeout = if self.ready.is_empty() {
            timeout
        } else {
            Some(Duration::ZERO)
        };
        match self.poll.poll(&mut self.events, poll_timeout) {
            Ok(()) => {
                let mut ready = Vec::new();
                for event in &self.events {
                    let Some(key) = self.tokens.get(&event.token()).cloned() else {
                        continue;
                    };
                    if event.is_writable() {
                        ready.push(RuntimeReadyEvent {
                            key: key.clone(),
                            interest: RuntimeReadyInterest::Writable,
                        });
                    }
                    if event.is_readable() {
                        ready.push(RuntimeReadyEvent {
                            key,
                            interest: RuntimeReadyInterest::Readable,
                        });
                    }
                }
                for event in ready {
                    self.push_ready(event);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(runtime_poll_io(error)),
        }

        let ready_this_poll = self.ready.len().min(MAX_EVENTS_PER_LOOP);
        let mut processed = 0usize;
        while processed < ready_this_poll {
            let Some(event) = self.pop_ready() else {
                break;
            };
            if !fds.allows(&event) {
                continue;
            }
            match handle_runtime_ready_event(
                config,
                endpoint,
                control_listener,
                runtime,
                options,
                signals,
                &event,
            )? {
                RuntimeReadyResult::Stop => return Ok(RuntimeEventPollOutcome::Stop),
                RuntimeReadyResult::NotReady => {}
                RuntimeReadyResult::ReadyAgain => self.push_ready(event),
                RuntimeReadyResult::Processed => {}
            }
            processed += 1;
        }

        Ok(RuntimeEventPollOutcome::Continue)
    }

    fn push_ready(&mut self, event: RuntimeReadyEvent) {
        if self.ready_members.insert(event.clone()) {
            self.ready.push_back(event);
        }
    }

    fn pop_ready(&mut self) -> Option<RuntimeReadyEvent> {
        let event = self.ready.pop_front()?;
        self.ready_members.remove(&event);
        Some(event)
    }

    fn sync_registry(&mut self, fds: &RuntimePollFdSet) -> Result<(), TincdError> {
        let stale = self
            .registered
            .keys()
            .cloned()
            .filter(|key| !fds.contains(key))
            .collect::<Vec<_>>();

        for key in stale {
            if let Some(registration) = self.registered.remove(&key) {
                self.tokens.remove(&registration.token);
                self.deregister_fd(registration.fd)?;
            }
        }

        for (key, fd, interest) in fds.iter() {
            match self.registered.get(key).copied() {
                Some(registration)
                    if registration.fd == fd && registration.interest == interest => {}
                Some(registration) => {
                    let interest_changed = registration.interest != interest;
                    if registration.fd == fd {
                        self.reregister_fd(fd, registration.token, interest)?;
                    } else {
                        self.deregister_fd(registration.fd)?;
                        self.register_fd(fd, registration.token, interest)?;
                    }
                    if let Some(registered) = self.registered.get_mut(key) {
                        registered.fd = fd;
                        registered.interest = interest;
                    }
                    if interest_changed {
                        self.queue_initial_ready(key, interest);
                    }
                }
                None => {
                    let token = self.next_poll_token();
                    self.register_fd(fd, token, interest)?;
                    self.tokens.insert(token, key.clone());
                    self.registered.insert(
                        key.clone(),
                        RuntimePollRegistration {
                            fd,
                            token,
                            interest,
                        },
                    );
                    self.queue_initial_ready(key, interest);
                }
            }
        }

        Ok(())
    }

    fn register_fd(
        &self,
        fd: RawFd,
        token: mio::Token,
        interest: RuntimeFdInterest,
    ) -> Result<(), TincdError> {
        let mut source = mio::unix::SourceFd(&fd);
        self.poll
            .registry()
            .register(&mut source, token, interest.to_mio())
            .map_err(runtime_poll_io)
    }

    fn reregister_fd(
        &self,
        fd: RawFd,
        token: mio::Token,
        interest: RuntimeFdInterest,
    ) -> Result<(), TincdError> {
        let mut source = mio::unix::SourceFd(&fd);
        match self
            .poll
            .registry()
            .reregister(&mut source, token, interest.to_mio())
        {
            Ok(()) => Ok(()),
            Err(error) if is_stale_poll_registration_error(&error) => {
                self.register_fd(fd, token, interest)
            }
            Err(error) => Err(runtime_poll_io(error)),
        }
    }

    fn deregister_fd(&self, fd: RawFd) -> Result<(), TincdError> {
        let mut source = mio::unix::SourceFd(&fd);
        match self.poll.registry().deregister(&mut source) {
            Ok(()) => Ok(()),
            Err(error) if is_stale_poll_registration_error(&error) => Ok(()),
            Err(error) => Err(runtime_poll_io(error)),
        }
    }

    fn next_poll_token(&mut self) -> mio::Token {
        let token = mio::Token(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        token
    }

    fn queue_initial_ready(&mut self, key: &RuntimePollKey, interest: RuntimeFdInterest) {
        if interest.writable {
            self.push_ready(RuntimeReadyEvent {
                key: key.clone(),
                interest: RuntimeReadyInterest::Writable,
            });
        }
        if interest.readable {
            self.push_ready(RuntimeReadyEvent {
                key: key.clone(),
                interest: RuntimeReadyInterest::Readable,
            });
        }
    }
}

#[cfg(unix)]
pub(crate) enum RuntimeEventPollOutcome {
    Continue,
    Stop,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RuntimeReadyEvent {
    key: RuntimePollKey,
    interest: RuntimeReadyInterest,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RuntimeReadyInterest {
    Readable,
    Writable,
}

#[cfg(unix)]
enum RuntimeReadyResult {
    Processed,
    ReadyAgain,
    NotReady,
    Stop,
}

#[cfg(unix)]
fn handle_runtime_ready_event(
    config: &mut RuntimeConfig,
    endpoint: &ControlEndpoint,
    control_listener: &std::os::unix::net::UnixListener,
    runtime: &mut RuntimeDaemonState,
    options: &TincdOptions,
    signals: &RuntimeSignalHandlers,
    event: &RuntimeReadyEvent,
) -> Result<RuntimeReadyResult, TincdError> {
    match (&event.key, event.interest) {
        (RuntimePollKey::Control, RuntimeReadyInterest::Readable) => {
            match accept_control_connection_once_progress(
                config,
                endpoint,
                control_listener,
                Some(runtime),
                Some(options),
            )? {
                ControlAcceptProgress::Stop => Ok(RuntimeReadyResult::Stop),
                ControlAcceptProgress::Accepted => Ok(RuntimeReadyResult::ReadyAgain),
                ControlAcceptProgress::NotReady => Ok(RuntimeReadyResult::NotReady),
            }
        }
        (RuntimePollKey::Signals, RuntimeReadyInterest::Readable) => {
            if handle_runtime_signal_actions(config, runtime, options, signals)? {
                Ok(RuntimeReadyResult::Stop)
            } else {
                Ok(RuntimeReadyResult::Processed)
            }
        }
        (RuntimePollKey::ListenTcp(index), RuntimeReadyInterest::Readable) => {
            let mut accepted = false;
            while runtime.accept_meta_connection_once(*index)? {
                accepted = true;
            }
            if accepted {
                Ok(RuntimeReadyResult::Processed)
            } else {
                Ok(RuntimeReadyResult::NotReady)
            }
        }
        (RuntimePollKey::ListenUdp(index), RuntimeReadyInterest::Readable) => {
            let read = runtime.read_udp_datagrams_once(*index, UDP_DATAGRAMS_PER_READY)?;
            if read == 0 {
                Ok(RuntimeReadyResult::NotReady)
            } else if read >= UDP_DATAGRAMS_PER_READY {
                Ok(RuntimeReadyResult::ReadyAgain)
            } else {
                Ok(RuntimeReadyResult::Processed)
            }
        }
        (RuntimePollKey::Meta(id), RuntimeReadyInterest::Writable) => {
            let mut wrote = false;
            while matches!(
                runtime.flush_meta_output_by_id(*id)?,
                RuntimeIoProgress::Processed
            ) {
                wrote = true;
            }
            if wrote {
                Ok(RuntimeReadyResult::Processed)
            } else {
                Ok(RuntimeReadyResult::NotReady)
            }
        }
        (RuntimePollKey::Meta(id), RuntimeReadyInterest::Readable) => {
            let mut read = false;
            while matches!(
                runtime.read_meta_connection_once_by_id(*id)?,
                RuntimeIoProgress::Processed
            ) {
                read = true;
            }
            if read {
                Ok(RuntimeReadyResult::Processed)
            } else {
                Ok(RuntimeReadyResult::NotReady)
            }
        }
        (RuntimePollKey::ControlSubscriber(id), RuntimeReadyInterest::Writable) => {
            let mut wrote = false;
            while matches!(
                runtime.flush_control_subscriber_by_id(*id)?,
                RuntimeIoProgress::Processed
            ) {
                wrote = true;
            }
            if wrote {
                Ok(RuntimeReadyResult::Processed)
            } else {
                Ok(RuntimeReadyResult::NotReady)
            }
        }
        (RuntimePollKey::Device, RuntimeReadyInterest::Readable) => {
            if runtime.poll_device_packet()? {
                Ok(RuntimeReadyResult::ReadyAgain)
            } else {
                Ok(RuntimeReadyResult::NotReady)
            }
        }
        (RuntimePollKey::UpnpLog, RuntimeReadyInterest::Readable) => {
            if runtime.drain_upnp_logs() {
                Ok(RuntimeReadyResult::Processed)
            } else {
                Ok(RuntimeReadyResult::NotReady)
            }
        }
        _ => Ok(RuntimeReadyResult::NotReady),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimePollRegistration {
    fd: RawFd,
    token: mio::Token,
    interest: RuntimeFdInterest,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RuntimePollKey {
    Control,
    Signals,
    ListenTcp(usize),
    ListenUdp(usize),
    Meta(u64),
    ControlSubscriber(u64),
    Device,
    UpnpLog,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeFdInterest {
    readable: bool,
    writable: bool,
}

#[cfg(unix)]
impl RuntimeFdInterest {
    const READABLE: Self = Self {
        readable: true,
        writable: false,
    };

    const WRITABLE: Self = Self {
        readable: false,
        writable: true,
    };

    const READABLE_WRITABLE: Self = Self {
        readable: true,
        writable: true,
    };

    fn merge(&mut self, other: Self) {
        self.readable |= other.readable;
        self.writable |= other.writable;
    }

    fn to_mio(self) -> mio::Interest {
        match (self.readable, self.writable) {
            (true, true) => mio::Interest::READABLE | mio::Interest::WRITABLE,
            (true, false) => mio::Interest::READABLE,
            (false, true) => mio::Interest::WRITABLE,
            (false, false) => mio::Interest::READABLE,
        }
    }
}

#[cfg(unix)]
#[derive(Default)]
struct RuntimePollFdSet {
    fds: BTreeMap<RuntimePollKey, RuntimePollFd>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimePollFd {
    fd: RawFd,
    interest: RuntimeFdInterest,
}

#[cfg(unix)]
impl RuntimePollFdSet {
    fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, key: RuntimePollKey, fd: RawFd, interest: RuntimeFdInterest) {
        if fd < 0 {
            return;
        }
        self.fds
            .entry(key)
            .and_modify(|existing| {
                if existing.fd == fd {
                    existing.interest.merge(interest);
                } else {
                    *existing = RuntimePollFd { fd, interest };
                }
            })
            .or_insert(RuntimePollFd { fd, interest });
    }

    fn contains(&self, key: &RuntimePollKey) -> bool {
        self.fds.contains_key(key)
    }

    fn allows(&self, event: &RuntimeReadyEvent) -> bool {
        let Some(fd) = self.fds.get(&event.key) else {
            return false;
        };
        match event.interest {
            RuntimeReadyInterest::Readable => fd.interest.readable,
            RuntimeReadyInterest::Writable => fd.interest.writable,
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&RuntimePollKey, RawFd, RuntimeFdInterest)> {
        self.fds.iter().map(|(key, fd)| (key, fd.fd, fd.interest))
    }
}

#[cfg(unix)]
fn insert_runtime_fds(runtime: &RuntimeDaemonState, fds: &mut RuntimePollFdSet) {
    for (index, socket) in runtime.listen_sockets.iter().enumerate() {
        fds.insert(
            RuntimePollKey::ListenTcp(index),
            socket.tcp.as_raw_fd(),
            RuntimeFdInterest::READABLE,
        );
        fds.insert(
            RuntimePollKey::ListenUdp(index),
            socket.udp.as_raw_fd(),
            RuntimeFdInterest::READABLE,
        );
    }

    let now = Instant::now();
    for connection in &runtime.meta_connections {
        let interest = if connection.has_pending_output() {
            if runtime.topology_backoff.active(now) {
                RuntimeFdInterest::WRITABLE
            } else {
                RuntimeFdInterest::READABLE_WRITABLE
            }
        } else if runtime.topology_backoff.active(now) {
            continue;
        } else {
            RuntimeFdInterest::READABLE
        };
        fds.insert(
            RuntimePollKey::Meta(connection.id),
            connection.stream.as_raw_fd(),
            interest,
        );
    }

    for subscriber in runtime.control_subscriber_writers() {
        if subscriber.has_pending_output() {
            fds.insert(
                RuntimePollKey::ControlSubscriber(subscriber.id),
                subscriber.stream.as_raw_fd(),
                RuntimeFdInterest::WRITABLE,
            );
        }
    }

    if let Some(fd) = runtime.device_poll_fd() {
        fds.insert(RuntimePollKey::Device, fd, RuntimeFdInterest::READABLE);
    }

    if let Some(fd) = runtime.upnp_log_poll_fd() {
        fds.insert(RuntimePollKey::UpnpLog, fd, RuntimeFdInterest::READABLE);
    }
}

#[cfg(unix)]
pub(crate) fn runtime_event_wait_timeout(
    runtime: &RuntimeDaemonState,
    watchdog: &RuntimeWatchdog,
) -> Option<Duration> {
    let now = Instant::now();
    let mut next = None;

    if !watchdog.interval.is_zero() {
        push_next_timer_deadline(&mut next, watchdog.next_ping, now);
    }
    push_next_timer_deadline(&mut next, runtime.next_tinc_periodic, now);
    push_next_timer_deadline(&mut next, runtime.next_meta_ping_check, now);

    for (peer, retry) in &runtime.outgoing_retry {
        if !runtime.has_pending_or_authenticated_meta_connection_with_name(peer) {
            push_next_timer_deadline(&mut next, retry.next_attempt, now);
        }
    }
    for (peer, retry) in &runtime.autoconnect_outgoing {
        if !runtime.has_pending_or_authenticated_meta_connection_with_name(peer) {
            push_next_timer_deadline(&mut next, retry.next_attempt, now);
        }
    }
    if let Some(next_key_expire) = runtime.next_key_expire {
        push_next_timer_deadline(&mut next, next_key_expire, now);
    }
    if let Some(next_past_request_age) = runtime.next_past_request_age {
        push_next_timer_deadline(&mut next, next_past_request_age, now);
    }
    if let Some(device_backoff) = runtime.device_read_backoff_until {
        push_next_gate_deadline(&mut next, device_backoff, now);
    }
    if let Some(topology_backoff) = runtime.topology_backoff.until {
        push_next_gate_deadline(&mut next, topology_backoff, now);
    }
    push_next_timer_deadline(&mut next, runtime.next_mac_subnet_age, now);

    for probe in runtime.udp_probe.values() {
        if let Some(timeout) = probe.udp_ping_timeout {
            push_next_timer_deadline(&mut next, timeout, now);
        }
    }

    next.map(|deadline| deadline.saturating_duration_since(now))
}

#[cfg(unix)]
fn push_next_timer_deadline(next: &mut Option<Instant>, deadline: Instant, now: Instant) {
    if deadline <= now {
        *next = Some(now);
        return;
    }
    if next.is_none_or(|current| deadline < current) {
        *next = Some(deadline);
    }
}

#[cfg(unix)]
fn push_next_gate_deadline(next: &mut Option<Instant>, deadline: Instant, now: Instant) {
    if deadline <= now {
        return;
    }
    if next.is_none_or(|current| deadline < current) {
        *next = Some(deadline);
    }
}

#[cfg(unix)]
fn runtime_poll_io(error: io::Error) -> TincdError {
    TincdError::RuntimeState(format!("event poll failed: {error}"))
}

#[cfg(unix)]
fn is_stale_poll_registration_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EBADF | libc::ENOENT))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tinc_runtime::sptps::ED25519_SEED_LEN;

    #[test]
    fn poll_fd_set_merges_interests_for_same_source() {
        let mut fds = RuntimePollFdSet::new();
        fds.insert(RuntimePollKey::Meta(1), 7, RuntimeFdInterest::READABLE);
        fds.insert(
            RuntimePollKey::Meta(1),
            7,
            RuntimeFdInterest::READABLE_WRITABLE,
        );

        let entries = fds.iter().collect::<Vec<_>>();
        assert_eq!(1, entries.len());
        assert_eq!(&RuntimePollKey::Meta(1), entries[0].0);
        assert_eq!(7, entries[0].1);
        assert_eq!(RuntimeFdInterest::READABLE_WRITABLE, entries[0].2);
    }

    #[test]
    fn runtime_event_wait_timeout_uses_earliest_deadline() {
        let mut tree = ConfigTree::new();
        tree.add(Config::new(
            "Name",
            "alpha",
            tinc_core::config::ConfigSource::command_line(1),
        ));
        let config = RuntimeConfig::from_config_tree(&tree).unwrap();
        let now = Instant::now();
        let mut runtime = RuntimeDaemonState::new(
            Vec::new(),
            &config,
            RuntimeKeys {
                private_key: None,
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        );
        runtime.next_mac_subnet_age = now + Duration::from_secs(30);
        runtime.next_key_expire = Some(now + Duration::from_secs(20));
        runtime.next_tinc_periodic = now + Duration::from_secs(10);
        runtime.next_meta_ping_check = now + Duration::from_secs(30);
        runtime.outgoing_retry.insert(
            "beta".to_owned(),
            OutgoingRetryState {
                timeout_secs: 1,
                next_attempt: now + Duration::from_secs(5),
            },
        );
        let watchdog = RuntimeWatchdog {
            interval: Duration::ZERO,
            next_ping: now + Duration::from_secs(1),
        };

        let timeout = runtime_event_wait_timeout(&runtime, &watchdog).unwrap();

        assert!(timeout <= Duration::from_secs(5));
    }

    #[test]
    fn runtime_event_wait_timeout_wakes_immediately_for_due_deadline() {
        let mut tree = ConfigTree::new();
        tree.add(Config::new(
            "Name",
            "alpha",
            tinc_core::config::ConfigSource::command_line(1),
        ));
        let config = RuntimeConfig::from_config_tree(&tree).unwrap();
        let now = Instant::now();
        let mut runtime = RuntimeDaemonState::new(
            Vec::new(),
            &config,
            RuntimeKeys {
                private_key: None,
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        );
        runtime.next_tinc_periodic = now + Duration::from_secs(30);
        runtime.next_mac_subnet_age = now + Duration::from_secs(30);
        runtime.next_meta_ping_check = now + Duration::from_secs(30);
        runtime.next_past_request_age = Some(now - Duration::from_secs(1));
        let watchdog = RuntimeWatchdog {
            interval: Duration::ZERO,
            next_ping: now + Duration::from_secs(30),
        };

        let timeout = runtime_event_wait_timeout(&runtime, &watchdog).unwrap();

        assert_eq!(Duration::ZERO, timeout);
    }

    #[test]
    fn runtime_event_wait_timeout_does_not_spin_on_expired_fd_gate() {
        let mut tree = ConfigTree::new();
        tree.add(Config::new(
            "Name",
            "alpha",
            tinc_core::config::ConfigSource::command_line(1),
        ));
        let config = RuntimeConfig::from_config_tree(&tree).unwrap();
        let now = Instant::now();
        let mut runtime = RuntimeDaemonState::new(
            Vec::new(),
            &config,
            RuntimeKeys {
                private_key: None,
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        );
        runtime.next_tinc_periodic = now + Duration::from_secs(30);
        runtime.next_mac_subnet_age = now + Duration::from_secs(30);
        runtime.next_meta_ping_check = now + Duration::from_secs(30);
        runtime.device_read_backoff_until = Some(now - Duration::from_secs(1));
        let watchdog = RuntimeWatchdog {
            interval: Duration::ZERO,
            next_ping: now + Duration::from_secs(30),
        };

        let timeout = runtime_event_wait_timeout(&runtime, &watchdog).unwrap();

        assert!(timeout > Duration::from_secs(20));
    }

    #[test]
    fn runtime_event_wait_timeout_ignores_retry_deadline_with_pending_connection_like_tinc() {
        let mut tree = ConfigTree::new();
        tree.add(Config::new(
            "Name",
            "alpha",
            tinc_core::config::ConfigSource::command_line(1),
        ));
        let config = RuntimeConfig::from_config_tree(&tree).unwrap();
        let now = Instant::now();
        let mut runtime = RuntimeDaemonState::new(
            Vec::new(),
            &config,
            RuntimeKeys {
                private_key: None,
                peer_public_keys: BTreeMap::new(),
                rsa_private_key: None,
                peer_rsa_public_keys: BTreeMap::new(),
            },
        );
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind pending connection test listener: {error}"),
        };
        let remote_stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, peer) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let local = stream.local_addr().unwrap();
        let driver = RuntimeMetaDriver::modern(MetaConnectionDriver::new(MetaConnectionAuth::new(
            "alpha",
            true,
            test_key(1),
            test_key(2).public_key(),
            "655",
            0,
            0,
        )));
        let connection = RuntimeMetaConnection {
            id: 1,
            stream,
            peer,
            local,
            bytes_read: 0,
            bytes_written: 0,
            outbound: Vec::new(),
            outbound_offset: 0,
            status: CONNECTION_STATUS_ACTIVE,
            options: 0,
            outgoing_peer: None,
            outgoing_autoconnect: false,
            connecting: true,
            close_requested: false,
            last_activity: now,
            last_ping_time: now,
            last_ping_sent: None,
            edge_peer: None,
            exec_proxy: None,
            kind: RuntimeMetaConnectionKind::Active {
                driver,
                name: Some("beta".to_owned()),
                proxy: ProxyHandshake::None,
            },
        };
        let _remote_stream = remote_stream;
        runtime.meta_connections.push(connection);
        runtime.next_key_expire = None;
        runtime.next_mac_subnet_age = now + Duration::from_secs(30);
        runtime.next_tinc_periodic = now + Duration::from_secs(60);
        runtime.next_meta_ping_check = now + Duration::from_secs(60);
        runtime.outgoing_retry.insert(
            "beta".to_owned(),
            OutgoingRetryState {
                timeout_secs: 0,
                next_attempt: now,
            },
        );
        let watchdog = RuntimeWatchdog {
            interval: Duration::ZERO,
            next_ping: now,
        };

        let timeout = runtime_event_wait_timeout(&runtime, &watchdog).unwrap();

        assert!(
            timeout >= Duration::from_secs(4),
            "C keeps retry timers idle while an outgoing connection object exists; Rust must not spin on next_attempt=now for a pending/active meta connection"
        );
    }

    fn test_key(byte: u8) -> TincEd25519PrivateKey {
        TincEd25519PrivateKey::from_seed([byte; ED25519_SEED_LEN])
    }
}
