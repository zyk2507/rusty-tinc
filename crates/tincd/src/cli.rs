use crate::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliAction {
    Exit {
        code: u8,
        output: String,
    },
    Loaded(RuntimeConfig),
    RunDaemon {
        options: TincdOptions,
        config: RuntimeConfig,
        control: ControlEndpoint,
        keys: RuntimeKeys,
    },
    RunForeground {
        options: TincdOptions,
        config: RuntimeConfig,
        control: ControlEndpoint,
        keys: RuntimeKeys,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TincdOptions {
    pub program_name: String,
    pub confbase: Option<PathBuf>,
    pub netname: Option<String>,
    pub command_line_options: Vec<Config>,
    pub no_detach: bool,
    pub debug_level: Option<Option<i32>>,
    pub lock_memory: bool,
    pub use_syslog: bool,
    pub logfile: Option<Option<PathBuf>>,
    pub pidfile: Option<PathBuf>,
    pub bypass_security: bool,
    pub chroot: bool,
    pub user: Option<String>,
}

impl TincdOptions {
    pub(crate) fn new(program_name: String) -> Self {
        Self {
            program_name,
            confbase: None,
            netname: None,
            command_line_options: Vec::new(),
            no_detach: false,
            debug_level: None,
            lock_memory: false,
            use_syslog: false,
            logfile: None,
            pidfile: None,
            bypass_security: false,
            chroot: false,
            user: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TincdError {
    MissingArgument { option: String },
    UnexpectedArgument(String),
    UnknownOption(String),
    InvalidNetname(String),
    ConfigOption(ConfigParseError),
    ConfigLoad(ConfigLoadError),
    RuntimeConfig(RuntimeConfigError),
    UnsupportedLegacyCompression(CompressionLevel),
    ControlIo(String),
    ControlHandshake(String),
    InvalidListenAddress(String),
    ListenIo(String),
    MetaConnection(String),
    LegacyPacket(LegacyPacketError),
    RuntimeState(String),
    SandboxPolicy(String),
    UnknownPeerKey(String),
    KeyIo { path: PathBuf, message: String },
    KeyParse { path: PathBuf, message: String },
}

impl fmt::Display for TincdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArgument { option } => write!(f, "missing argument for {option}"),
            Self::UnexpectedArgument(argument) => write!(f, "unrecognized argument {argument}"),
            Self::UnknownOption(option) => write!(f, "unknown option {option}"),
            Self::InvalidNetname(netname) => write!(f, "invalid character in netname {netname}"),
            Self::ConfigOption(error) => write!(f, "{error}"),
            Self::ConfigLoad(error) => write!(f, "{error}"),
            Self::RuntimeConfig(error) => write!(f, "{error}"),
            Self::UnsupportedLegacyCompression(compression) => {
                let name = unsupported_legacy_compression_name(*compression);
                write!(
                    f,
                    "Bogus compression level!\n{name} compression is unavailable on this node."
                )
            }
            Self::ControlIo(error) => write!(f, "control socket error: {error}"),
            Self::ControlHandshake(line) => write!(f, "control socket handshake failed: {line}"),
            Self::InvalidListenAddress(address) => write!(f, "invalid listen address {address}"),
            Self::ListenIo(error) => write!(f, "listen socket error: {error}"),
            Self::MetaConnection(error) => write!(f, "meta connection error: {error}"),
            Self::LegacyPacket(error) => write!(f, "legacy packet error: {error}"),
            Self::RuntimeState(error) => write!(f, "runtime state error: {error}"),
            Self::SandboxPolicy(error) => write!(f, "{error}"),
            Self::UnknownPeerKey(peer) => write!(f, "missing Ed25519 public key for peer {peer}"),
            Self::KeyIo { path, message } => {
                write!(f, "could not read key file {}: {message}", path.display())
            }
            Self::KeyParse { path, message } => {
                write!(f, "could not parse key file {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for TincdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConfigOption(error) => Some(error),
            Self::ConfigLoad(error) => Some(error),
            Self::RuntimeConfig(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ConfigLoadError> for TincdError {
    fn from(error: ConfigLoadError) -> Self {
        Self::ConfigLoad(error)
    }
}

impl From<RuntimeConfigError> for TincdError {
    fn from(error: RuntimeConfigError) -> Self {
        Self::RuntimeConfig(error)
    }
}

pub fn run(args: Vec<String>) -> Result<CliAction, TincdError> {
    let parsed = parse_args(args)?;

    match parsed {
        ParsedCommand::Help(program_name) => Ok(CliAction::Exit {
            code: 0,
            output: usage(&program_name),
        }),
        ParsedCommand::Version => Ok(CliAction::Exit {
            code: 0,
            output: version(),
        }),
        ParsedCommand::Run(options) => {
            let mut config = load_runtime_config(&options)?;
            let keys = load_runtime_keys(&options)?;
            reconcile_runtime_config_with_keys(&mut config, &keys);
            let control = ControlEndpoint::new(&options);

            if options.no_detach || systemd_listen_pid_matches_current_process_env() {
                Ok(CliAction::RunForeground {
                    options,
                    config,
                    control,
                    keys,
                })
            } else {
                Ok(CliAction::RunDaemon {
                    options,
                    config,
                    control,
                    keys,
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedCommand {
    Help(String),
    Version,
    Run(TincdOptions),
}

pub fn parse_args(args: Vec<String>) -> Result<ParsedCommand, TincdError> {
    let mut args = args.into_iter().peekable();
    let program_name = args.next().unwrap_or_else(|| "tincd".to_owned());
    let mut options = TincdOptions::new(program_name.clone());
    let mut option_line = 0;

    while let Some(argument) = args.next() {
        if argument == "--help" {
            return Ok(ParsedCommand::Help(program_name));
        }

        if argument == "--version" {
            return Ok(ParsedCommand::Version);
        }

        match argument.as_str() {
            "-c" | "--config" => {
                options.confbase = Some(PathBuf::from(next_arg(&mut args, &argument)?));
            }
            "-n" | "--net" => {
                options.netname = normalize_netname(Some(next_arg(&mut args, &argument)?))?;
            }
            "-o" | "--option" => {
                option_line += 1;
                options.command_line_options.push(parse_cli_config(
                    &next_arg(&mut args, &argument)?,
                    option_line,
                )?);
            }
            "-D" | "--no-detach" => options.no_detach = true,
            "-s" | "--syslog" => {
                options.use_syslog = true;
                options.logfile = None;
            }
            "-R" | "--chroot" => options.chroot = true,
            "-U" | "--user" => options.user = Some(next_arg(&mut args, &argument)?),
            "-L" | "--mlock" => options.lock_memory = true,
            "--bypass-security" => options.bypass_security = true,
            "--pidfile" => options.pidfile = Some(PathBuf::from(next_arg(&mut args, &argument)?)),
            "--logfile" => {
                options.use_syslog = false;
                options.logfile = Some(next_optional_path(&mut args));
            }
            "-d" | "--debug" => {
                apply_debug_option(
                    &mut options,
                    next_optional_value(&mut args).map(|value| value.parse().unwrap_or_default()),
                );
            }
            _ if argument.starts_with("--config=") => {
                options.confbase = Some(PathBuf::from(value_after_equals(&argument)));
            }
            _ if argument.starts_with("--net=") => {
                options.netname = normalize_netname(Some(value_after_equals(&argument)))?;
            }
            _ if argument.starts_with("--option=") => {
                option_line += 1;
                options.command_line_options.push(parse_cli_config(
                    &value_after_equals(&argument),
                    option_line,
                )?);
            }
            _ if argument.starts_with("--pidfile=") => {
                options.pidfile = Some(PathBuf::from(value_after_equals(&argument)));
            }
            _ if argument.starts_with("--logfile=") => {
                options.use_syslog = false;
                options.logfile = Some(Some(PathBuf::from(value_after_equals(&argument))));
            }
            _ if argument.starts_with("--debug=") => {
                apply_debug_option(
                    &mut options,
                    Some(value_after_equals(&argument).parse().unwrap_or_default()),
                );
            }
            _ if argument.starts_with("-d") && argument.len() > 2 => {
                apply_debug_option(
                    &mut options,
                    Some(argument[2..].parse().unwrap_or_default()),
                );
            }
            _ if argument.starts_with('-') => return Err(TincdError::UnknownOption(argument)),
            _ => return Err(TincdError::UnexpectedArgument(argument)),
        }
    }

    if options.netname.is_none() {
        options.netname = normalize_netname(env::var("NETNAME").ok())?;
    }

    Ok(ParsedCommand::Run(options))
}

pub(crate) fn apply_debug_option(options: &mut TincdOptions, value: Option<i32>) {
    match value {
        Some(level) => options.debug_level = Some(Some(level)),
        None => {
            options.debug_level = Some(match options.debug_level {
                None => None,
                Some(None) => Some(2),
                Some(Some(level)) => Some(level + 1),
            });
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RuntimeKeys {
    pub private_key: Option<TincEd25519PrivateKey>,
    pub peer_public_keys: BTreeMap<String, TincEd25519PublicKey>,
    pub rsa_private_key: Option<RuntimeRsaPrivateKey>,
    pub peer_rsa_public_keys: BTreeMap<String, RsaPublicKey>,
}

#[derive(Clone, Eq, PartialEq)]
pub enum RuntimeRsaPrivateKey {
    Pem(RsaPrivateKey),
    LegacyHex {
        public_key: RsaPublicKey,
        private_exponent: BigUint,
    },
}

impl RuntimeRsaPrivateKey {
    pub fn public_key(&self) -> RsaPublicKey {
        match self {
            Self::Pem(key) => RsaPublicKey::from(key),
            Self::LegacyHex { public_key, .. } => public_key.clone(),
        }
    }

    pub fn rsa_size(&self) -> usize {
        legacy_meta_rsa_size(&self.public_key())
    }

    pub fn legacy_meta_private_key(&self) -> LegacyMetaPrivateKey {
        match self {
            Self::Pem(key) => LegacyMetaPrivateKey::Pem(key.clone()),
            Self::LegacyHex {
                public_key,
                private_exponent,
            } => LegacyMetaPrivateKey::Components {
                public_key: public_key.clone(),
                private_exponent: private_exponent.clone(),
            },
        }
    }

    pub fn decrypt_legacy_meta_block(&self, ciphertext: &[u8]) -> Result<Vec<u8>, LegacyMetaError> {
        match self {
            Self::Pem(key) => legacy_meta_private_decrypt_pem(key, ciphertext),
            Self::LegacyHex {
                public_key,
                private_exponent,
            } => legacy_meta_private_decrypt_components(public_key, private_exponent, ciphertext),
        }
    }
}

impl fmt::Debug for RuntimeRsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pem(_) => f.write_str("Pem(<redacted>)"),
            Self::LegacyHex { public_key, .. } => f
                .debug_struct("LegacyHex")
                .field("public_key", public_key)
                .field("private_exponent", &"<redacted>")
                .finish(),
        }
    }
}

impl RuntimeKeys {
    pub fn new(
        private_key: TincEd25519PrivateKey,
        peer_public_keys: BTreeMap<String, TincEd25519PublicKey>,
    ) -> Self {
        Self {
            private_key: Some(private_key),
            peer_public_keys,
            rsa_private_key: None,
            peer_rsa_public_keys: BTreeMap::new(),
        }
    }
}

impl fmt::Debug for RuntimeKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeKeys")
            .field("private_key", &self.private_key)
            .field("peer_public_keys", &self.peer_public_keys)
            .field(
                "rsa_private_key",
                &self.rsa_private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("peer_rsa_public_keys", &self.peer_rsa_public_keys)
            .finish()
    }
}

pub fn load_runtime_keys(options: &TincdOptions) -> Result<RuntimeKeys, TincdError> {
    let confbase = resolve_confbase(options);
    let mut server_tree = ConfigTree::new();

    server_tree.read_server_config(&confbase, &options.command_line_options)?;
    let name = server_tree
        .lookup("Name")
        .ok_or(RuntimeConfigError::MissingRequired { variable: "Name" })?
        .value
        .clone();
    server_tree.read_host_config(&confbase, &name, &options.command_line_options)?;
    let host_configs = ConfigTree::read_all_host_configs(&confbase, &options.command_line_options)?;
    let experimental_protocol = server_tree
        .lookup("ExperimentalProtocol")
        .map(Config::as_bool)
        .transpose()
        .map_err(RuntimeConfigError::from)?;
    let private_key = match experimental_protocol {
        Some(false) => None,
        Some(true) => Some(read_private_key(&confbase, &server_tree)?),
        None => read_optional_private_key(&confbase, &server_tree)?,
    };
    let rsa_private_key = read_rsa_private_key(&confbase, &server_tree);
    let peer_rsa_public_keys = read_peer_rsa_public_keys(&confbase, &name, &host_configs);
    let experimental = experimental_protocol.unwrap_or(private_key.is_some());
    let peer_public_keys = if experimental {
        read_peer_public_keys(&confbase, &name, &host_configs)?
    } else {
        BTreeMap::new()
    };

    if experimental && private_key.is_none() {
        return Err(TincdError::RuntimeState(
            "No Ed25519 private key available, cannot start tinc with ExperimentalProtocol enabled"
                .to_owned(),
        ));
    }

    if !experimental && rsa_private_key.is_none() {
        return Err(TincdError::RuntimeState(
            "No private keys available, cannot start tinc!".to_owned(),
        ));
    }

    Ok(RuntimeKeys {
        private_key,
        peer_public_keys,
        rsa_private_key,
        peer_rsa_public_keys,
    })
}

pub fn load_runtime_config(options: &TincdOptions) -> Result<RuntimeConfig, TincdError> {
    let confbase = resolve_confbase(options);
    let mut server_tree = ConfigTree::new();

    server_tree.read_server_config(&confbase, &options.command_line_options)?;
    let name = server_tree
        .lookup("Name")
        .ok_or(RuntimeConfigError::MissingRequired { variable: "Name" })?
        .value
        .clone();
    server_tree.read_host_config(&confbase, &name, &options.command_line_options)?;
    let host_configs = ConfigTree::read_all_host_configs(&confbase, &options.command_line_options)?;

    let config = RuntimeConfig::from_config_tree_with_hosts(
        &server_tree,
        host_configs
            .iter()
            .map(|(name, tree)| (name.as_str(), tree)),
    )?;
    validate_runtime_config_like_tinc(&config)?;
    Ok(config)
}

pub(crate) fn validate_runtime_config_like_tinc(config: &RuntimeConfig) -> Result<(), TincdError> {
    if legacy_compression_is_available(config.daemon.legacy_compression) {
        Ok(())
    } else {
        Err(TincdError::UnsupportedLegacyCompression(
            config.daemon.legacy_compression,
        ))
    }
}

pub(crate) fn unsupported_legacy_compression_name(compression: CompressionLevel) -> &'static str {
    match compression {
        CompressionLevel::LzoLow | CompressionLevel::LzoHigh => "LZO",
        CompressionLevel::Lz4 => "LZ4",
        CompressionLevel::Zlib1
        | CompressionLevel::Zlib2
        | CompressionLevel::Zlib3
        | CompressionLevel::Zlib4
        | CompressionLevel::Zlib5
        | CompressionLevel::Zlib6
        | CompressionLevel::Zlib7
        | CompressionLevel::Zlib8
        | CompressionLevel::Zlib9 => "ZLIB",
        CompressionLevel::None => "None",
    }
}

pub(crate) fn read_private_key(
    confbase: &Path,
    config: &ConfigTree,
) -> Result<TincEd25519PrivateKey, TincdError> {
    let path = private_key_path(confbase, config);
    let data = read_key_file(&path)?;

    TincEd25519PrivateKey::from_pem(&data).map_err(|error| key_parse(&path, error))
}

pub(crate) fn read_optional_private_key(
    confbase: &Path,
    config: &ConfigTree,
) -> Result<Option<TincEd25519PrivateKey>, TincdError> {
    let path = private_key_path(confbase, config);
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(key_io(&path, error)),
    };

    TincEd25519PrivateKey::from_pem(&data)
        .map(Some)
        .map_err(|error| key_parse(&path, error))
}

pub(crate) fn private_key_path(confbase: &Path, config: &ConfigTree) -> PathBuf {
    config
        .lookup("Ed25519PrivateKeyFile")
        .map(|config| PathBuf::from(&config.value))
        .unwrap_or_else(|| confbase.join("ed25519_key.priv"))
}

pub(crate) fn read_peer_public_keys(
    confbase: &Path,
    myself: &str,
    host_configs: &[(String, ConfigTree)],
) -> Result<BTreeMap<String, TincEd25519PublicKey>, TincdError> {
    let mut keys = BTreeMap::new();

    for (name, tree) in host_configs {
        if name == myself {
            continue;
        }

        if let Some(key) = read_peer_public_key(confbase, name, tree)? {
            keys.insert(name.clone(), key);
        }
    }

    Ok(keys)
}

pub(crate) fn read_peer_public_key(
    confbase: &Path,
    name: &str,
    config: &ConfigTree,
) -> Result<Option<TincEd25519PublicKey>, TincdError> {
    if let Some(config) = config.lookup("Ed25519PublicKey") {
        return TincEd25519PublicKey::from_base64(&config.value)
            .map(Some)
            .map_err(|error| TincdError::KeyParse {
                path: PathBuf::from(format!("hosts/{name}:Ed25519PublicKey")),
                message: error.to_string(),
            });
    }

    let path = config
        .lookup("Ed25519PublicKeyFile")
        .map(|config| PathBuf::from(&config.value))
        .unwrap_or_else(|| confbase.join("hosts").join(name));

    match fs::read_to_string(&path) {
        Ok(data) => read_optional_ed25519_public_pem(&path, &data),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(key_io(&path, error)),
    }
}

pub(crate) fn read_optional_ed25519_public_pem(
    path: &Path,
    data: &str,
) -> Result<Option<TincEd25519PublicKey>, TincdError> {
    if !data.contains("-----BEGIN ED25519 PUBLIC KEY-----") {
        return Ok(None);
    }

    TincEd25519PublicKey::from_pem(data)
        .map(Some)
        .map_err(|error| key_parse(path, error))
}

pub(crate) fn read_rsa_private_key(
    confbase: &Path,
    config: &ConfigTree,
) -> Option<RuntimeRsaPrivateKey> {
    if let Some(private_config) = config.lookup("PrivateKey") {
        let public_config = config.lookup("PublicKey")?;
        return rsa_private_key_from_legacy_hex(&public_config.value, &private_config.value);
    }

    let path = config
        .lookup("PrivateKeyFile")
        .map(|config| PathBuf::from(&config.value))
        .unwrap_or_else(|| confbase.join("rsa_key.priv"));
    let data = fs::read_to_string(path).ok()?;

    read_rsa_private_from_text(&data)
}

pub(crate) fn read_peer_rsa_public_keys(
    confbase: &Path,
    myself: &str,
    host_configs: &[(String, ConfigTree)],
) -> BTreeMap<String, RsaPublicKey> {
    let mut keys = BTreeMap::new();

    for (name, tree) in host_configs {
        if name == myself {
            continue;
        }

        if let Some(key) = read_peer_rsa_public_key(confbase, name, tree) {
            keys.insert(name.clone(), key);
        }
    }

    keys
}

pub(crate) fn read_peer_rsa_public_key(
    confbase: &Path,
    name: &str,
    config: &ConfigTree,
) -> Option<RsaPublicKey> {
    if let Some(config) = config.lookup("PublicKey") {
        return rsa_public_key_from_legacy_hex(&config.value);
    }

    let path = config
        .lookup("PublicKeyFile")
        .map(|config| PathBuf::from(&config.value))
        .unwrap_or_else(|| confbase.join("hosts").join(name));
    let data = fs::read_to_string(path).ok()?;

    read_rsa_public_from_text(&data)
}

pub(crate) fn rsa_private_key_from_legacy_hex(
    public: &str,
    private: &str,
) -> Option<RuntimeRsaPrivateKey> {
    let modulus = BigUint::parse_bytes(public.as_bytes(), 16)?;
    let private_exponent = BigUint::parse_bytes(private.as_bytes(), 16)?;
    let public_key = RsaPublicKey::new(modulus, legacy_rsa_exponent()).ok()?;

    Some(RuntimeRsaPrivateKey::LegacyHex {
        public_key,
        private_exponent,
    })
}

pub(crate) fn rsa_public_key_from_legacy_hex(value: &str) -> Option<RsaPublicKey> {
    let modulus = BigUint::parse_bytes(value.as_bytes(), 16)?;
    RsaPublicKey::new(modulus, legacy_rsa_exponent()).ok()
}

pub(crate) fn legacy_rsa_exponent() -> BigUint {
    BigUint::from(0xffffu32)
}

pub(crate) fn read_rsa_private_from_text(contents: &str) -> Option<RuntimeRsaPrivateKey> {
    let pem = extract_pem_block(contents, "RSA PRIVATE KEY")?;
    RsaPrivateKey::from_pkcs1_pem(&pem)
        .ok()
        .map(RuntimeRsaPrivateKey::Pem)
}

pub(crate) fn read_rsa_public_from_text(contents: &str) -> Option<RsaPublicKey> {
    let pem = extract_pem_block(contents, "RSA PUBLIC KEY")?;
    RsaPublicKey::from_pkcs1_pem(&pem).ok()
}

pub(crate) fn extract_pem_block(contents: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = contents.find(&begin)?;
    let end_start = contents[start..].find(&end)? + start;
    let mut end_index = end_start + end.len();

    if contents[end_index..].starts_with("\r\n") {
        end_index += 2;
    } else if contents[end_index..].starts_with('\n') {
        end_index += 1;
    }

    Some(contents[start..end_index].to_owned())
}

pub(crate) fn read_key_file(path: &Path) -> Result<String, TincdError> {
    fs::read_to_string(path).map_err(|error| key_io(path, error))
}

pub(crate) fn key_io(path: &Path, error: io::Error) -> TincdError {
    TincdError::KeyIo {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

pub(crate) fn key_parse(path: &Path, error: SptpsError) -> TincdError {
    TincdError::KeyParse {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

pub(crate) fn read_runtime_invitation_context(
    confbase: PathBuf,
    config: &RuntimeConfig,
) -> Result<Option<RuntimeInvitationContext>, TincdError> {
    let path = confbase.join("invitations").join("ed25519_key.priv");
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(key_io(&path, error)),
    };
    let key = TincEd25519PrivateKey::from_pem(&data).map_err(|error| key_parse(&path, error))?;
    let expire = Duration::from_secs(config.daemon.invitation_expire.max(0) as u64);

    Ok(Some(RuntimeInvitationContext {
        confbase,
        key,
        expire,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeInvitationFile {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn read_runtime_invitation_file(
    context: &RuntimeInvitationContext,
    local_name: &str,
    cookie: &[u8],
) -> Result<RuntimeInvitationFile, TincdError> {
    if cookie.len() != INVITATION_COOKIE_LEN {
        return Err(TincdError::MetaConnection(format!(
            "invalid invitation cookie length {}",
            cookie.len()
        )));
    }

    let invitation_public = context.key.public_key().to_base64();
    let filename = invitation_cookie_filename(cookie, &invitation_public);
    let invitations_dir = context.confbase.join("invitations");
    let path = invitations_dir.join(&filename);
    let used_path = invitations_dir.join(format!("{filename}.used"));

    fs::rename(&path, &used_path).map_err(|error| {
        TincdError::RuntimeState(format!(
            "could not rename invitation {} to {}: {error}",
            path.display(),
            used_path.display()
        ))
    })?;

    read_renamed_runtime_invitation_file(&used_path, context.expire, local_name)
}

pub(crate) fn read_renamed_runtime_invitation_file(
    path: &Path,
    expire: Duration,
    local_name: &str,
) -> Result<RuntimeInvitationFile, TincdError> {
    let metadata = fs::metadata(path).map_err(|error| {
        TincdError::RuntimeState(format!(
            "could not stat invitation {}: {error}",
            path.display()
        ))
    })?;
    let modified = metadata.modified().map_err(|error| {
        TincdError::RuntimeState(format!(
            "could not read invitation timestamp {}: {error}",
            path.display()
        ))
    })?;

    if SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default()
        > expire
    {
        return Err(TincdError::RuntimeState(format!(
            "invitation {} has expired",
            path.display()
        )));
    }

    let data = fs::read(path).map_err(|error| {
        TincdError::RuntimeState(format!(
            "could not read invitation {}: {error}",
            path.display()
        ))
    })?;
    let text = std::str::from_utf8(&data).map_err(|_| {
        TincdError::RuntimeState(format!("invitation {} is not valid UTF-8", path.display()))
    })?;
    let name = runtime_invitation_name(text, local_name).ok_or_else(|| {
        TincdError::RuntimeState(format!("invalid invitation file {}", path.display()))
    })?;

    fs::remove_file(path).map_err(|error| {
        TincdError::RuntimeState(format!(
            "could not remove used invitation {}: {error}",
            path.display()
        ))
    })?;

    Ok(RuntimeInvitationFile { name, data })
}

pub(crate) fn invitation_cookie_filename(cookie: &[u8], invitation_public: &str) -> String {
    let mut input = Vec::with_capacity(cookie.len() + invitation_public.len());
    input.extend_from_slice(cookie);
    input.extend_from_slice(invitation_public.as_bytes());
    hash18_tinc_urlsafe(&input)
}

pub(crate) fn runtime_invitation_name(data: &str, local_name: &str) -> Option<String> {
    let first = data
        .lines()
        .next()?
        .trim_end_matches([' ', '\t', '\r', '\n']);
    let (variable, value) = parse_runtime_config_line(first);

    if variable.eq_ignore_ascii_case("Name") && check_id(value) && value != local_name {
        Some(value.to_owned())
    } else {
        None
    }
}

pub(crate) fn parse_runtime_config_line(line: &str) -> (&str, &str) {
    let variable_end = line
        .find(|ch: char| ch == ' ' || ch == '\t' || ch == '=')
        .unwrap_or(line.len());
    let mut value = line[variable_end..].trim_start_matches([' ', '\t']);

    if let Some(rest) = value.strip_prefix('=') {
        value = rest.trim_start_matches([' ', '\t']);
    }

    (&line[..variable_end], value)
}

pub(crate) fn accept_runtime_invitation_public_key(
    confbase: &Path,
    name: &str,
    payload: &[u8],
) -> Result<TincEd25519PublicKey, TincdError> {
    let public_key = std::str::from_utf8(payload).map_err(|_| {
        TincdError::MetaConnection("invited node sent a non-UTF-8 public key".to_owned())
    })?;

    if public_key.contains('\n') {
        return Err(TincdError::MetaConnection(format!(
            "invited node {name} sent an invalid public key"
        )));
    }

    let key = TincEd25519PublicKey::from_base64(public_key).map_err(|error| {
        TincdError::MetaConnection(format!(
            "invited node {name} sent an invalid public key: {error}"
        ))
    })?;
    let hosts_dir = confbase.join("hosts");
    let path = hosts_dir.join(name);
    fs::create_dir_all(&hosts_dir).map_err(|error| {
        TincdError::RuntimeState(format!(
            "could not create hosts directory {}: {error}",
            hosts_dir.display()
        ))
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            TincdError::RuntimeState(format!(
                "could not create host file {}: {error}",
                path.display()
            ))
        })?;
    writeln!(file, "Ed25519PublicKey = {public_key}").map_err(|error| {
        TincdError::RuntimeState(format!(
            "could not write host file {}: {error}",
            path.display()
        ))
    })?;

    Ok(key)
}

pub(crate) fn append_runtime_host_config(
    confbase: &Path,
    name: &str,
    key: &str,
    value: &str,
) -> io::Result<()> {
    let path = confbase.join("hosts").join(name);
    let mut file = OpenOptions::new().append(true).create(true).open(path)?;
    writeln!(
        file,
        "\n# The following line was automatically added by tinc\n{key} = {value}"
    )
}

pub(crate) fn hash18_tinc_urlsafe(input: &[u8]) -> String {
    b64encode_tinc_urlsafe(&hash18_bytes(input))
}

pub(crate) fn hash18_bytes(input: &[u8]) -> [u8; INVITATION_COOKIE_LEN] {
    let digest = Sha512::digest(input);
    digest[..INVITATION_COOKIE_LEN]
        .try_into()
        .expect("SHA-512 digest has at least 18 bytes")
}

pub fn resolve_confbase(options: &TincdOptions) -> PathBuf {
    if let Some(confbase) = &options.confbase {
        return confbase.clone();
    }

    match &options.netname {
        Some(netname) => Path::new(DEFAULT_CONFDIR).join(netname),
        None => PathBuf::from(DEFAULT_CONFDIR),
    }
}

pub(crate) fn run_daemon_script(
    name: &str,
    config: &RuntimeConfig,
    options: &TincdOptions,
    device_info: &DeviceInfo,
    extra_env: &[(&str, String)],
) -> Result<bool, TincdError> {
    let path = resolve_confbase(options).join(format!("{name}{}", config.daemon.scripts.extension));
    if !path.exists() {
        return Ok(false);
    }

    let mut command = script_command(&path, config)?;
    command.env("NAME", &config.name);
    if let Some(netname) = &options.netname {
        command.env("NETNAME", netname);
    }
    command.env("DEVICE", &device_info.device);
    if let Some(interface) = &device_info.interface {
        command.env("INTERFACE", interface);
    }
    if let Some(debug) = options.debug_level {
        command.env("DEBUG", debug.unwrap_or(1).to_string());
    }
    for (key, value) in extra_env {
        command.env(key, value);
    }

    let status = command.status().map_err(|error| {
        TincdError::RuntimeState(format!(
            "could not execute script {}: {error}",
            path.display()
        ))
    })?;
    if status.success() {
        Ok(true)
    } else {
        Err(TincdError::RuntimeState(format!(
            "script {} exited with {status}",
            path.display()
        )))
    }
}

pub(crate) fn script_command(path: &Path, config: &RuntimeConfig) -> Result<Command, TincdError> {
    let Some(interpreter) = config
        .daemon
        .scripts
        .interpreter
        .as_deref()
        .map(str::trim)
        .filter(|interpreter| !interpreter.is_empty())
    else {
        return Ok(Command::new(path));
    };

    let mut parts = interpreter.split_whitespace();
    let program = parts.next().ok_or_else(|| {
        TincdError::RuntimeState("ScriptsInterpreter did not contain a command".to_owned())
    })?;
    let mut command = Command::new(program);
    command.args(parts);
    command.arg(path);
    Ok(command)
}

pub(crate) fn script_subnet_env(subnet: &Subnet) -> (String, String) {
    let value = subnet.to_string();
    value
        .split_once('#')
        .map(|(subnet, weight)| (subnet.to_owned(), weight.to_owned()))
        .unwrap_or((value, String::new()))
}
