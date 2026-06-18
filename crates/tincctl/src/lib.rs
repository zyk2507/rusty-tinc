// SPDX-License-Identifier: GPL-2.0-or-later

use std::env;
#[cfg(unix)]
use std::ffi::CStr;
#[cfg(unix)]
use std::ffi::CString;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
#[cfg(not(unix))]
use std::net::{TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding,
};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha512};
use tinc_core::graph::{
    OPTION_CLAMP_MSS, OPTION_INDIRECT, OPTION_PMTU_DISCOVERY, OPTION_TCPONLY, option_version,
};
use tinc_core::protocol::{AckMessage, IdMessage, MetaMessage, Request, parse_meta_message};
use tinc_core::protocol::{PROT_MAJOR, PROT_MINOR};
use tinc_core::subnet::{Subnet, SubnetKind};
use tinc_core::utils::{
    b64decode_tinc, b64encode_tinc, b64encode_tinc_urlsafe, check_id, check_netname,
};
use tinc_runtime::meta::{MetaStreamDecoder, MetaStreamFrame};
use tinc_runtime::sptps::{
    ED25519_SEED_LEN, ED25519_SIGNATURE_LEN, SptpsHandshakeEvent, SptpsHandshakeSession,
    TincEd25519PrivateKey, TincEd25519PublicKey,
};

pub const DEFAULT_CONFDIR: &str = "/etc/tinc";

const DEFAULT_TINC_PORT: u16 = 655;
const INIT_RANDOM_PORT_BASE: u16 = 0x1000;
const INIT_RANDOM_PORT_SPAN: u16 = 0x8000;
const INIT_RANDOM_PORT_ATTEMPTS: usize = 100;

const COMMANDS: &[CommandSpec] = &[
    CommandSpec::visible("start"),
    CommandSpec::visible("stop"),
    CommandSpec::visible("restart"),
    CommandSpec::visible("reload"),
    CommandSpec::visible("dump"),
    CommandSpec::visible("list"),
    CommandSpec::visible("purge"),
    CommandSpec::visible("debug"),
    CommandSpec::visible("retry"),
    CommandSpec::visible("connect"),
    CommandSpec::visible("disconnect"),
    CommandSpec::visible("top"),
    CommandSpec::visible("pcap"),
    CommandSpec::visible("log"),
    CommandSpec::visible("pid"),
    CommandSpec::hidden("config"),
    CommandSpec::visible("add"),
    CommandSpec::visible("del"),
    CommandSpec::visible("get"),
    CommandSpec::visible("set"),
    CommandSpec::visible("init"),
    CommandSpec::visible("generate-keys"),
    CommandSpec::visible("generate-rsa-keys"),
    CommandSpec::visible("generate-ed25519-keys"),
    CommandSpec::visible("help"),
    CommandSpec::visible("version"),
    CommandSpec::visible("info"),
    CommandSpec::visible("edit"),
    CommandSpec::visible("export"),
    CommandSpec::visible("export-all"),
    CommandSpec::visible("import"),
    CommandSpec::visible("exchange"),
    CommandSpec::visible("exchange-all"),
    CommandSpec::visible("invite"),
    CommandSpec::visible("join"),
    CommandSpec::visible("network"),
    CommandSpec::visible("fsck"),
    CommandSpec::visible("sign"),
    CommandSpec::visible("verify"),
];

const VAR_SERVER: u8 = 0x01;
const VAR_HOST: u8 = 0x02;
const VAR_MULTIPLE: u8 = 0x04;
const VAR_OBSOLETE: u8 = 0x08;
const VAR_SAFE: u8 = 0x10;
const TINC_CTL_VERSION_CURRENT: i32 = 0;
const DEFAULT_RSA_BITS: usize = 2048;
const MIN_RSA_BITS: usize = 1024;
const MAX_RSA_BITS: usize = 8192;
const REQ_STOP: i32 = 0;
const REQ_RELOAD: i32 = 1;
const REQ_DUMP_NODES: i32 = 3;
const REQ_DUMP_EDGES: i32 = 4;
const REQ_DUMP_SUBNETS: i32 = 5;
const REQ_DUMP_CONNECTIONS: i32 = 6;
const REQ_PURGE: i32 = 8;
const REQ_SET_DEBUG: i32 = 9;
const REQ_RETRY: i32 = 10;
const REQ_CONNECT: i32 = 11;
const REQ_DISCONNECT: i32 = 12;
const REQ_DUMP_TRAFFIC: i32 = 13;
const REQ_PCAP: i32 = 14;
const REQ_LOG: i32 = 15;
const DEBUG_UNSET: i32 = -1;
const LOG_CONTROL_BUFFER_SIZE: usize = 1024;
const PCAP_CONTROL_BUFFER_SIZE: usize = 9018;
const INVITATION_LABEL: &[u8] = b"tinc invitation";
const INVITATION_TIMEOUT: Duration = Duration::from_secs(5);
const EDIT_CONFIG_FILES: &[&str] = &[
    "tinc.conf",
    "tinc-up",
    "tinc-down",
    "subnet-up",
    "subnet-down",
    "host-up",
    "host-down",
];

const VARIABLES: &[VariableSpec] = &[
    VariableSpec::new("AddressFamily", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("AutoConnect", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("BindToAddress", VAR_SERVER | VAR_MULTIPLE),
    VariableSpec::new("BindToInterface", VAR_SERVER),
    VariableSpec::new("Broadcast", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("BroadcastSubnet", VAR_SERVER | VAR_MULTIPLE | VAR_SAFE),
    VariableSpec::new("ConnectTo", VAR_SERVER | VAR_MULTIPLE | VAR_SAFE),
    VariableSpec::new("DecrementTTL", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("Device", VAR_SERVER),
    VariableSpec::new("DeviceStandby", VAR_SERVER),
    VariableSpec::new("DeviceType", VAR_SERVER),
    VariableSpec::new("DirectOnly", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("Ed25519PrivateKeyFile", VAR_SERVER),
    VariableSpec::new("ExperimentalProtocol", VAR_SERVER),
    VariableSpec::new("Forwarding", VAR_SERVER),
    VariableSpec::new("FWMark", VAR_SERVER),
    VariableSpec::new("GraphDumpFile", VAR_SERVER | VAR_OBSOLETE),
    VariableSpec::new("Hostnames", VAR_SERVER),
    VariableSpec::new("IffOneQueue", VAR_SERVER),
    VariableSpec::new("Interface", VAR_SERVER),
    VariableSpec::new("InvitationExpire", VAR_SERVER),
    VariableSpec::new("KeyExpire", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("ListenAddress", VAR_SERVER | VAR_MULTIPLE),
    VariableSpec::new("LocalDiscovery", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("LogLevel", VAR_SERVER),
    VariableSpec::new("MACExpire", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("MaxConnectionBurst", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("MaxOutputBufferSize", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("MaxTimeout", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("Mode", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("Name", VAR_SERVER),
    VariableSpec::new("PingInterval", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("PingTimeout", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("PriorityInheritance", VAR_SERVER),
    VariableSpec::new("PrivateKey", VAR_SERVER | VAR_OBSOLETE),
    VariableSpec::new("PrivateKeyFile", VAR_SERVER),
    VariableSpec::new("ProcessPriority", VAR_SERVER),
    VariableSpec::new("Proxy", VAR_SERVER),
    VariableSpec::new("ReplayWindow", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("Sandbox", VAR_SERVER),
    VariableSpec::new("ScriptsExtension", VAR_SERVER),
    VariableSpec::new("ScriptsInterpreter", VAR_SERVER),
    VariableSpec::new("StrictSubnets", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("TunnelServer", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("UDPDiscovery", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("UDPDiscoveryKeepaliveInterval", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("UDPDiscoveryInterval", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("UDPDiscoveryTimeout", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("MTUInfoInterval", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("UDPInfoInterval", VAR_SERVER | VAR_SAFE),
    VariableSpec::new("UDPRcvBuf", VAR_SERVER),
    VariableSpec::new("UDPSndBuf", VAR_SERVER),
    VariableSpec::new("UPnP", VAR_SERVER),
    VariableSpec::new("UPnPDiscoverWait", VAR_SERVER),
    VariableSpec::new("UPnPRefreshPeriod", VAR_SERVER),
    VariableSpec::new("VDEGroup", VAR_SERVER),
    VariableSpec::new("VDEPort", VAR_SERVER),
    VariableSpec::new("Address", VAR_HOST | VAR_MULTIPLE),
    VariableSpec::new("Cipher", VAR_SERVER | VAR_HOST),
    VariableSpec::new("ClampMSS", VAR_SERVER | VAR_HOST | VAR_SAFE),
    VariableSpec::new("Compression", VAR_SERVER | VAR_HOST | VAR_SAFE),
    VariableSpec::new("Digest", VAR_SERVER | VAR_HOST),
    VariableSpec::new("Ed25519PublicKey", VAR_HOST),
    VariableSpec::new("Ed25519PublicKeyFile", VAR_SERVER | VAR_HOST),
    VariableSpec::new("IndirectData", VAR_SERVER | VAR_HOST | VAR_SAFE),
    VariableSpec::new("MACLength", VAR_SERVER | VAR_HOST),
    VariableSpec::new("PMTU", VAR_SERVER | VAR_HOST),
    VariableSpec::new("PMTUDiscovery", VAR_SERVER | VAR_HOST),
    VariableSpec::new("Port", VAR_HOST),
    VariableSpec::new("PublicKey", VAR_HOST | VAR_OBSOLETE),
    VariableSpec::new("PublicKeyFile", VAR_SERVER | VAR_HOST | VAR_OBSOLETE),
    VariableSpec::new("Subnet", VAR_HOST | VAR_MULTIPLE | VAR_SAFE),
    VariableSpec::new("TCPOnly", VAR_SERVER | VAR_HOST | VAR_SAFE),
    VariableSpec::new("Weight", VAR_HOST | VAR_SAFE),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VariableSpec {
    name: &'static str,
    flags: u8,
}

impl VariableSpec {
    const fn new(name: &'static str, flags: u8) -> Self {
        Self { name, flags }
    }

    const fn is_server(self) -> bool {
        self.flags & VAR_SERVER != 0
    }

    const fn is_host(self) -> bool {
        self.flags & VAR_HOST != 0
    }

    const fn is_multiple(self) -> bool {
        self.flags & VAR_MULTIPLE != 0
    }

    const fn is_obsolete(self) -> bool {
        self.flags & VAR_OBSOLETE != 0
    }

    const fn is_safe(self) -> bool {
        self.flags & VAR_SAFE != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub name: &'static str,
    pub hidden: bool,
}

impl CommandSpec {
    const fn visible(name: &'static str) -> Self {
        Self {
            name,
            hidden: false,
        }
    }

    const fn hidden(name: &'static str) -> Self {
        Self { name, hidden: true }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliAction {
    Exit { code: u8, output: String },
    ExitBytes { code: u8, output: Vec<u8> },
    Command(TincCommand),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TincOptions {
    pub program_name: String,
    pub confbase: Option<PathBuf>,
    pub confbase_given: bool,
    pub netname: Option<String>,
    pub batch: bool,
    pub pidfile: Option<PathBuf>,
    pub force: bool,
}

impl TincOptions {
    fn new(program_name: String) -> Self {
        Self {
            program_name,
            confbase: None,
            confbase_given: false,
            netname: None,
            batch: false,
            pidfile: None,
            force: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TincCommand {
    pub options: TincOptions,
    pub name: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedCommand {
    Help(String),
    Version,
    Command(TincCommand),
    Shell(TincOptions),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TincError {
    MissingArgument { option: String },
    InvalidArguments(String),
    TooManyArguments,
    MissingName,
    UnknownOption(String),
    MissingCommand,
    UnknownCommand(String),
    InvalidNetname(String),
    InvalidNodeName(String),
    UnknownVariable(String),
    ObsoleteVariable(String),
    ServerVariableInHostFile(String),
    MissingValue(String),
    MalformedSubnet(String),
    NonCanonicalSubnet(String),
    MissingLocalName,
    ConfigurationExists(PathBuf),
    InvalidPidFile(PathBuf),
    ControlUnsupported,
    ControlConnection(String),
    ControlHandshake(String),
    ControlResponse(String),
    StartFailed(String),
    UnknownDumpType(String),
    DumpParse(String),
    UnknownNode(String),
    UnknownSubnet(String),
    UnknownAddress(String),
    NoMatchingConfigurationVariables,
    NoConfigurationVariablesDeleted,
    NoHostConfigurationsImported,
    InvitationFailed(String),
    Random(String),
    EditFailed(String),
    Io { path: PathBuf, error: String },
}

impl fmt::Display for TincError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArgument { option } => write!(f, "missing argument for {option}"),
            Self::InvalidArguments(message) => write!(f, "{message}"),
            Self::TooManyArguments => write!(f, "too many arguments"),
            Self::MissingName => write!(f, "no Name given"),
            Self::UnknownOption(option) => write!(f, "unknown option {option}"),
            Self::MissingCommand => write!(f, "missing command"),
            Self::UnknownCommand(command) => write!(f, "unknown command {command}"),
            Self::InvalidNetname(netname) => write!(f, "invalid character in netname {netname}"),
            Self::InvalidNodeName(node) => write!(f, "invalid name for node {node}"),
            Self::UnknownVariable(variable) => write!(
                f,
                "{variable}: is not a known configuration variable; use --force to use it anyway"
            ),
            Self::ObsoleteVariable(variable) => {
                write!(
                    f,
                    "{variable} is an obsolete variable; use --force to use it anyway"
                )
            }
            Self::ServerVariableInHostFile(variable) => write!(
                f,
                "{variable} is not a host configuration variable; use --force to use it anyway"
            ),
            Self::MissingValue(variable) => write!(f, "no value for variable {variable} given"),
            Self::MalformedSubnet(value) => write!(f, "malformed subnet definition {value}"),
            Self::NonCanonicalSubnet(value) => {
                write!(f, "network address and prefix length do not match: {value}")
            }
            Self::MissingLocalName => write!(f, "could not determine local node name"),
            Self::ConfigurationExists(path) => {
                write!(f, "configuration file {} already exists", path.display())
            }
            Self::InvalidPidFile(path) => write!(f, "invalid pid file {}", path.display()),
            Self::ControlUnsupported => {
                write!(f, "control sockets are not supported on this platform yet")
            }
            Self::ControlConnection(error) => {
                write!(f, "control socket connection failed: {error}")
            }
            Self::ControlHandshake(error) => write!(f, "control socket handshake failed: {error}"),
            Self::ControlResponse(error) => write!(f, "control socket response failed: {error}"),
            Self::StartFailed(error) => write!(f, "could not start tincd: {error}"),
            Self::UnknownDumpType(kind) => write!(f, "unknown dump type {kind}"),
            Self::DumpParse(line) => write!(f, "unable to parse dump from tincd: {line}"),
            Self::UnknownNode(node) => write!(f, "unknown node {node}"),
            Self::UnknownSubnet(subnet) => write!(f, "unknown subnet {subnet}"),
            Self::UnknownAddress(address) => write!(f, "unknown address {address}"),
            Self::NoMatchingConfigurationVariables => {
                write!(f, "no matching configuration variables found")
            }
            Self::NoConfigurationVariablesDeleted => {
                write!(f, "no configuration variables deleted")
            }
            Self::NoHostConfigurationsImported => {
                write!(f, "no host configuration files imported")
            }
            Self::InvitationFailed(message) => write!(f, "{message}"),
            Self::Random(error) => write!(f, "random generation failed: {error}"),
            Self::EditFailed(error) => write!(f, "editor failed: {error}"),
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for TincError {}

pub fn run(args: Vec<String>) -> Result<CliAction, TincError> {
    run_with_input_bytes(args, b"")
}

pub fn run_with_input(args: Vec<String>, input: &str) -> Result<CliAction, TincError> {
    run_with_input_bytes(args, input.as_bytes())
}

pub fn run_with_stdio(args: Vec<String>) -> Result<CliAction, TincError> {
    match parse_args(args)? {
        ParsedCommand::Help(program_name) => Ok(CliAction::Exit {
            code: 0,
            output: usage(&program_name),
        }),
        ParsedCommand::Version => Ok(CliAction::Exit {
            code: 0,
            output: version(),
        }),
        ParsedCommand::Command(command) => {
            let mut input = Vec::new();

            if command_reads_stdin(&command) {
                io::stdin()
                    .read_to_end(&mut input)
                    .map_err(|error| TincError::Io {
                        path: PathBuf::from("stdin"),
                        error: error.to_string(),
                    })?;
            }

            run_command_action(command, &input)
        }
        ParsedCommand::Shell(options) => run_stdio_shell(options),
    }
}

pub fn run_with_input_bytes(args: Vec<String>, input: &[u8]) -> Result<CliAction, TincError> {
    match parse_args(args)? {
        ParsedCommand::Help(program_name) => Ok(CliAction::Exit {
            code: 0,
            output: usage(&program_name),
        }),
        ParsedCommand::Version => Ok(CliAction::Exit {
            code: 0,
            output: version(),
        }),
        ParsedCommand::Command(command) => run_command_action(command, input),
        ParsedCommand::Shell(options) => run_shell_bytes(options, input, false),
    }
}

pub fn run_stdio_shell(options: TincOptions) -> Result<CliAction, TincError> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let interactive = stdin.is_terminal() && stdout.is_terminal() && !options.batch;
    let mut reader = BufReader::new(stdin.lock());

    run_shell(
        options,
        &mut reader,
        &mut stdout,
        &mut stderr,
        interactive,
        false,
        None,
    )
}

fn run_shell_bytes(
    options: TincOptions,
    input: &[u8],
    interactive: bool,
) -> Result<CliAction, TincError> {
    let mut reader = BufReader::new(input);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    run_shell(
        options,
        &mut reader,
        &mut stdout,
        &mut stderr,
        interactive,
        true,
        None,
    )
}

#[cfg(test)]
fn run_shell_bytes_with_history(
    options: TincOptions,
    input: &[u8],
    interactive: bool,
    history_path: &Path,
) -> Result<CliAction, TincError> {
    let mut reader = BufReader::new(input);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    run_shell(
        options,
        &mut reader,
        &mut stdout,
        &mut stderr,
        interactive,
        true,
        Some(history_path),
    )
}

fn run_shell(
    options: TincOptions,
    reader: &mut impl BufRead,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    interactive: bool,
    capture_output: bool,
    history_path: Option<&Path>,
) -> Result<CliAction, TincError> {
    let mut result = 0u8;
    let mut combined_output = String::new();
    let prompt = shell_prompt(&options);
    let mut line = String::new();
    let mut history = ShellHistory::open(history_path)?;

    loop {
        if interactive {
            stdout
                .write_all(prompt.as_bytes())
                .map_err(|error| io_error(Path::new("stdout"), error))?;
            stdout
                .flush()
                .map_err(|error| io_error(Path::new("stdout"), error))?;
        }

        line.clear();
        let bytes = reader.read_line(&mut line).map_err(|error| TincError::Io {
            path: PathBuf::from("stdin"),
            error: error.to_string(),
        })?;

        if bytes == 0 {
            if interactive {
                stdout
                    .write_all(b"\n")
                    .map_err(|error| io_error(Path::new("stdout"), error))?;
            }
            break;
        }

        match run_shell_line(&options, &line, reader)? {
            ShellLineResult::Continue {
                action,
                history_entry,
            } => {
                match action {
                    CliAction::Exit {
                        code,
                        output: command_output,
                    } => {
                        result |= code;
                        output_shell_text(
                            command_output.as_bytes(),
                            stdout,
                            &mut combined_output,
                            capture_output,
                            "stdout",
                        )?;
                    }
                    CliAction::ExitBytes {
                        code,
                        output: command_output,
                    } => {
                        result |= code;
                        output_shell_text(
                            &command_output,
                            stdout,
                            &mut combined_output,
                            capture_output,
                            "stdout",
                        )?;
                    }
                    CliAction::Command(command) => {
                        result |= 1;
                        let text = format!("command `{}` is not implemented yet\n", command.name);
                        output_shell_text(
                            text.as_bytes(),
                            stderr,
                            &mut combined_output,
                            capture_output,
                            "stderr",
                        )?;
                    }
                }
                history.add(history_entry);
            }
            ShellLineResult::Error {
                error,
                history_entry,
            } => {
                result |= 1;
                let text = match error {
                    TincError::UnknownCommand(command) => {
                        format!("Unknown command `{command}'.\n")
                    }
                    error => format!("{error}\n"),
                };
                output_shell_text(
                    text.as_bytes(),
                    stderr,
                    &mut combined_output,
                    capture_output,
                    "stderr",
                )?;
                history.add(history_entry);
            }
            ShellLineResult::Exit => break,
            ShellLineResult::Skip => {}
        }
    }

    history.save()?;

    Ok(CliAction::Exit {
        code: result,
        output: combined_output,
    })
}

fn output_shell_text(
    bytes: &[u8],
    output: &mut impl Write,
    combined_output: &mut String,
    capture_output: bool,
    stream: &str,
) -> Result<(), TincError> {
    output
        .write_all(bytes)
        .map_err(|error| io_error(Path::new(stream), error))?;

    if capture_output {
        combined_output.push_str(&String::from_utf8_lossy(bytes));
    }

    Ok(())
}

#[derive(Debug)]
enum ShellLineResult {
    Continue {
        action: CliAction,
        history_entry: Option<String>,
    },
    Error {
        error: TincError,
        history_entry: Option<String>,
    },
    Exit,
    Skip,
}

fn run_shell_line(
    options: &TincOptions,
    line: &str,
    reader: &mut impl BufRead,
) -> Result<ShellLineResult, TincError> {
    if line.starts_with('#') {
        return Ok(ShellLineResult::Skip);
    }

    let fields = split_shell_line(line);

    if fields.is_empty() {
        return Ok(ShellLineResult::Skip);
    }

    let name = &fields[0];

    if name.eq_ignore_ascii_case("exit") || name.eq_ignore_ascii_case("quit") {
        return Ok(ShellLineResult::Exit);
    }

    if !is_known_command(name) {
        return Ok(ShellLineResult::Error {
            error: TincError::UnknownCommand(name.to_owned()),
            history_entry: None,
        });
    }

    let history_entry = shell_history_entry(line);
    let command = TincCommand {
        options: options.clone(),
        name: name.clone(),
        arguments: fields[1..].to_vec(),
    };

    let mut command_input = Vec::new();
    if command_reads_stdin(&command) {
        reader
            .read_to_end(&mut command_input)
            .map_err(|error| TincError::Io {
                path: PathBuf::from("stdin"),
                error: error.to_string(),
            })?;
    }

    match run_command_action(command, &command_input) {
        Ok(action) => Ok(ShellLineResult::Continue {
            action,
            history_entry,
        }),
        Err(error) => Ok(ShellLineResult::Error {
            error,
            history_entry,
        }),
    }
}

struct ShellHistory {
    path: Option<PathBuf>,
    entries: Vec<String>,
    dirty: bool,
}

impl ShellHistory {
    fn open(path: Option<&Path>) -> Result<Self, TincError> {
        let Some(path) = path else {
            return Ok(Self {
                path: None,
                entries: Vec::new(),
                dirty: false,
            });
        };

        let entries = match fs::read_to_string(path) {
            Ok(contents) => contents.lines().map(ToOwned::to_owned).collect(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(io_error(path, error)),
        };

        Ok(Self {
            path: Some(path.to_path_buf()),
            entries,
            dirty: false,
        })
    }

    fn add(&mut self, entry: Option<String>) {
        if self.path.is_none() {
            return;
        }
        if let Some(entry) = entry {
            self.entries.push(entry);
            self.dirty = true;
        }
    }

    fn save(&self) -> Result<(), TincError> {
        if !self.dirty {
            return Ok(());
        }
        let Some(path) = &self.path else {
            return Ok(());
        };

        let mut contents = String::new();
        for entry in &self.entries {
            contents.push_str(entry);
            contents.push('\n');
        }
        fs::write(path, contents).map_err(|error| io_error(path, error))
    }
}

fn shell_history_entry(line: &str) -> Option<String> {
    let entry = line.trim_end_matches(['\r', '\n']);
    (!entry.is_empty()).then(|| entry.to_owned())
}

fn split_shell_line(line: &str) -> Vec<String> {
    line.split([' ', '\t', '\n'])
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn shell_prompt(options: &TincOptions) -> String {
    match &options.netname {
        Some(netname) => format!("tinc.{netname}> "),
        None => "tinc> ".to_owned(),
    }
}

fn run_command_action(command: TincCommand, input: &[u8]) -> Result<CliAction, TincError> {
    let text_input = || {
        std::str::from_utf8(input)
            .map_err(|_| TincError::InvalidArguments("input is not valid UTF-8".to_owned()))
    };

    if command.name.eq_ignore_ascii_case("help") {
        Ok(CliAction::Exit {
            code: 0,
            output: usage(&command.options.program_name),
        })
    } else if command.name.eq_ignore_ascii_case("version") {
        Ok(CliAction::Exit {
            code: 0,
            output: version(),
        })
    } else if is_config_command(&command.name) {
        Ok(CliAction::Exit {
            code: 0,
            output: run_config_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("export") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_export_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("export-all") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_export_all_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("import") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_import_command(&command, text_input()?)?,
        })
    } else if command.name.eq_ignore_ascii_case("exchange") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_exchange_command(&command, text_input()?, false)?,
        })
    } else if command.name.eq_ignore_ascii_case("exchange-all") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_exchange_command(&command, text_input()?, true)?,
        })
    } else if command.name.eq_ignore_ascii_case("generate-keys") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_generate_keys_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("generate-rsa-keys") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_generate_rsa_keys_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("generate-ed25519-keys") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_generate_ed25519_keys_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("sign") {
        Ok(CliAction::ExitBytes {
            code: 0,
            output: run_sign_command(&command, input)?,
        })
    } else if command.name.eq_ignore_ascii_case("verify") {
        Ok(CliAction::ExitBytes {
            code: 0,
            output: run_verify_command(&command, input)?,
        })
    } else if command.name.eq_ignore_ascii_case("init") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_init_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("edit") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_edit_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("pid") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_pid_command(&command)?,
        })
    } else if is_dump_command(&command.name) {
        Ok(CliAction::Exit {
            code: 0,
            output: run_dump_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("info") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_info_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("log") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_log_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("pcap") {
        Ok(CliAction::ExitBytes {
            code: 0,
            output: run_pcap_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("top") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_top_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("start") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_start_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("restart") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_restart_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("network") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_network_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("fsck") {
        let (code, output) = run_fsck_command(&command)?;
        Ok(CliAction::Exit { code, output })
    } else if command.name.eq_ignore_ascii_case("invite") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_invite_command(&command)?,
        })
    } else if command.name.eq_ignore_ascii_case("join") {
        Ok(CliAction::Exit {
            code: 0,
            output: run_join_command(&command, text_input()?)?,
        })
    } else if is_simple_control_command(&command.name) {
        Ok(CliAction::Exit {
            code: 0,
            output: run_simple_control_command(&command)?,
        })
    } else {
        Ok(CliAction::Command(command))
    }
}

pub fn parse_args(args: Vec<String>) -> Result<ParsedCommand, TincError> {
    let mut args = args.into_iter();
    let program_name = args.next().unwrap_or_else(|| "tinc".to_owned());
    let mut options = TincOptions::new(program_name.clone());

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--help" => return Ok(ParsedCommand::Help(program_name)),
            "--version" => return Ok(ParsedCommand::Version),
            "-b" | "--batch" => options.batch = true,
            "-c" | "--config" => {
                options.confbase = Some(PathBuf::from(next_arg(&mut args, &argument)?));
                options.confbase_given = true;
            }
            "-n" | "--net" => {
                options.netname = normalize_netname(Some(next_arg(&mut args, &argument)?))?;
            }
            "--pidfile" => options.pidfile = Some(PathBuf::from(next_arg(&mut args, &argument)?)),
            "--force" => options.force = true,
            _ if argument.starts_with("--config=") => {
                options.confbase = Some(PathBuf::from(value_after_equals(&argument)));
                options.confbase_given = true;
            }
            _ if argument.starts_with("--net=") => {
                options.netname = normalize_netname(Some(value_after_equals(&argument)))?;
            }
            _ if argument.starts_with("--pidfile=") => {
                options.pidfile = Some(PathBuf::from(value_after_equals(&argument)));
            }
            _ if argument.starts_with('-') => return Err(TincError::UnknownOption(argument)),
            _ => {
                options.netname = normalize_netname(options.netname)?;
                let name = argument;

                if !is_known_command(&name) {
                    return Err(TincError::UnknownCommand(name));
                }

                return Ok(ParsedCommand::Command(TincCommand {
                    options,
                    name,
                    arguments: args.collect(),
                }));
            }
        }
    }

    if options.netname.is_none() {
        options.netname = normalize_netname(env::var("NETNAME").ok())?;
    }

    Ok(ParsedCommand::Shell(options))
}

pub fn command_requires_stdin(args: Vec<String>) -> bool {
    matches!(
        parse_args(args),
        Ok(ParsedCommand::Command(command)) if command_reads_stdin(&command)
    )
}

fn command_reads_stdin(command: &TincCommand) -> bool {
    matches!(
        command.name.to_ascii_lowercase().as_str(),
        "import" | "exchange" | "exchange-all"
    ) || (command.name.eq_ignore_ascii_case("sign") && command.arguments.is_empty())
        || (command.name.eq_ignore_ascii_case("verify") && command.arguments.len() == 1)
        || (command.name.eq_ignore_ascii_case("join") && command.arguments.is_empty())
}

pub fn resolve_confbase(options: &TincOptions) -> PathBuf {
    if let Some(confbase) = &options.confbase {
        return confbase.clone();
    }

    match &options.netname {
        Some(netname) => Path::new(DEFAULT_CONFDIR).join(netname),
        None => PathBuf::from(DEFAULT_CONFDIR),
    }
}

pub fn visible_commands() -> impl Iterator<Item = &'static str> {
    COMMANDS
        .iter()
        .filter(|command| !command.hidden)
        .map(|command| command.name)
}

fn is_known_command(command: &str) -> bool {
    COMMANDS
        .iter()
        .any(|candidate| candidate.name.eq_ignore_ascii_case(command))
}

fn is_config_command(command: &str) -> bool {
    matches!(
        command.to_ascii_lowercase().as_str(),
        "config" | "get" | "set" | "change" | "replace" | "add" | "del"
    )
}

fn is_dump_command(command: &str) -> bool {
    matches!(command.to_ascii_lowercase().as_str(), "dump" | "list")
}

fn is_simple_control_command(command: &str) -> bool {
    matches!(
        command.to_ascii_lowercase().as_str(),
        "stop" | "reload" | "purge" | "debug" | "retry" | "connect" | "disconnect"
    )
}

fn normalize_netname(netname: Option<String>) -> Result<Option<String>, TincError> {
    let Some(netname) = netname else {
        return Ok(None);
    };

    if netname.is_empty() || netname == "." {
        return Ok(None);
    }

    if netname.starts_with('.') || netname.contains('/') || netname.contains('\\') {
        return Err(TincError::InvalidNetname(netname));
    }

    Ok(Some(netname))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigAction {
    Get,
    Delete,
    Set,
    Add,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfigEdit {
    action: ConfigAction,
    node: Option<String>,
    variable: String,
    value: Option<String>,
}

fn run_config_command(command: &TincCommand) -> Result<String, TincError> {
    let edit = parse_config_edit(&command.name, &command.arguments)?;
    let options = &command.options;
    let confbase = resolve_confbase(options);
    let prepared = prepare_config_edit(edit, &confbase, options.force)?;
    edit_config_file(prepared)
}

fn run_export_command(command: &TincCommand) -> Result<String, TincError> {
    if !command.arguments.is_empty() {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    let name = read_local_name(&confbase)?;
    export_host(&confbase, &name)
}

fn run_export_all_command(command: &TincCommand) -> Result<String, TincError> {
    if !command.arguments.is_empty() {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    let hosts_dir = confbase.join("hosts");
    let mut names = Vec::new();

    for entry in fs::read_dir(&hosts_dir).map_err(|error| io_error(&hosts_dir, error))? {
        let entry = entry.map_err(|error| io_error(&hosts_dir, error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };

        if check_id(name) {
            names.push(name.to_owned());
        }
    }

    names.sort();

    let mut output = String::new();

    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            output
                .push_str("\n#---------------------------------------------------------------#\n");
        }

        output.push_str(&export_host(&confbase, name)?);
    }

    Ok(output)
}

fn run_network_command(command: &TincCommand) -> Result<String, TincError> {
    if command.arguments.len() > 1 {
        return Err(TincError::TooManyArguments);
    }

    if let Some(name) = command.arguments.first() {
        if name != "." && !check_netname(name, false) {
            return Err(TincError::InvalidNetname(name.clone()));
        }

        if name != "." && !check_netname(name, true) {
            return Ok("Warning: unsafe character in netname!\n".to_owned());
        }

        return Ok(String::new());
    }

    let confdir = network_listing_directory(&command.options);
    let mut networks = Vec::new();

    for entry in fs::read_dir(&confdir).map_err(|error| io_error(&confdir, error))? {
        let entry = entry.map_err(|error| io_error(&confdir, error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };

        if name.starts_with('.') {
            continue;
        }

        if name == "tinc.conf" {
            networks.push(".".to_owned());
            continue;
        }

        if confdir.join(name).join("tinc.conf").is_file() {
            networks.push(name.to_owned());
        }
    }

    networks.sort();

    let mut output = String::new();

    for network in networks {
        output.push_str(&network);
        output.push('\n');
    }

    Ok(output)
}

fn network_listing_directory(options: &TincOptions) -> PathBuf {
    if options.confbase_given {
        resolve_confbase(options)
    } else {
        PathBuf::from(DEFAULT_CONFDIR)
    }
}

fn run_fsck_command(command: &TincCommand) -> Result<(u8, String), TincError> {
    if !command.arguments.is_empty() {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    let mut output = String::new();
    let mut success = true;
    let tinc_conf = confbase.join("tinc.conf");

    if !tinc_conf.exists() {
        output.push_str(&format!(
            "ERROR: cannot read {}: No such file or directory\n",
            tinc_conf.display()
        ));
        output.push_str("No tinc configuration found. Create a new one with:\n\n");
        output.push_str(&format!("{} init\n", command.options.program_name));
        output.push_str("ERROR: tinc cannot run without a valid Name.\n");
        return Ok((1, output));
    }

    let server_entries = match read_fsck_config_file(&tinc_conf) {
        Ok(entries) => entries,
        Err(error) => {
            output.push_str(&format!(
                "ERROR: cannot read {}: {error}\n",
                tinc_conf.display()
            ));
            output.push_str("ERROR: tinc cannot run without a valid Name.\n");
            return Ok((1, output));
        }
    };

    let Some(name) = fsck_lookup_value(&server_entries, "Name").filter(|name| check_id(name))
    else {
        output.push_str("ERROR: tinc cannot run without a valid Name.\n");
        return Ok((1, output));
    };

    let host_path = confbase.join("hosts").join(name);
    let host_entries = match read_fsck_config_file(&host_path) {
        Ok(entries) => entries,
        Err(error) => {
            output.push_str(&format!("WARNING: cannot read {}\n", host_path.display()));
            output.push_str(&format!("ERROR: {error}\n"));
            Vec::new()
        }
    };

    if !check_fsck_keypair(
        &confbase,
        &host_path,
        &server_entries,
        &host_entries,
        command.options.force,
        &mut output,
    )? {
        success = false;
    }

    check_fsck_scripts(&confbase, command.options.force, &mut output)?;
    check_fsck_config_variables(&confbase, &server_entries, &host_entries, &mut output)?;

    Ok((u8::from(!success), output))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FsckConfigEntry {
    variable: String,
    value: String,
    path: PathBuf,
    line: usize,
    missing_value: bool,
}

fn read_fsck_config_file(path: &Path) -> Result<Vec<FsckConfigEntry>, io::Error> {
    let contents = fs::read_to_string(path)?;
    Ok(parse_fsck_config_file(path, &contents))
}

fn parse_fsck_config_file(path: &Path, contents: &str) -> Vec<FsckConfigEntry> {
    let mut entries = Vec::new();
    let mut in_pem = false;

    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim_start_matches(['\t', ' ']);

        if trimmed.starts_with("-----BEGIN") {
            in_pem = true;
            continue;
        }

        if trimmed.starts_with("-----END") {
            in_pem = false;
            continue;
        }

        if in_pem || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (variable, value) = parse_config_file_line(line);

        if variable.is_empty() {
            continue;
        }

        entries.push(FsckConfigEntry {
            variable: variable.to_owned(),
            value: value.to_owned(),
            path: path.to_path_buf(),
            line: index + 1,
            missing_value: value.is_empty(),
        });
    }

    entries
}

fn fsck_lookup_value<'a>(entries: &'a [FsckConfigEntry], variable: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|entry| entry.variable.eq_ignore_ascii_case(variable) && !entry.value.is_empty())
        .map(|entry| entry.value.as_str())
}

fn check_fsck_keypair(
    confbase: &Path,
    host_path: &Path,
    server_entries: &[FsckConfigEntry],
    host_entries: &[FsckConfigEntry],
    force: bool,
    output: &mut String,
) -> Result<bool, TincError> {
    let ed25519_private = read_fsck_ed25519_private_key(confbase, server_entries);
    if let Some((private_path, _)) = &ed25519_private {
        check_private_file_permissions(private_path, force, output)?;
    }

    let rsa_private = read_fsck_rsa_private_key(confbase, server_entries);
    if let Some((private_path, _)) = &rsa_private {
        check_private_file_permissions(private_path, force, output)?;
    }

    if ed25519_private.is_none() && rsa_private.is_none() {
        output.push_str("ERROR: Neither RSA or Ed25519 private key found.\n\n");
        output.push_str("You can generate new keys with:\n\n");
        output.push_str("tinc generate-keys\n");
        return Ok(false);
    }

    let mut success = true;

    if !check_fsck_rsa_public_key(
        confbase,
        host_path,
        server_entries,
        host_entries,
        rsa_private.as_ref().map(|(_, key)| key),
        force,
        output,
    )? {
        success = false;
    }

    if !check_fsck_ed25519_public_key(
        confbase,
        host_path,
        server_entries,
        host_entries,
        ed25519_private.as_ref().map(|(_, key)| key),
        force,
        output,
    )? {
        success = false;
    }

    Ok(success)
}

fn read_fsck_ed25519_private_key(
    confbase: &Path,
    server_entries: &[FsckConfigEntry],
) -> Option<(PathBuf, TincEd25519PrivateKey)> {
    let private_path = fsck_lookup_value(server_entries, "Ed25519PrivateKeyFile")
        .map(PathBuf::from)
        .unwrap_or_else(|| confbase.join("ed25519_key.priv"));
    let private = fs::read_to_string(&private_path)
        .ok()
        .and_then(|contents| TincEd25519PrivateKey::from_pem(&contents).ok())?;

    Some((private_path, private))
}

fn read_fsck_rsa_private_key(
    confbase: &Path,
    server_entries: &[FsckConfigEntry],
) -> Option<(PathBuf, RsaPrivateKey)> {
    let private_path = fsck_lookup_value(server_entries, "PrivateKeyFile")
        .map(PathBuf::from)
        .unwrap_or_else(|| confbase.join("rsa_key.priv"));
    let private = fs::read_to_string(&private_path)
        .ok()
        .and_then(|contents| RsaPrivateKey::from_pkcs1_pem(&contents).ok())?;

    Some((private_path, private))
}

fn check_fsck_rsa_public_key(
    confbase: &Path,
    host_path: &Path,
    server_entries: &[FsckConfigEntry],
    host_entries: &[FsckConfigEntry],
    private: Option<&RsaPrivateKey>,
    force: bool,
    output: &mut String,
) -> Result<bool, TincError> {
    let public = read_fsck_rsa_public_key(confbase, server_entries, host_entries);

    match (private, public) {
        (Some(private), Some(public)) if public == RsaPublicKey::from(private) => Ok(true),
        (Some(private), Some(_)) => {
            output.push_str("ERROR: public and private RSA keys do not match.\n");
            maybe_fix_rsa_public_key(host_path, private, force, output)
        }
        (Some(private), None) => {
            output.push_str("WARNING: No (usable) public RSA key found.\n");
            maybe_fix_rsa_public_key(host_path, private, force, output)
        }
        (None, Some(_)) => {
            output.push_str("WARNING: A public RSA key was found but no private key is known.\n");
            Ok(true)
        }
        (None, None) => {
            output.push_str("WARNING: No (usable) public RSA key found.\n");
            Ok(true)
        }
    }
}

fn check_fsck_ed25519_public_key(
    confbase: &Path,
    host_path: &Path,
    server_entries: &[FsckConfigEntry],
    host_entries: &[FsckConfigEntry],
    private: Option<&TincEd25519PrivateKey>,
    force: bool,
    output: &mut String,
) -> Result<bool, TincError> {
    let public = read_fsck_ed25519_public_key(confbase, server_entries, host_entries);

    match (private, public) {
        (Some(private), Some(public)) if public == private.public_key() => Ok(true),
        (Some(private), Some(_)) => {
            output.push_str("ERROR: public and private Ed25519 keys do not match.\n");
            maybe_fix_ed25519_public_key(host_path, private, force, output)
        }
        (Some(private), None) => {
            output.push_str("WARNING: No (usable) public Ed25519 key found.\n");
            maybe_fix_ed25519_public_key(host_path, private, force, output)
        }
        (None, Some(_)) => {
            output
                .push_str("WARNING: A public Ed25519 key was found but no private key is known.\n");
            Ok(true)
        }
        (None, None) => Ok(true),
    }
}

fn read_fsck_ed25519_public_key(
    confbase: &Path,
    server_entries: &[FsckConfigEntry],
    host_entries: &[FsckConfigEntry],
) -> Option<TincEd25519PublicKey> {
    for entries in [host_entries, server_entries] {
        for entry in entries.iter() {
            if entry.variable.eq_ignore_ascii_case("Ed25519PublicKey") && !entry.value.is_empty() {
                if let Ok(key) = TincEd25519PublicKey::from_base64(&entry.value) {
                    return Some(key);
                }
            }

            if entry.variable.eq_ignore_ascii_case("Ed25519PublicKeyFile")
                && !entry.value.is_empty()
            {
                let path = PathBuf::from(&entry.value);
                let path = if path.is_absolute() {
                    path
                } else {
                    confbase.join(path)
                };

                if let Ok(contents) = fs::read_to_string(&path) {
                    if let Ok(key) = TincEd25519PublicKey::from_pem(&contents) {
                        return Some(key);
                    }
                }
            }
        }
    }

    read_inline_ed25519_public_pem(host_entries)
}

fn read_fsck_rsa_public_key(
    confbase: &Path,
    server_entries: &[FsckConfigEntry],
    host_entries: &[FsckConfigEntry],
) -> Option<RsaPublicKey> {
    for entries in [host_entries, server_entries] {
        for entry in entries.iter() {
            if entry.variable.eq_ignore_ascii_case("PublicKey") && !entry.value.is_empty() {
                if let Some(key) = rsa_public_key_from_legacy_hex(&entry.value) {
                    return Some(key);
                }
            }

            if entry.variable.eq_ignore_ascii_case("PublicKeyFile") && !entry.value.is_empty() {
                let path = resolve_fsck_config_path(confbase, &entry.value);

                if let Ok(contents) = fs::read_to_string(&path) {
                    if let Some(key) = read_rsa_public_from_text(&contents) {
                        return Some(key);
                    }
                }
            }
        }
    }

    let contents = fs::read_to_string(host_entries.first()?.path.as_path()).ok()?;
    read_rsa_public_from_text(&contents)
}

fn resolve_fsck_config_path(confbase: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        confbase.join(path)
    }
}

fn rsa_public_key_from_legacy_hex(value: &str) -> Option<RsaPublicKey> {
    let modulus = BigUint::parse_bytes(value.as_bytes(), 16)?;
    RsaPublicKey::new(modulus, BigUint::from(0xffffu32)).ok()
}

fn read_rsa_public_from_text(contents: &str) -> Option<RsaPublicKey> {
    let pem = extract_pem_block(contents, "RSA PUBLIC KEY")?;
    RsaPublicKey::from_pkcs1_pem(&pem).ok()
}

fn read_inline_ed25519_public_pem(entries: &[FsckConfigEntry]) -> Option<TincEd25519PublicKey> {
    let contents = fs::read_to_string(entries.first()?.path.as_path()).ok()?;
    let pem =
        extract_pem_block(&contents, "ED25519 PUBLIC KEY").unwrap_or_else(|| contents.clone());
    TincEd25519PublicKey::from_pem(&pem).ok()
}

fn extract_pem_block(contents: &str, label: &str) -> Option<String> {
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

fn maybe_fix_rsa_public_key(
    host_path: &Path,
    private: &RsaPrivateKey,
    force: bool,
    output: &mut String,
) -> Result<bool, TincError> {
    if !force {
        return Ok(true);
    }

    let public_pem = RsaPublicKey::from(private)
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|error| {
            TincError::InvalidArguments(format!("could not encode RSA public key: {error}"))
        })?;
    append_config_text(host_path, &public_pem, FilePrivacy::Public)?;
    output.push_str(&format!(
        "Wrote RSA public key to {}.\n",
        host_path.display()
    ));
    Ok(true)
}

fn maybe_fix_ed25519_public_key(
    host_path: &Path,
    private: &TincEd25519PrivateKey,
    force: bool,
    output: &mut String,
) -> Result<bool, TincError> {
    if !force {
        return Ok(true);
    }

    append_config_text(
        host_path,
        &private.public_key().to_pem(),
        FilePrivacy::Public,
    )?;
    output.push_str(&format!(
        "Wrote Ed25519 public key to {}.\n",
        host_path.display()
    ));
    Ok(true)
}

fn check_private_file_permissions(
    path: &Path,
    force: bool,
    output: &mut String,
) -> Result<(), TincError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::metadata(path).map_err(|error| io_error(path, error))?;
        let mode = metadata.permissions().mode();

        if mode & 0o077 != 0 {
            output.push_str(&format!(
                "WARNING: unsafe file permissions on {}.\n",
                path.display()
            ));

            if force {
                fs::set_permissions(path, fs::Permissions::from_mode(mode & !0o077))
                    .map_err(|error| io_error(path, error))?;
                output.push_str(&format!("Fixed permissions of {}.\n", path.display()));
            }
        }
    }

    #[cfg(not(unix))]
    let _ = (path, force, output);

    Ok(())
}

fn check_fsck_scripts(confbase: &Path, force: bool, output: &mut String) -> Result<(), TincError> {
    check_fsck_script_dir(confbase, &["tinc", "host", "subnet"], force, output)?;
    check_fsck_script_dir(&confbase.join("hosts"), &[], force, output)?;
    Ok(())
}

fn check_fsck_script_dir(
    dir: &Path,
    known_bases: &[&str],
    force: bool,
    output: &mut String,
) -> Result<(), TincError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(dir, error)),
    };

    for entry in entries {
        let entry = entry.map_err(|error| io_error(dir, error))?;
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Some(base) = name
            .strip_suffix("-up")
            .or_else(|| name.strip_suffix("-down"))
        else {
            continue;
        };

        if !known_bases.is_empty() && !known_bases.iter().any(|known| *known == base) {
            output.push_str(&format!(
                "WARNING: Unknown script {}/{} found.\n",
                dir.display(),
                name
            ));
            output.push_str(&format!(
                "The only scripts in {} executed by tinc are:\n",
                dir.display()
            ));
            output.push_str("tinc-up, tinc-down, host-up, host-down, subnet-up and subnet-down.\n");
            continue;
        }

        check_script_executable(&path, force, output)?;
    }

    Ok(())
}

fn check_script_executable(path: &Path, force: bool, output: &mut String) -> Result<(), TincError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::metadata(path).map_err(|error| io_error(path, error))?;

        if metadata.permissions().mode() & 0o500 != 0o500 {
            output.push_str(&format!(
                "WARNING: cannot read and execute {}: Permission denied\n",
                path.display()
            ));

            if force {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                    .map_err(|error| io_error(path, error))?;
            }
        }
    }

    #[cfg(not(unix))]
    let _ = (path, force, output);

    Ok(())
}

fn check_fsck_config_variables(
    confbase: &Path,
    server_entries: &[FsckConfigEntry],
    local_host_entries: &[FsckConfigEntry],
    output: &mut String,
) -> Result<(), TincError> {
    check_fsck_config_file_variables(None, true, server_entries, output);
    check_fsck_config_file_variables(None, false, local_host_entries, output);

    let hosts_dir = confbase.join("hosts");
    let entries = match fs::read_dir(&hosts_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(&hosts_dir, error)),
    };

    for entry in entries {
        let entry = entry.map_err(|error| io_error(&hosts_dir, error))?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };

        if !check_id(&name) {
            continue;
        }

        let path = entry.path();

        if path
            == local_host_entries
                .first()
                .map(|entry| entry.path.clone())
                .unwrap_or_default()
        {
            continue;
        }

        if let Ok(entries) = read_fsck_config_file(&path) {
            check_fsck_config_file_variables(Some(&name), false, &entries, output);
        }
    }

    Ok(())
}

fn check_fsck_config_file_variables(
    nodename: Option<&str>,
    server: bool,
    entries: &[FsckConfigEntry],
    output: &mut String,
) {
    let mut counts = vec![0usize; VARIABLES.len()];

    for entry in entries {
        if entry.missing_value {
            output.push_str(&format!(
                "WARNING: No value for variable `{}` in {} line {}\n",
                entry.variable,
                entry.path.display(),
                entry.line
            ));
        }

        let Some((index, spec)) = VARIABLES
            .iter()
            .copied()
            .enumerate()
            .find(|(_, candidate)| candidate.name.eq_ignore_ascii_case(&entry.variable))
        else {
            continue;
        };

        counts[index] += 1;

        if spec.is_obsolete() {
            output.push_str(&format!(
                "WARNING: obsolete variable {} in {} line {}\n",
                entry.variable,
                entry.path.display(),
                entry.line
            ));
        }

        if server && !spec.is_server() {
            output.push_str(&format!(
                "WARNING: host variable {} found in server config {} line {} \n",
                entry.variable,
                entry.path.display(),
                entry.line
            ));
        }

        if !server && !spec.is_host() {
            output.push_str(&format!(
                "WARNING: server variable {} found in host config {} line {} \n",
                entry.variable,
                entry.path.display(),
                entry.line
            ));
        }
    }

    for (index, count) in counts.into_iter().enumerate() {
        let spec = VARIABLES[index];

        if count > 1 && !spec.is_multiple() {
            output.push_str(&format!(
                "WARNING: multiple instances of variable {} in {}\n",
                spec.name,
                nodename.unwrap_or("tinc.conf")
            ));
        }
    }
}

fn run_import_command(command: &TincCommand, input: &str) -> Result<String, TincError> {
    if !command.arguments.is_empty() {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    import_hosts(&confbase, input, command.options.force)?;
    Ok(String::new())
}

fn run_exchange_command(
    command: &TincCommand,
    input: &str,
    all: bool,
) -> Result<String, TincError> {
    if !command.arguments.is_empty() {
        return Err(TincError::TooManyArguments);
    }

    let exported = if all {
        run_export_all_command(command)?
    } else {
        run_export_command(command)?
    };
    run_import_command(command, input)?;
    Ok(exported)
}

fn run_invite_command(command: &TincCommand) -> Result<String, TincError> {
    if command.arguments.len() != 1 {
        return Err(TincError::InvalidArguments(
            "invalid number of arguments".to_owned(),
        ));
    }

    let invitee = &command.arguments[0];

    if !check_id(invitee) {
        return Err(TincError::InvalidNodeName(invitee.clone()));
    }

    let confbase = resolve_confbase(&command.options);
    let local_name = read_local_name(&confbase)?;
    let invitee_host_path = confbase.join("hosts").join(invitee);

    if invitee_host_path.exists() {
        return Err(TincError::ConfigurationExists(invitee_host_path));
    }

    let invitations_dir = confbase.join("invitations");
    fs::create_dir_all(&invitations_dir).map_err(|error| io_error(&invitations_dir, error))?;
    let active_invitations = cleanup_expired_invitations(&invitations_dir)?;
    let invitation_key_path = invitations_dir.join("ed25519_key.priv");

    if active_invitations == 0 {
        match fs::remove_file(&invitation_key_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(&invitation_key_path, error)),
        }
    }

    let invitation_key = read_or_create_invitation_key(&invitation_key_path)?;
    let inviter_public = invitation_key.public_key().to_base64();
    let key_hash = hash18_tinc_urlsafe(inviter_public.as_bytes());
    let (authority, port) = invitation_authority_and_port(&confbase, &local_name)?;
    let body = build_invitation_body(
        &confbase,
        &local_name,
        invitee,
        command.options.netname.as_deref(),
        &port,
    )?;

    for _ in 0..16 {
        let cookie_bytes = random_bytes_18()?;
        let cookie = b64encode_tinc_urlsafe(&cookie_bytes);
        let mut cookie_hash_input = Vec::with_capacity(cookie_bytes.len() + inviter_public.len());
        cookie_hash_input.extend_from_slice(&cookie_bytes);
        cookie_hash_input.extend_from_slice(inviter_public.as_bytes());
        let cookie_hash = hash18_tinc_urlsafe(&cookie_hash_input);
        let invitation_path = invitations_dir.join(&cookie_hash);

        match write_private_text_create_new(&invitation_path, &body) {
            Ok(()) => {
                let url = format!("{authority}/{key_hash}{cookie}");
                run_invitation_created_script(
                    &confbase,
                    &command.options,
                    &local_name,
                    invitee,
                    &invitation_path,
                    &url,
                );
                return Ok(format!("{url}\n"));
            }
            Err(TincError::Io { path: _, error })
                if error.contains("File exists") || error.contains("already exists") =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    Err(TincError::Random(
        "could not allocate a unique invitation cookie".to_owned(),
    ))
}

fn run_invitation_created_script(
    confbase: &Path,
    options: &TincOptions,
    local_name: &str,
    invitee: &str,
    invitation_path: &Path,
    url: &str,
) -> bool {
    let path = confbase.join("invitation-created");
    if !path.exists() {
        return false;
    }

    let mut command = Command::new(&path);
    if let Some(netname) = &options.netname {
        command.env("NETNAME", netname);
    }
    command.env("NAME", local_name);
    command.env("NODE", invitee);
    command.env("INVITATION_FILE", invitation_path);
    command.env("INVITATION_URL", url);

    command.status().is_ok()
}

fn run_join_command(command: &TincCommand, input: &str) -> Result<String, TincError> {
    if command.arguments.len() > 1 {
        return Err(TincError::TooManyArguments);
    }

    let invitation = command
        .arguments
        .first()
        .map(String::as_str)
        .unwrap_or(input)
        .trim();
    let parsed = parse_invitation_url(invitation)?;
    let confbase = resolve_confbase(&command.options);

    fs::create_dir_all(&confbase).map_err(|error| io_error(&confbase, error))?;

    if (command.options.netname.is_some() || command.options.confbase_given)
        && confbase.join("tinc.conf").exists()
    {
        return Err(TincError::ConfigurationExists(confbase.join("tinc.conf")));
    }

    accept_invitation(&confbase, &parsed, command.options.force)?;
    Ok(String::new())
}

fn accept_invitation(
    confbase: &Path,
    invitation: &ParsedInvitationUrl,
    force: bool,
) -> Result<String, TincError> {
    let address = invitation_socket_address(&invitation.address, &invitation.port)?;
    let stream = TcpStream::connect(&address).map_err(|error| {
        TincError::InvitationFailed(format!("could not connect to inviter {address}: {error}"))
    })?;
    stream
        .set_read_timeout(Some(INVITATION_TIMEOUT))
        .map_err(|error| invitation_io_error(&address, error))?;
    stream
        .set_write_timeout(Some(INVITATION_TIMEOUT))
        .map_err(|error| invitation_io_error(&address, error))?;

    let mut connection = InvitationConnection::new(stream);
    let throwaway_key = generate_ed25519_keypair()?;
    let throwaway_public = throwaway_key.public_key().to_base64();
    connection.write_all(
        format!(
            "{} ?{} {}.1\n",
            Request::Id.number(),
            throwaway_public,
            PROT_MAJOR
        )
        .as_bytes(),
    )?;

    let peer_id = read_invitation_peer_id(&mut connection)?;
    let peer_public = read_invitation_peer_key(&mut connection, &invitation.key_hash)?;
    let mut session =
        SptpsHandshakeSession::start_tcp(true, throwaway_key, peer_public, INVITATION_LABEL)
            .map_err(invitation_sptps_error)?;
    let mut decoder = MetaStreamDecoder::new();
    let mut invitation_data = Vec::new();

    for record in session.drain_outbound() {
        connection.write_all(&record)?;
    }

    let trailing = connection.take_buffer();

    if !trailing.is_empty() {
        decoder.push(&trailing);
    }

    loop {
        while let Some(frame) = decoder
            .next_sptps_frame(session.is_established())
            .map_err(|error| TincError::InvitationFailed(error.to_string()))?
        {
            let MetaStreamFrame::SptpsRecord(record) = frame else {
                return Err(TincError::InvitationFailed(
                    "unexpected invitation stream frame".to_owned(),
                ));
            };
            let events = session
                .receive_datagram(&record)
                .map_err(invitation_sptps_error)?;

            for record in session.drain_outbound() {
                connection.write_all(&record)?;
            }

            for event in events {
                match event {
                    SptpsHandshakeEvent::HandshakeComplete => {
                        let cookie = session
                            .send_record(0, &invitation.cookie)
                            .map_err(invitation_sptps_error)?;
                        connection.write_all(&cookie)?;
                    }
                    SptpsHandshakeEvent::ApplicationRecord {
                        record_type: 0,
                        payload,
                    } => invitation_data.extend_from_slice(&payload),
                    SptpsHandshakeEvent::ApplicationRecord {
                        record_type: 1,
                        payload: _,
                    } => {
                        let invitation_text =
                            String::from_utf8(invitation_data.clone()).map_err(|_| {
                                TincError::InvalidArguments(
                                    "invitation data is not valid UTF-8".to_owned(),
                                )
                            })?;
                        let finalized =
                            finalize_join_data_inner(confbase, &invitation_text, force)?;
                        let response = session
                            .send_record(1, finalized.public_key.as_bytes())
                            .map_err(invitation_sptps_error)?;
                        connection.write_all(&response)?;
                        write_join_legacy_rsa_keys(confbase, &finalized.name)?;
                    }
                    SptpsHandshakeEvent::ApplicationRecord {
                        record_type: 2,
                        payload: _,
                    } => return Ok(peer_id.name),
                    SptpsHandshakeEvent::ApplicationRecord {
                        record_type,
                        payload: _,
                    } => {
                        return Err(TincError::InvitationFailed(format!(
                            "unexpected invitation record type {record_type}"
                        )));
                    }
                }
            }
        }

        let read = connection.read_more()?;

        if read == 0 {
            return Err(TincError::InvitationFailed(
                "invitation cancelled before completion".to_owned(),
            ));
        }

        let chunk = connection.take_buffer();
        decoder.push(&chunk);
    }
}

fn read_invitation_peer_id(connection: &mut InvitationConnection) -> Result<IdMessage, TincError> {
    let line = connection.read_line()?;
    let message = parse_meta_message(&line)
        .map_err(|error| TincError::InvitationFailed(format!("invalid invitation ID: {error}")))?;
    let MetaMessage::Id(id) = message else {
        return Err(TincError::InvitationFailed(
            "inviter did not send an ID message".to_owned(),
        ));
    };

    if id.protocol_major != PROT_MAJOR as i32 || !check_id(&id.name) {
        return Err(TincError::InvitationFailed(
            "inviter sent an invalid ID message".to_owned(),
        ));
    }

    Ok(id)
}

fn read_invitation_peer_key(
    connection: &mut InvitationConnection,
    expected_hash: &[u8; 18],
) -> Result<TincEd25519PublicKey, TincError> {
    let line = connection.read_line()?;
    let message = parse_meta_message(&line)
        .map_err(|error| TincError::InvitationFailed(format!("invalid invitation ACK: {error}")))?;
    let MetaMessage::Ack(AckMessage::Payload(public_key)) = message else {
        return Err(TincError::InvitationFailed(
            "inviter did not send an invitation public key".to_owned(),
        ));
    };

    if &hash18_bytes(public_key.as_bytes()) != expected_hash {
        return Err(TincError::InvitationFailed(
            "peer has an invalid invitation key".to_owned(),
        ));
    }

    TincEd25519PublicKey::from_base64(&public_key)
        .map_err(|error| TincError::InvitationFailed(format!("invalid invitation key: {error}")))
}

fn invitation_socket_address(address: &str, port: &str) -> Result<String, TincError> {
    let port = port
        .parse::<u16>()
        .map_err(|_| TincError::InvalidArguments("invalid invitation URL".to_owned()))?;

    if address.contains(':') {
        Ok(format!("[{address}]:{port}"))
    } else {
        Ok(format!("{address}:{port}"))
    }
}

fn invitation_io_error(address: &str, error: io::Error) -> TincError {
    TincError::InvitationFailed(format!(
        "invitation connection to {address} failed: {error}"
    ))
}

fn invitation_sptps_error(error: impl fmt::Display) -> TincError {
    TincError::InvitationFailed(format!("invitation SPTPS failed: {error}"))
}

struct InvitationConnection {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl InvitationConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    fn write_all(&mut self, data: &[u8]) -> Result<(), TincError> {
        self.stream.write_all(data).map_err(|error| {
            TincError::InvitationFailed(format!("invitation send failed: {error}"))
        })
    }

    fn read_line(&mut self) -> Result<String, TincError> {
        loop {
            if let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line = self.buffer.drain(..=newline).collect::<Vec<_>>();
                let line = trim_meta_line(&line);
                return String::from_utf8(line.to_vec()).map_err(|_| {
                    TincError::InvitationFailed("invitation line is not valid UTF-8".to_owned())
                });
            }

            if self.read_more()? == 0 {
                return Err(TincError::InvitationFailed(
                    "inviter closed the connection".to_owned(),
                ));
            }
        }
    }

    fn read_more(&mut self) -> Result<usize, TincError> {
        let mut chunk = [0u8; 4096];
        let len = self.stream.read(&mut chunk).map_err(|error| {
            TincError::InvitationFailed(format!("invitation read failed: {error}"))
        })?;
        self.buffer.extend_from_slice(&chunk[..len]);
        Ok(len)
    }

    fn take_buffer(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
    }
}

fn cleanup_expired_invitations(invitations_dir: &Path) -> Result<usize, TincError> {
    let now = SystemTime::now();
    let mut active = 0usize;

    for entry in fs::read_dir(invitations_dir).map_err(|error| io_error(invitations_dir, error))? {
        let entry = entry.map_err(|error| io_error(invitations_dir, error))?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };

        if filename.len() != 24 {
            continue;
        }

        let path = entry.path();
        let metadata = entry.metadata().map_err(|error| io_error(&path, error))?;
        let expired = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age.as_secs() >= 604_800);

        if expired {
            fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
        } else {
            active += 1;
        }
    }

    Ok(active)
}

fn read_or_create_invitation_key(path: &Path) -> Result<TincEd25519PrivateKey, TincError> {
    match fs::read_to_string(path) {
        Ok(contents) => TincEd25519PrivateKey::from_pem(&contents).map_err(|error| {
            TincError::InvalidArguments(format!(
                "could not read private key from {}: {error}",
                path.display()
            ))
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = generate_ed25519_keypair()?;
            write_private_text(path, &key.to_pem())?;
            Ok(key)
        }
        Err(error) => Err(io_error(path, error)),
    }
}

fn invitation_authority_and_port(
    confbase: &Path,
    local_name: &str,
) -> Result<(String, String), TincError> {
    let mut host = None;
    let mut port = None;

    scan_invitation_hostname(
        &confbase.join("hosts").join(local_name),
        &mut host,
        &mut port,
    )?;
    scan_invitation_hostname(&confbase.join("tinc.conf"), &mut host, &mut port)?;

    let Some(host) = host else {
        return Err(TincError::InvalidArguments(
            "could not determine external address; please set Address manually".to_owned(),
        ));
    };

    let port = match port {
        Some(port) if port.parse::<u64>().ok() != Some(0) => port,
        _ => {
            let pidfile = read_pidfile(&resolve_confbase_pidfile(confbase))?;
            pidfile.port
        }
    };
    let authority_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host
    };

    Ok((format!("{authority_host}:{port}"), port))
}

fn resolve_confbase_pidfile(confbase: &Path) -> PathBuf {
    confbase.join("pid")
}

fn scan_invitation_hostname(
    path: &Path,
    host: &mut Option<String>,
    port: &mut Option<String>,
) -> Result<(), TincError> {
    if host.is_some() && port.is_some() {
        return Ok(());
    }

    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(path, error)),
    };

    for line in contents.lines() {
        let (variable, value) = parse_config_file_line(line);

        if variable.eq_ignore_ascii_case("Port") && port.is_none() && !value.is_empty() {
            if let Some(first) = value.split_whitespace().next() {
                *port = Some(first.to_owned());
            }
        } else if variable.eq_ignore_ascii_case("Address") && host.is_none() && !value.is_empty() {
            let mut fields = value.split_whitespace();

            if let Some(first) = fields.next() {
                *host = Some(first.to_owned());
            }

            if let Some(second) = fields.next() {
                *port = Some(second.to_owned());
            }
        }

        if host.is_some() && port.is_some() {
            break;
        }
    }

    Ok(())
}

fn build_invitation_body(
    confbase: &Path,
    local_name: &str,
    invitee: &str,
    netname: Option<&str>,
    port: &str,
) -> Result<String, TincError> {
    let mut body = format!("Name = {invitee}\n");

    if let Some(netname) = netname.filter(|netname| check_netname(netname, true)) {
        body.push_str(&format!("NetName = {netname}\n"));
    }

    body.push_str(&format!("ConnectTo = {local_name}\n"));
    append_invitation_mode_lines(confbase, &mut body)?;
    body.push_str("#---------------------------------------------------------------#\n");
    body.push_str(&format!("Name = {local_name}\n"));
    body.push_str(&host_config_replacing_port(
        &confbase.join("hosts").join(local_name),
        port,
    )?);

    Ok(body)
}

fn append_invitation_mode_lines(confbase: &Path, body: &mut String) -> Result<(), TincError> {
    let path = confbase.join("tinc.conf");
    let contents = read_config_text(&path)?;

    for line in contents.lines() {
        let (variable, _) = parse_config_file_line(line);

        if variable.eq_ignore_ascii_case("Mode") || variable.eq_ignore_ascii_case("Broadcast") {
            body.push_str(line.trim_end_matches('\r'));
            body.push('\n');
        }
    }

    Ok(())
}

fn host_config_replacing_port(path: &Path, port: &str) -> Result<String, TincError> {
    let contents = read_config_text(path)?;
    let mut output = String::new();

    for line in contents.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let raw = line.strip_suffix('\n').unwrap_or(line);
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let (variable, _) = parse_config_file_line(raw);

        if variable.eq_ignore_ascii_case("Port") {
            output.push_str(&format!("Port = {port}\n"));
        } else {
            output.push_str(raw);

            if has_newline {
                output.push('\n');
            } else if !raw.is_empty() {
                output.push('\n');
            }
        }
    }

    Ok(output)
}

fn hash18_tinc_urlsafe(input: &[u8]) -> String {
    b64encode_tinc_urlsafe(&hash18_bytes(input))
}

fn hash18_bytes(input: &[u8]) -> [u8; 18] {
    let digest = Sha512::digest(input);
    digest[..18]
        .try_into()
        .expect("SHA-512 digest has at least 18 bytes")
}

fn random_bytes_18() -> Result<[u8; 18], TincError> {
    let mut bytes = [0u8; 18];
    getrandom::getrandom(&mut bytes).map_err(|error| TincError::Random(error.to_string()))?;
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedInvitationUrl {
    pub address: String,
    pub port: String,
    pub key_hash: [u8; 18],
    pub cookie: [u8; 18],
}

pub fn parse_invitation_url(invitation: &str) -> Result<ParsedInvitationUrl, TincError> {
    let invitation = invitation.trim();
    let Some((authority, token)) = invitation.split_once('/') else {
        return Err(invalid_invitation_url());
    };

    if token.len() != 48 {
        return Err(invalid_invitation_url());
    }

    let (address, port) = parse_invitation_authority(authority)?;
    let key_hash = decode_invitation_token_half(&token[..24])?;
    let cookie = decode_invitation_token_half(&token[24..])?;

    Ok(ParsedInvitationUrl {
        address,
        port,
        key_hash,
        cookie,
    })
}

pub fn finalize_join_data(
    confbase: &Path,
    invitation_data: &str,
    force: bool,
) -> Result<String, TincError> {
    let finalized = finalize_join_data_inner(confbase, invitation_data, force)?;
    write_join_legacy_rsa_keys(confbase, &finalized.name)?;
    Ok(finalized.name)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JoinFinalizeResult {
    name: String,
    public_key: String,
}

fn finalize_join_data_inner(
    confbase: &Path,
    invitation_data: &str,
    force: bool,
) -> Result<JoinFinalizeResult, TincError> {
    let chunks = split_invitation_chunks(invitation_data);
    let first_chunk = chunks
        .first()
        .filter(|chunk| !chunk.is_empty())
        .ok_or_else(|| TincError::InvalidArguments("empty invitation data".to_owned()))?;
    let local_name = invitation_chunk_name(first_chunk).ok_or_else(|| {
        TincError::InvalidArguments("no Name found in invitation data".to_owned())
    })?;

    if !check_id(&local_name) {
        return Err(TincError::InvalidNodeName(local_name));
    }

    let tinc_conf = confbase.join("tinc.conf");

    if tinc_conf.exists() {
        return Err(TincError::ConfigurationExists(tinc_conf));
    }

    let hosts_dir = confbase.join("hosts");
    fs::create_dir_all(&hosts_dir).map_err(|error| io_error(&hosts_dir, error))?;

    let mut server_config = format!("Name = {local_name}\n");
    let mut local_host_config = String::new();
    let mut tinc_up_script = join_tinc_up_header();
    let mut valid_tinc_up = false;

    for line in first_chunk {
        let normalized = normalize_invitation_line(line);

        if normalized.is_empty() || normalized.starts_with('#') {
            continue;
        }

        let (variable, value) = parse_config_file_line(normalized);

        if variable.is_empty()
            || variable.eq_ignore_ascii_case("Name")
            || variable.eq_ignore_ascii_case("NetName")
        {
            continue;
        }

        if variable.eq_ignore_ascii_case("Ifconfig") {
            valid_tinc_up |= append_join_ifconfig_statement(&mut tinc_up_script, value);
            continue;
        }

        if variable.eq_ignore_ascii_case("Route") {
            valid_tinc_up |= append_join_route_statement(&mut tinc_up_script, value);
            continue;
        }

        let Some(spec) = lookup_variable(variable) else {
            continue;
        };

        if !spec.is_safe() && !force {
            continue;
        }

        if spec.is_host() {
            local_host_config.push_str(&format!("{} = {value}\n", spec.name));
        } else {
            server_config.push_str(&format!("{} = {value}\n", spec.name));
        }
    }

    let key = generate_ed25519_keypair()?;
    let public_key = key.public_key().to_base64();
    local_host_config.push_str(&format!("Ed25519PublicKey = {public_key}\n"));

    write_config_text(&tinc_conf, &server_config)?;
    fs::write(hosts_dir.join(&local_name), local_host_config)
        .map_err(|error| io_error(&hosts_dir.join(&local_name), error))?;
    write_private_text(&confbase.join("ed25519_key.priv"), &key.to_pem())?;
    fs::write(confbase.join("invitation-data"), invitation_data)
        .map_err(|error| io_error(&confbase.join("invitation-data"), error))?;
    write_join_tinc_up(confbase, tinc_up_script, valid_tinc_up, force)?;

    for chunk in chunks.iter().skip(1) {
        let Some(name) = invitation_chunk_name(chunk) else {
            continue;
        };

        if !check_id(&name) {
            return Err(TincError::InvalidNodeName(name));
        }

        if name == local_name {
            return Err(TincError::InvalidArguments(
                "secondary invitation chunk would overwrite local host config".to_owned(),
            ));
        }

        let mut host_config = String::new();

        for line in chunk {
            let normalized = normalize_invitation_line(line);
            let (variable, _) = parse_config_file_line(normalized);

            if variable.eq_ignore_ascii_case("Name") {
                continue;
            }

            if !normalized.is_empty() {
                host_config.push_str(normalized);
                host_config.push('\n');
            }
        }

        fs::write(hosts_dir.join(&name), host_config)
            .map_err(|error| io_error(&hosts_dir.join(&name), error))?;
    }

    Ok(JoinFinalizeResult {
        name: local_name,
        public_key,
    })
}

fn write_join_legacy_rsa_keys(confbase: &Path, local_name: &str) -> Result<(), TincError> {
    let rsa_key = generate_rsa_keypair(DEFAULT_RSA_BITS)?;
    let rsa_private_pem = rsa_key.to_pkcs1_pem(LineEnding::LF).map_err(|error| {
        TincError::InvalidArguments(format!("could not encode RSA key: {error}"))
    })?;
    write_private_text(&confbase.join("rsa_key.priv"), rsa_private_pem.as_str())?;

    let rsa_public_pem = RsaPublicKey::from(&rsa_key)
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|error| {
            TincError::InvalidArguments(format!("could not encode RSA public key: {error}"))
        })?;
    append_config_text(
        &confbase.join("hosts").join(local_name),
        &rsa_public_pem,
        FilePrivacy::Public,
    )
}

fn join_tinc_up_header() -> String {
    #[cfg(target_os = "linux")]
    {
        "#!/bin/sh\nip link set \"$INTERFACE\" up\n".to_owned()
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        "#!/bin/sh\n".to_owned()
    }
    #[cfg(windows)]
    {
        String::new()
    }
}

fn append_join_ifconfig_statement(script: &mut String, value: &str) -> bool {
    if value.eq_ignore_ascii_case("dhcp") {
        append_join_dhcp(script);
        return true;
    }
    if value.eq_ignore_ascii_case("dhcp6") {
        append_join_dhcp6(script);
        return true;
    }
    if value.eq_ignore_ascii_case("slaac") {
        append_join_slaac(script);
        return true;
    }

    let Ok(address) = value.parse::<Subnet>() else {
        return false;
    };
    match address.kind {
        SubnetKind::Ipv4 { .. } | SubnetKind::Ipv6 { .. } => {
            append_join_address(script, &address);
            true
        }
        SubnetKind::Mac(_) => false,
    }
}

fn append_join_route_statement(script: &mut String, value: &str) -> bool {
    let (subnet, gateway) = value.split_once(' ').unwrap_or((value, ""));
    let Ok(subnet) = subnet.parse::<Subnet>() else {
        return false;
    };
    if matches!(subnet.kind, SubnetKind::Mac(_)) {
        return false;
    }

    let gateway = gateway.trim_start_matches(' ');
    let gateway = if gateway.is_empty() {
        None
    } else {
        let Ok(parsed) = gateway.parse::<Subnet>() else {
            return false;
        };
        if !same_subnet_family(&subnet, &parsed) || matches!(parsed.kind, SubnetKind::Mac(_)) {
            return false;
        }
        let gateway = parsed.to_string();
        Some(
            gateway
                .split_once('/')
                .map(|(address, _)| address.to_owned())
                .unwrap_or(gateway),
        )
    };

    append_join_route(script, &subnet, gateway.as_deref());
    true
}

fn same_subnet_family(left: &Subnet, right: &Subnet) -> bool {
    matches!(
        (&left.kind, &right.kind),
        (SubnetKind::Ipv4 { .. }, SubnetKind::Ipv4 { .. })
            | (SubnetKind::Ipv6 { .. }, SubnetKind::Ipv6 { .. })
    )
}

fn append_join_dhcp(script: &mut String) {
    #[cfg(target_os = "linux")]
    script.push_str("dhclient -nw \"$INTERFACE\"\n");
    #[cfg(all(unix, not(target_os = "linux")))]
    script.push_str("dhclient -nw \"$INTERFACE\"\n");
    #[cfg(windows)]
    script.push_str("netsh interface ipv4 set address \"%INTERFACE%\" dhcp\n");
}

fn append_join_dhcp6(script: &mut String) {
    #[cfg(not(windows))]
    script.push_str("dhclient -6 -nw \"$INTERFACE\"\n");
}

fn append_join_slaac(script: &mut String) {
    #[cfg(target_os = "linux")]
    {
        script.push_str("echo 1 >\"/proc/sys/net/ipv6/conf/$INTERFACE/accept_ra\"\n");
        script.push_str("echo 1 >\"/proc/sys/net/ipv6/conf/$INTERFACE/autoconf\"\n");
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    script.push_str("rtsol \"$INTERFACE\" &\n");
}

fn append_join_address(script: &mut String, address: &Subnet) {
    #[cfg(target_os = "linux")]
    script.push_str(&format!("ip addr replace {address} dev \"$INTERFACE\"\n"));
    #[cfg(all(unix, not(target_os = "linux")))]
    match address.kind {
        SubnetKind::Ipv4 { .. } => script.push_str(&format!("ifconfig \"$INTERFACE\" {address}\n")),
        SubnetKind::Ipv6 { .. } => {
            script.push_str(&format!("ifconfig \"$INTERFACE\" inet6 {address}\n"))
        }
        SubnetKind::Mac(_) => {}
    }
    #[cfg(windows)]
    match address.kind {
        SubnetKind::Ipv4 { .. } => script.push_str(&format!(
            "netsh interface ipv4 set address \"%INTERFACE%\" static {address}\n"
        )),
        SubnetKind::Ipv6 { .. } => script.push_str(&format!(
            "netsh interface ipv6 set address \"%INTERFACE%\" {address}\n"
        )),
        SubnetKind::Mac(_) => {}
    }
}

fn append_join_route(script: &mut String, subnet: &Subnet, gateway: Option<&str>) {
    #[cfg(target_os = "linux")]
    {
        if let Some(gateway) = gateway {
            script.push_str(&format!(
                "ip route add {subnet} via {gateway} dev \"$INTERFACE\" onlink\n"
            ));
        } else {
            script.push_str(&format!("ip route add {subnet} dev \"$INTERFACE\"\n"));
        }
    }
    #[cfg(windows)]
    match subnet.kind {
        SubnetKind::Ipv4 { .. } => {
            if let Some(gateway) = gateway {
                script.push_str(&format!(
                    "netsh interface ipv4 add route {subnet} \"%INTERFACE%\" {gateway}\n"
                ));
            } else {
                script.push_str(&format!(
                    "netsh interface ipv4 add route {subnet} \"%INTERFACE%\"\n"
                ));
            }
        }
        SubnetKind::Ipv6 { .. } => {
            if let Some(gateway) = gateway {
                script.push_str(&format!(
                    "netsh interface ipv6 add route {subnet} \"%INTERFACE%\" {gateway}\n"
                ));
            } else {
                script.push_str(&format!(
                    "netsh interface ipv6 add route {subnet} \"%INTERFACE%\"\n"
                ));
            }
        }
        SubnetKind::Mac(_) => {}
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let Some(gateway) = gateway else {
            return;
        };
        match subnet.kind {
            SubnetKind::Ipv4 { .. } => script.push_str(&format!("route add {subnet} {gateway}\n")),
            SubnetKind::Ipv6 { .. } => {
                script.push_str(&format!("route add -inet6 {subnet} {gateway}\n"))
            }
            SubnetKind::Mac(_) => {}
        }
    }
}

fn finalize_join_tinc_up(script: &mut String, valid: bool) {
    if valid {
        #[cfg(all(unix, not(target_os = "linux")))]
        script.push_str("ifconfig \"$INTERFACE\" up\n");
        return;
    }

    #[cfg(target_os = "linux")]
    script.push_str(
        "#ip addr add <your vpn IP address>/<prefix of whole VPN> dev $INTERFACE\n\n\
echo \"Unconfigured tinc-up script, please edit '$0'!\" >&2\n",
    );
    #[cfg(all(unix, not(target_os = "linux")))]
    script.push_str(
        "#ifconfig $INTERFACE <your vpn IP address>/<prefix of whole VPN>\n\n\
echo \"Unconfigured tinc-up script, please edit '$0'!\" >&2\n",
    );
}

fn write_join_tinc_up(
    confbase: &Path,
    mut script: String,
    valid: bool,
    force: bool,
) -> Result<(), TincError> {
    finalize_join_tinc_up(&mut script, valid);
    let enabled = !valid || force;
    let path = confbase.join(if enabled {
        #[cfg(windows)]
        {
            "tinc-up.bat"
        }
        #[cfg(not(windows))]
        {
            "tinc-up"
        }
    } else {
        "tinc-up.invitation"
    });
    fs::write(&path, script).map_err(|error| io_error(&path, error))?;

    if enabled {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .map_err(|error| io_error(&path, error))?;
        }
    }

    Ok(())
}

fn parse_invitation_authority(authority: &str) -> Result<(String, String), TincError> {
    if authority.is_empty() {
        return Err(invalid_invitation_url());
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let Some((address, after_bracket)) = rest.split_once(']') else {
            return Err(invalid_invitation_url());
        };

        if address.is_empty() {
            return Err(invalid_invitation_url());
        }

        let port = after_bracket.strip_prefix(':').unwrap_or("655");

        if port.is_empty() {
            return Err(invalid_invitation_url());
        }

        return Ok((address.to_owned(), port.to_owned()));
    }

    match authority.split_once(':') {
        Some((address, port)) if !address.is_empty() && !port.is_empty() => {
            Ok((address.to_owned(), port.to_owned()))
        }
        Some(_) => Err(invalid_invitation_url()),
        None => Ok((authority.to_owned(), "655".to_owned())),
    }
}

fn decode_invitation_token_half(token: &str) -> Result<[u8; 18], TincError> {
    let decoded = b64decode_tinc(token).map_err(|_| invalid_invitation_url())?;

    decoded.try_into().map_err(|_| invalid_invitation_url())
}

fn invalid_invitation_url() -> TincError {
    TincError::InvalidArguments("invalid invitation URL".to_owned())
}

fn trim_meta_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn split_invitation_chunks(invitation_data: &str) -> Vec<Vec<&str>> {
    let mut chunks = vec![Vec::new()];

    for line in invitation_data.lines() {
        if normalize_invitation_line(line)
            == "#---------------------------------------------------------------#"
        {
            chunks.push(Vec::new());
        } else if let Some(chunk) = chunks.last_mut() {
            chunk.push(line);
        }
    }

    chunks
}

fn invitation_chunk_name(chunk: &[&str]) -> Option<String> {
    chunk.iter().find_map(|line| {
        let (variable, value) = parse_config_file_line(normalize_invitation_line(line));

        if variable.eq_ignore_ascii_case("Name") && !value.is_empty() {
            value
                .split_whitespace()
                .next()
                .map(std::borrow::ToOwned::to_owned)
        } else {
            None
        }
    })
}

fn normalize_invitation_line(line: &str) -> &str {
    line.trim_end_matches('\r')
}

fn run_generate_ed25519_keys_command(command: &TincCommand) -> Result<String, TincError> {
    if !command.arguments.is_empty() {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    let name = read_local_name(&confbase).ok();
    let key = generate_ed25519_keypair()?;
    write_ed25519_keypair(&confbase, name.as_deref(), &key)?;
    Ok(String::new())
}

fn run_generate_keys_command(command: &TincCommand) -> Result<String, TincError> {
    if command.arguments.len() > 1 {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    let name = read_local_name(&confbase).ok();
    let bits = parse_rsa_key_bits(command.arguments.first().map(String::as_str))?;
    let rsa = generate_rsa_keypair(bits)?;
    write_rsa_keypair(&confbase, name.as_deref(), &rsa)?;
    let ed25519 = generate_ed25519_keypair()?;
    write_ed25519_keypair(&confbase, name.as_deref(), &ed25519)?;
    Ok(String::new())
}

fn run_generate_rsa_keys_command(command: &TincCommand) -> Result<String, TincError> {
    if command.arguments.len() > 1 {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    let name = read_local_name(&confbase).ok();
    let bits = parse_rsa_key_bits(command.arguments.first().map(String::as_str))?;
    let key = generate_rsa_keypair(bits)?;
    write_rsa_keypair(&confbase, name.as_deref(), &key)?;
    Ok(String::new())
}

fn run_sign_command(command: &TincCommand, input: &[u8]) -> Result<Vec<u8>, TincError> {
    if command.arguments.len() > 1 {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    let name = read_local_name(&confbase)?;
    let key = read_private_ed25519_key(&confbase)?;
    let payload = match command.arguments.first() {
        Some(path) => fs::read(path).map_err(|error| io_error(Path::new(path), error))?,
        None => input.to_vec(),
    };
    let timestamp = current_unix_time();
    let trailer = format!(" {name} {timestamp}");
    let mut signed_payload = Vec::with_capacity(payload.len() + trailer.len());
    signed_payload.extend_from_slice(&payload);
    signed_payload.extend_from_slice(trailer.as_bytes());
    let signature = key.sign(&signed_payload);

    let mut output = format!(
        "Signature = {name} {timestamp} {}\n",
        b64encode_tinc(&signature)
    )
    .into_bytes();
    output.extend_from_slice(&payload);
    Ok(output)
}

fn run_verify_command(command: &TincCommand, input: &[u8]) -> Result<Vec<u8>, TincError> {
    if command.arguments.is_empty() {
        return Err(TincError::InvalidArguments(
            "not enough arguments".to_owned(),
        ));
    }

    if command.arguments.len() > 2 {
        return Err(TincError::TooManyArguments);
    }

    let confbase = resolve_confbase(&command.options);
    let requested_node = parse_verify_node(&confbase, &command.arguments[0])?;
    let data = match command.arguments.get(1) {
        Some(path) => fs::read(path).map_err(|error| io_error(Path::new(path), error))?,
        None => input.to_vec(),
    };
    let (header, payload) = split_signature_input(&data)?;
    let signature = parse_signature_header(header)?;

    if let Some(node) = &requested_node {
        if node != &signature.signer {
            return Err(TincError::InvalidArguments(format!(
                "signature is not made by {node}"
            )));
        }
    }

    let public_key = read_host_ed25519_public_key(&confbase, &signature.signer)?;
    let trailer = format!(" {} {}", signature.signer, signature.timestamp);
    let mut signed_payload = Vec::with_capacity(payload.len() + trailer.len());
    signed_payload.extend_from_slice(payload);
    signed_payload.extend_from_slice(trailer.as_bytes());

    public_key
        .verify(&signed_payload, &signature.signature)
        .map_err(|_| TincError::InvalidArguments("invalid signature".to_owned()))?;

    Ok(payload.to_vec())
}

fn run_init_command(command: &TincCommand) -> Result<String, TincError> {
    run_init_command_with_name_reader(command, stdin_stdout_are_terminals(), read_init_name)
}

fn run_init_command_with_name_reader(
    command: &TincCommand,
    interactive: bool,
    mut read_name: impl FnMut() -> Result<String, TincError>,
) -> Result<String, TincError> {
    run_init_command_with_name_reader_and_ports(
        command,
        interactive,
        &mut read_name,
        init_random_port,
        try_bind_tinc_port,
    )
}

fn run_init_command_with_name_reader_and_ports(
    command: &TincCommand,
    interactive: bool,
    read_name: &mut impl FnMut() -> Result<String, TincError>,
    random_port: impl FnMut() -> Result<u16, TincError>,
    try_bind_port: impl FnMut(u16) -> bool,
) -> Result<String, TincError> {
    let confbase = resolve_confbase(&command.options);
    let tinc_conf = confbase.join("tinc.conf");

    if tinc_conf.exists() {
        return Err(TincError::ConfigurationExists(tinc_conf));
    }

    let name = match command.arguments.as_slice() {
        [] if interactive => read_name()?,
        [] => return Err(TincError::MissingName),
        [name] if !name.is_empty() => name.clone(),
        [_] => return Err(TincError::MissingName),
        _ => return Err(TincError::TooManyArguments),
    };

    if !check_id(&name) {
        return Err(TincError::InvalidNodeName(name.clone()));
    }

    fs::create_dir_all(confbase.join("hosts")).map_err(|error| io_error(&confbase, error))?;
    fs::create_dir_all(confbase.join("conf.d")).map_err(|error| io_error(&confbase, error))?;
    fs::create_dir_all(confbase.join("cache")).map_err(|error| io_error(&confbase, error))?;
    fs::write(&tinc_conf, format!("Name = {name}\n"))
        .map_err(|error| io_error(&tinc_conf, error))?;

    let rsa = generate_rsa_keypair(DEFAULT_RSA_BITS)?;
    write_rsa_keypair(&confbase, Some(&name), &rsa)?;
    let key = generate_ed25519_keypair()?;
    write_ed25519_keypair(&confbase, Some(&name), &key)?;
    check_init_port(&confbase, &name, random_port, try_bind_port)?;
    create_default_tinc_up(&confbase)?;

    Ok(String::new())
}

fn check_init_port(
    confbase: &Path,
    name: &str,
    mut random_port: impl FnMut() -> Result<u16, TincError>,
    mut try_bind_port: impl FnMut(u16) -> bool,
) -> Result<u16, TincError> {
    if try_bind_port(DEFAULT_TINC_PORT) {
        return Ok(DEFAULT_TINC_PORT);
    }

    eprint!("Warning: could not bind to port {DEFAULT_TINC_PORT}. ");

    for _ in 0..INIT_RANDOM_PORT_ATTEMPTS {
        let port = random_port()?;

        if try_bind_port(port) {
            let host_config = confbase.join("hosts").join(name);
            match append_config_text(
                &host_config,
                &format!("Port = {port}\n"),
                FilePrivacy::Public,
            ) {
                Ok(()) => {
                    eprintln!("Tinc will instead listen on port {port}.");
                    return Ok(port);
                }
                Err(error) => {
                    eprintln!("{error}");
                    eprintln!("Please change tinc's Port manually.");
                    return Ok(0);
                }
            }
        }
    }

    eprintln!("Please change tinc's Port manually.");
    Ok(0)
}

fn init_random_port() -> Result<u16, TincError> {
    let mut bytes = [0u8; 2];
    getrandom::getrandom(&mut bytes).map_err(|error| TincError::Random(error.to_string()))?;
    let offset = u16::from_ne_bytes(bytes) % INIT_RANDOM_PORT_SPAN;
    Ok(INIT_RANDOM_PORT_BASE + offset)
}

#[cfg(unix)]
fn try_bind_tinc_port(port: u16) -> bool {
    let port = match CString::new(port.to_string()) {
        Ok(port) => port,
        Err(_) => return false,
    };
    let hints = libc::addrinfo {
        ai_flags: libc::AI_PASSIVE,
        ai_family: libc::AF_UNSPEC,
        ai_socktype: libc::SOCK_STREAM,
        ai_protocol: libc::IPPROTO_TCP,
        ai_addrlen: 0,
        ai_addr: std::ptr::null_mut(),
        ai_canonname: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };
    let mut result: *mut libc::addrinfo = std::ptr::null_mut();

    // SAFETY: `port` and `hints` are valid for this call, and `result` is freed with
    // `freeaddrinfo` before returning when resolution succeeds.
    let resolved =
        unsafe { libc::getaddrinfo(std::ptr::null(), port.as_ptr(), &hints, &mut result) };
    if resolved != 0 || result.is_null() {
        return false;
    }

    // The original C code loops over addrinfo entries but accidentally uses the
    // head pointer for each socket/bind attempt. Matching that keeps the same
    // practical port check on platforms where getaddrinfo returns multiple rows.
    let info = unsafe { &*result };
    // SAFETY: `info` points to an addrinfo returned by getaddrinfo.
    let fd = unsafe { libc::socket(info.ai_family, libc::SOCK_STREAM, libc::IPPROTO_TCP) };
    if fd == -1 {
        // SAFETY: `result` came from getaddrinfo and has not been freed yet.
        unsafe {
            libc::freeaddrinfo(result);
        }
        return false;
    }

    // SAFETY: `fd` is a valid socket and `info.ai_addr`/`ai_addrlen` come from getaddrinfo.
    let bind_result = unsafe { libc::bind(fd, info.ai_addr, info.ai_addrlen) };
    // SAFETY: `fd` was returned by socket above.
    unsafe {
        libc::close(fd);
        libc::freeaddrinfo(result);
    }

    bind_result == 0
}

#[cfg(not(unix))]
fn try_bind_tinc_port(port: u16) -> bool {
    let Ok(addresses) = ("0.0.0.0", port).to_socket_addrs() else {
        return false;
    };

    addresses
        .into_iter()
        .any(|address| TcpListener::bind(address).is_ok())
}

fn stdin_stdout_are_terminals() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn read_init_name() -> Result<String, TincError> {
    eprint!("Enter the Name you want your tinc node to have: ");
    io::stderr().flush().map_err(|error| TincError::Io {
        path: PathBuf::from("stderr"),
        error: error.to_string(),
    })?;

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    read_init_name_from_reader(&mut reader)
}

fn read_init_name_from_reader(reader: &mut impl BufRead) -> Result<String, TincError> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).map_err(|error| TincError::Io {
        path: PathBuf::from("stdin"),
        error: error.to_string(),
    })?;

    if bytes == 0 {
        return Err(TincError::Io {
            path: PathBuf::from("stdin"),
            error: "unexpected end of file".to_owned(),
        });
    }

    let name = rstrip_tinc_whitespace(&line).to_owned();

    if name.is_empty() {
        return Err(TincError::MissingName);
    }

    Ok(name)
}

fn rstrip_tinc_whitespace(value: &str) -> &str {
    value.trim_end_matches(['\t', '\r', '\n', ' '])
}

fn run_edit_command(command: &TincCommand) -> Result<String, TincError> {
    let editor = env::var_os("VISUAL")
        .or_else(|| env::var_os("EDITOR"))
        .unwrap_or_else(|| "vi".into());
    run_edit_command_with_editor(command, editor.as_os_str())
}

fn run_edit_command_with_editor(
    command: &TincCommand,
    editor: &OsStr,
) -> Result<String, TincError> {
    let target = resolve_edit_target_path(command)?;
    run_editor_program(editor, &target)?;

    let reload = TincCommand {
        options: command.options.clone(),
        name: "reload".to_owned(),
        arguments: Vec::new(),
    };
    let _ = run_simple_control_command(&reload);

    Ok(String::new())
}

fn resolve_edit_target_path(command: &TincCommand) -> Result<PathBuf, TincError> {
    if command.arguments.len() != 1 {
        return Err(TincError::InvalidArguments(
            "invalid number of arguments".to_owned(),
        ));
    }

    resolve_edit_target_in_confbase(&resolve_confbase(&command.options), &command.arguments[0])
}

fn resolve_edit_target_in_confbase(confbase: &Path, filename: &str) -> Result<PathBuf, TincError> {
    if let Some(host_file) = strip_hosts_prefix(filename) {
        validate_host_edit_filename(host_file)?;
        return Ok(join_tinc_path_literal(&confbase.join("hosts"), host_file));
    }

    if EDIT_CONFIG_FILES.contains(&filename) {
        return Ok(join_tinc_path_literal(confbase, filename));
    }

    validate_host_edit_filename(filename)?;
    Ok(join_tinc_path_literal(&confbase.join("hosts"), filename))
}

fn strip_hosts_prefix(filename: &str) -> Option<&str> {
    filename.strip_prefix("hosts/").or_else(|| {
        #[cfg(windows)]
        {
            filename.strip_prefix("hosts\\")
        }

        #[cfg(not(windows))]
        {
            None
        }
    })
}

fn validate_host_edit_filename(filename: &str) -> Result<(), TincError> {
    if let Some((node, kind)) = filename.split_once('-') {
        if (kind != "up" && kind != "down") || !check_id(node) {
            return Err(TincError::InvalidArguments(
                "Invalid configuration filename.".to_owned(),
            ));
        }
    }

    Ok(())
}

fn join_tinc_path_literal(base: &Path, filename: &str) -> PathBuf {
    let mut path = base.to_path_buf();

    for component in filename.split('/') {
        if !component.is_empty() {
            path.push(component);
        }
    }

    path
}

fn run_editor_program(editor: &OsStr, target: &Path) -> Result<(), TincError> {
    let status = Command::new(editor)
        .arg(target)
        .status()
        .map_err(|error| TincError::EditFailed(error.to_string()))?;

    if !status.success() {
        return Err(TincError::EditFailed(format!(
            "{} exited with {status}",
            Path::new(editor).display()
        )));
    }

    Ok(())
}

fn run_pid_command(command: &TincCommand) -> Result<String, TincError> {
    if !command.arguments.is_empty() {
        return Err(TincError::TooManyArguments);
    }

    let path = resolve_pidfile(&command.options);
    let pidfile = read_pidfile(&path)?;
    let socket = control_socket_path(&path);
    verify_control_socket(&socket, &pidfile)?;
    Ok(format!("{}\n", pidfile.pid))
}

fn run_dump_command(command: &TincCommand) -> Result<String, TincError> {
    let request = build_dump_control_request(command)?;

    if request.mode == DumpMode::Invitations {
        return dump_invitations(&resolve_confbase(&command.options));
    }

    let path = resolve_pidfile(&command.options);
    let pidfile = read_pidfile(&path)?;
    let socket = control_socket_path(&path);
    let lines = send_control_dump_requests(&socket, &pidfile, &request.lines)?;
    format_dump_response(&request, &lines)
}

fn run_info_command(command: &TincCommand) -> Result<String, TincError> {
    if command.arguments.len() != 1 {
        return Err(TincError::InvalidArguments(
            "invalid number of arguments".to_owned(),
        ));
    }

    let item = &command.arguments[0];
    let control = Request::Control.number();
    let requests = if check_id(item) {
        vec![
            ControlRequestLine {
                request: REQ_DUMP_NODES,
                line: format!("{control} {REQ_DUMP_NODES} {item}\n"),
            },
            ControlRequestLine {
                request: REQ_DUMP_EDGES,
                line: format!("{control} {REQ_DUMP_EDGES} {item}\n"),
            },
            ControlRequestLine {
                request: REQ_DUMP_SUBNETS,
                line: format!("{control} {REQ_DUMP_SUBNETS} {item}\n"),
            },
        ]
    } else if item.contains('.') || item.contains(':') {
        vec![ControlRequestLine {
            request: REQ_DUMP_SUBNETS,
            line: format!("{control} {REQ_DUMP_SUBNETS} {item}\n"),
        }]
    } else {
        return Err(TincError::InvalidArguments(
            "argument is not a node name, subnet or address".to_owned(),
        ));
    };

    let path = resolve_pidfile(&command.options);
    let pidfile = read_pidfile(&path)?;
    let socket = control_socket_path(&path);
    let lines = send_control_dump_requests(&socket, &pidfile, &requests)?;

    if check_id(item) {
        format_info_node(item, &lines)
    } else {
        format_info_subnet_or_address(item, &lines)
    }
}

fn run_log_command(command: &TincCommand) -> Result<String, TincError> {
    if command.arguments.len() > 1 {
        return Err(TincError::TooManyArguments);
    }

    let level = command
        .arguments
        .first()
        .and_then(|argument| parse_c_i32_prefix(argument))
        .unwrap_or(DEBUG_UNSET);
    let control = Request::Control.number();
    let colorize = i32::from(io::stdout().is_terminal());
    let request = ControlRequestLine {
        request: REQ_LOG,
        line: format!("{control} {REQ_LOG} {level} {colorize}\n"),
    };
    let path = resolve_pidfile(&command.options);
    let pidfile = read_pidfile(&path)?;
    let socket = control_socket_path(&path);

    send_control_log_request(&socket, &pidfile, &request)
}

fn run_pcap_command(command: &TincCommand) -> Result<Vec<u8>, TincError> {
    if command.arguments.len() > 1 {
        return Err(TincError::TooManyArguments);
    }

    let snaplen = command
        .arguments
        .first()
        .and_then(|argument| parse_c_u32_prefix(argument))
        .unwrap_or_default();
    let control = Request::Control.number();
    let request = ControlRequestLine {
        request: REQ_PCAP,
        line: format!("{control} {REQ_PCAP} {snaplen}\n"),
    };
    let path = resolve_pidfile(&command.options);
    let pidfile = read_pidfile(&path)?;
    let socket = control_socket_path(&path);

    send_control_pcap_request(&socket, &pidfile, &request, snaplen)
}

fn run_top_command(command: &TincCommand) -> Result<String, TincError> {
    if !command.arguments.is_empty() {
        return Err(TincError::TooManyArguments);
    }

    run_top_interactive_command(command)?;
    Ok(String::new())
}

#[cfg(test)]
fn run_top_snapshots_command(command: &TincCommand, frames: usize) -> Result<String, TincError> {
    if frames == 0 {
        return Ok(String::new());
    }

    let pidfile = read_pidfile(&resolve_pidfile(&command.options))?;
    let socket = control_socket_path(&resolve_pidfile(&command.options));
    let request = ControlRequestLine {
        request: REQ_DUMP_TRAFFIC,
        line: format!("{} {REQ_DUMP_TRAFFIC}\n", Request::Control.number()),
    };

    let mut output = String::new();
    for frame in 0..frames {
        let lines = send_control_dump_requests(&socket, &pidfile, std::slice::from_ref(&request))?;
        if frames > 1 {
            output.push_str(&format!("Frame {}\n", frame + 1));
        }
        output.push_str(&format_top_snapshot(&lines)?);
        if frames > 1 && frame + 1 != frames {
            output.push('\n');
        }
    }

    Ok(output)
}

#[cfg(unix)]
fn run_top_interactive_command(command: &TincCommand) -> Result<(), TincError> {
    if !stdin_stdout_are_terminals() {
        return Err(TincError::InvalidArguments(
            "top requires an interactive terminal".to_owned(),
        ));
    }

    let path = resolve_pidfile(&command.options);
    let pidfile = read_pidfile(&path)?;
    let socket_path = control_socket_path(&path);
    let mut socket = open_control_socket(&socket_path, &pidfile)?;
    let mut state = TopState::new();
    let mut stdout = io::stdout();
    let mut terminal = TopTerminal::enter(&mut stdout)?;

    loop {
        let lines = send_top_dump_request(&mut socket)?;
        state.update_from_traffic_lines(&lines, top_now_since_epoch())?;
        let frame = state.render(command.options.netname.as_deref(), true);

        stdout
            .write_all(b"\x1b[H\x1b[2J")
            .map_err(|error| io_error(Path::new("stdout"), error))?;
        stdout
            .write_all(frame.as_bytes())
            .map_err(|error| io_error(Path::new("stdout"), error))?;
        stdout
            .flush()
            .map_err(|error| io_error(Path::new("stdout"), error))?;

        match read_top_key(state.delay) {
            Ok(Some(TopKey::Quit)) => break,
            Ok(Some(TopKey::PromptDelay)) => {
                prompt_top_delay(&mut state, &mut terminal, &mut stdout)?;
            }
            Ok(Some(TopKey::ToggleCumulative)) => state.cumulative = !state.cumulative,
            Ok(Some(TopKey::Sort(sort))) => state.sort = sort,
            Ok(Some(TopKey::Units(units))) => state.units = units,
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }

    terminal.restore(&mut stdout)?;
    Ok(())
}

#[cfg(not(unix))]
fn run_top_interactive_command(_command: &TincCommand) -> Result<(), TincError> {
    Err(TincError::ControlUnsupported)
}

#[cfg(unix)]
fn send_top_dump_request(socket: &mut ControlSocket) -> Result<Vec<String>, TincError> {
    let request = ControlRequestLine {
        request: REQ_DUMP_TRAFFIC,
        line: format!("{} {REQ_DUMP_TRAFFIC}\n", Request::Control.number()),
    };
    send_control_line(socket, &request)?;

    let mut lines = Vec::new();
    loop {
        let line = read_control_line(&mut socket.reader)?;
        let fields = line.split_whitespace().collect::<Vec<_>>();

        if fields.len() < 2 {
            return Err(TincError::ControlResponse(line));
        }

        let complete = fields.len() == 2;
        lines.push(line);

        if complete {
            break;
        }
    }

    Ok(lines)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TopSort {
    Name,
    InPackets,
    InBytes,
    OutPackets,
    OutBytes,
    TotalPackets,
    TotalBytes,
}

impl TopSort {
    const fn name(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::InPackets => "in pkts",
            Self::InBytes => "in bytes",
            Self::OutPackets => "out pkts",
            Self::OutBytes => "out bytes",
            Self::TotalPackets => "tot pkts",
            Self::TotalBytes => "tot bytes",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct TopUnits {
    bytes: &'static str,
    byte_scale: f64,
    packets: &'static str,
    packet_scale: f64,
}

impl TopUnits {
    const BYTES: Self = Self {
        bytes: "bytes",
        byte_scale: 1.0,
        packets: "pkts",
        packet_scale: 1.0,
    };
    const KILOBYTES: Self = Self {
        bytes: "kbyte",
        byte_scale: 1e-3,
        packets: "pkts",
        packet_scale: 1.0,
    };
    const MEGABYTES: Self = Self {
        bytes: "Mbyte",
        byte_scale: 1e-6,
        packets: "kpkt",
        packet_scale: 1e-3,
    };
    const GIGABYTES: Self = Self {
        bytes: "Gbyte",
        byte_scale: 1e-9,
        packets: "Mpkt",
        packet_scale: 1e-6,
    };
}

#[derive(Clone, Debug)]
struct TopNodeStats {
    name: String,
    display_order: usize,
    in_packets: u64,
    in_bytes: u64,
    out_packets: u64,
    out_bytes: u64,
    in_packets_rate: f64,
    in_bytes_rate: f64,
    out_packets_rate: f64,
    out_bytes_rate: f64,
    known: bool,
}

impl TopNodeStats {
    fn new(name: String) -> Self {
        Self {
            name,
            display_order: 0,
            in_packets: 0,
            in_bytes: 0,
            out_packets: 0,
            out_bytes: 0,
            in_packets_rate: 0.0,
            in_bytes_rate: 0.0,
            out_packets_rate: 0.0,
            out_bytes_rate: 0.0,
            known: false,
        }
    }
}

#[derive(Clone, Debug)]
struct TopState {
    nodes: Vec<TopNodeStats>,
    sorted: Vec<usize>,
    changed: bool,
    previous: Option<Duration>,
    delay: Duration,
    sort: TopSort,
    cumulative: bool,
    units: TopUnits,
}

impl TopState {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            sorted: Vec::new(),
            changed: true,
            previous: None,
            delay: Duration::from_millis(1000),
            sort: TopSort::Name,
            cumulative: false,
            units: TopUnits::BYTES,
        }
    }

    fn update_from_traffic_lines(
        &mut self,
        lines: &[String],
        now: Duration,
    ) -> Result<(), TincError> {
        for node in &mut self.nodes {
            node.known = false;
        }

        let interval = self
            .previous
            .and_then(|previous| now.checked_sub(previous))
            .unwrap_or(now);
        self.previous = Some(now);
        let interval = interval.as_secs_f64();

        for line in lines {
            let fields = line.split_whitespace().collect::<Vec<_>>();

            if fields.len() >= 2
                && fields[0].parse::<i32>().is_ok()
                && fields[1].parse::<i32>().is_ok()
                && fields.len() == 2
            {
                return Ok(());
            }

            if fields.len() < 7
                || fields[0].parse::<i32>().is_err()
                || fields[1].parse::<i32>().is_err()
            {
                return Err(TincError::DumpParse(line.clone()));
            }

            let name = fields[2];
            let in_packets = parse_u64_field(fields[3], line)?;
            let in_bytes = parse_u64_field(fields[4], line)?;
            let out_packets = parse_u64_field(fields[5], line)?;
            let out_bytes = parse_u64_field(fields[6], line)?;
            let index = self.node_index_or_insert(name);
            let node = &mut self.nodes[index];

            node.known = true;
            node.in_packets_rate = top_rate(in_packets.wrapping_sub(node.in_packets), interval);
            node.in_bytes_rate = top_rate(in_bytes.wrapping_sub(node.in_bytes), interval);
            node.out_packets_rate = top_rate(out_packets.wrapping_sub(node.out_packets), interval);
            node.out_bytes_rate = top_rate(out_bytes.wrapping_sub(node.out_bytes), interval);
            node.in_packets = in_packets;
            node.in_bytes = in_bytes;
            node.out_packets = out_packets;
            node.out_bytes = out_bytes;
        }

        Err(TincError::ControlConnection(
            "unexpected end of traffic dump".to_owned(),
        ))
    }

    fn node_index_or_insert(&mut self, name: &str) -> usize {
        match self
            .nodes
            .binary_search_by(|node| node.name.as_str().cmp(name))
        {
            Ok(index) => index,
            Err(index) => {
                self.nodes.insert(index, TopNodeStats::new(name.to_owned()));
                self.changed = true;
                index
            }
        }
    }

    fn render(&mut self, netname: Option<&str>, ansi: bool) -> String {
        if self.changed || self.sorted.len() != self.nodes.len() {
            self.sorted = (0..self.nodes.len()).collect();
            self.changed = false;
        }

        for (position, index) in self.sorted.iter().copied().enumerate() {
            self.nodes[index].display_order = position;
        }

        let sort = self.sort;
        let cumulative = self.cumulative;
        self.sorted.sort_by(|left, right| {
            top_sort_nodes(&self.nodes[*left], &self.nodes[*right], sort, cumulative)
        });

        let mut output = String::new();
        output.push_str(&format!(
            "Tinc {:<16}  Nodes: {:4}  Sort: {:<10}  {}\n\n",
            netname.unwrap_or(""),
            self.nodes.len(),
            self.sort.name(),
            if self.cumulative {
                "Cumulative"
            } else {
                "Current"
            }
        ));

        if ansi {
            output.push_str("\x1b[7m");
        }
        output.push_str(&format!(
            "Node                IN {}   IN {}   OUT {}  OUT {}",
            self.units.packets, self.units.bytes, self.units.packets, self.units.bytes
        ));
        if ansi {
            output.push_str("\x1b[0m");
        }
        output.push('\n');

        for index in self.sorted.iter().copied() {
            let node = &self.nodes[index];

            if ansi {
                if !node.known {
                    output.push_str("\x1b[2m");
                } else if node.in_packets_rate != 0.0 || node.out_packets_rate != 0.0 {
                    output.push_str("\x1b[1m");
                }
            }

            let values = if self.cumulative {
                (
                    node.in_packets as f64 * self.units.packet_scale,
                    node.in_bytes as f64 * self.units.byte_scale,
                    node.out_packets as f64 * self.units.packet_scale,
                    node.out_bytes as f64 * self.units.byte_scale,
                )
            } else {
                (
                    node.in_packets_rate * self.units.packet_scale,
                    node.in_bytes_rate * self.units.byte_scale,
                    node.out_packets_rate * self.units.packet_scale,
                    node.out_bytes_rate * self.units.byte_scale,
                )
            };

            output.push_str(&format!(
                "{:<16} {:10.0} {:10.0} {:10.0} {:10.0}",
                node.name, values.0, values.1, values.2, values.3
            ));
            if ansi {
                output.push_str("\x1b[0m");
            }
            output.push('\n');
        }

        output
    }
}

fn top_sort_nodes(
    left: &TopNodeStats,
    right: &TopNodeStats,
    sort: TopSort,
    cumulative: bool,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let result = match sort {
        TopSort::Name => left.name.cmp(&right.name),
        TopSort::InPackets => top_order_metric(
            top_packet_metric(left.in_packets, left.in_packets_rate, cumulative),
            top_packet_metric(right.in_packets, right.in_packets_rate, cumulative),
        ),
        TopSort::InBytes => top_order_metric(
            top_packet_metric(left.in_bytes, left.in_bytes_rate, cumulative),
            top_packet_metric(right.in_bytes, right.in_bytes_rate, cumulative),
        ),
        TopSort::OutPackets => top_order_metric(
            top_packet_metric(left.out_packets, left.out_packets_rate, cumulative),
            top_packet_metric(right.out_packets, right.out_packets_rate, cumulative),
        ),
        TopSort::OutBytes => top_order_metric(
            top_packet_metric(left.out_bytes, left.out_bytes_rate, cumulative),
            top_packet_metric(right.out_bytes, right.out_bytes_rate, cumulative),
        ),
        TopSort::TotalPackets => top_order_metric(
            top_packet_metric(
                left.in_packets.wrapping_add(left.out_packets),
                left.in_packets_rate + left.out_packets_rate,
                cumulative,
            ),
            top_packet_metric(
                right.in_packets.wrapping_add(right.out_packets),
                right.in_packets_rate + right.out_packets_rate,
                cumulative,
            ),
        ),
        TopSort::TotalBytes => top_order_metric(
            top_packet_metric(
                left.in_bytes.wrapping_add(left.out_bytes),
                left.in_bytes_rate + left.out_bytes_rate,
                cumulative,
            ),
            top_packet_metric(
                right.in_bytes.wrapping_add(right.out_bytes),
                right.in_bytes_rate + right.out_bytes_rate,
                cumulative,
            ),
        ),
    };

    if result == Ordering::Equal {
        left.display_order.cmp(&right.display_order)
    } else {
        result
    }
}

fn top_packet_metric(value: u64, rate: f64, cumulative: bool) -> f64 {
    if cumulative { value as f64 } else { rate }
}

fn top_order_metric(left: f64, right: f64) -> std::cmp::Ordering {
    right
        .partial_cmp(&left)
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn top_rate(delta: u64, interval: f64) -> f64 {
    if interval == 0.0 {
        if delta == 0 { 0.0 } else { f64::INFINITY }
    } else {
        delta as f64 / interval
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum TopKey {
    Quit,
    PromptDelay,
    ToggleCumulative,
    Sort(TopSort),
    Units(TopUnits),
}

#[cfg(unix)]
fn read_top_key(delay: Duration) -> Result<Option<TopKey>, TincError> {
    use std::os::fd::RawFd;

    let fd: RawFd = libc::STDIN_FILENO;
    let mut readfds = unsafe { std::mem::zeroed::<libc::fd_set>() };
    unsafe {
        libc::FD_ZERO(&mut readfds);
        libc::FD_SET(fd, &mut readfds);
    }

    let seconds = delay.as_secs().min(i64::MAX as u64) as libc::time_t;
    let micros = delay.subsec_micros() as libc::suseconds_t;
    let mut timeout = libc::timeval {
        tv_sec: seconds,
        tv_usec: micros,
    };
    let result = unsafe {
        libc::select(
            fd + 1,
            &mut readfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut timeout,
        )
    };

    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(None);
        }
        return Err(TincError::Io {
            path: PathBuf::from("stdin"),
            error: error.to_string(),
        });
    }

    if result == 0 {
        return Ok(None);
    }

    let mut byte = [0u8; 1];
    let read = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
    if read <= 0 {
        return Ok(None);
    }

    Ok(top_key_from_byte(byte[0]))
}

#[cfg(unix)]
fn top_key_from_byte(byte: u8) -> Option<TopKey> {
    match byte {
        b'q' | 3 => Some(TopKey::Quit),
        b's' => Some(TopKey::PromptDelay),
        b'c' => Some(TopKey::ToggleCumulative),
        b'n' => Some(TopKey::Sort(TopSort::Name)),
        b'i' => Some(TopKey::Sort(TopSort::InBytes)),
        b'I' => Some(TopKey::Sort(TopSort::InPackets)),
        b'o' => Some(TopKey::Sort(TopSort::OutBytes)),
        b'O' => Some(TopKey::Sort(TopSort::OutPackets)),
        b't' => Some(TopKey::Sort(TopSort::TotalBytes)),
        b'T' => Some(TopKey::Sort(TopSort::TotalPackets)),
        b'b' => Some(TopKey::Units(TopUnits::BYTES)),
        b'k' => Some(TopKey::Units(TopUnits::KILOBYTES)),
        b'M' => Some(TopKey::Units(TopUnits::MEGABYTES)),
        b'G' => Some(TopKey::Units(TopUnits::GIGABYTES)),
        _ => None,
    }
}

#[cfg(unix)]
fn prompt_top_delay(
    state: &mut TopState,
    terminal: &mut TopTerminal,
    stdout: &mut impl Write,
) -> Result<(), TincError> {
    terminal.restore(stdout)?;
    stdout
        .write_all(b"\x1b[2;1H\x1b[0K")
        .map_err(|error| io_error(Path::new("stdout"), error))?;
    write!(
        stdout,
        "Change delay from {:.1}s to: ",
        state.delay.as_secs_f64()
    )
    .map_err(|error| io_error(Path::new("stdout"), error))?;
    stdout
        .flush()
        .map_err(|error| io_error(Path::new("stdout"), error))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| TincError::Io {
            path: PathBuf::from("stdin"),
            error: error.to_string(),
        })?;

    if let Ok(mut seconds) = input.trim().parse::<f64>() {
        if seconds < 0.1 {
            seconds = 0.1;
        }
        state.delay = Duration::from_millis((seconds * 1000.0) as u64);
    }

    terminal.enter_raw(stdout)?;
    Ok(())
}

#[cfg(unix)]
struct TopTerminal {
    fd: libc::c_int,
    original: libc::termios,
    raw: bool,
}

#[cfg(unix)]
impl TopTerminal {
    fn enter(stdout: &mut impl Write) -> Result<Self, TincError> {
        let fd = libc::STDIN_FILENO;
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(TincError::Io {
                path: PathBuf::from("stdin"),
                error: io::Error::last_os_error().to_string(),
            });
        }

        let mut terminal = Self {
            fd,
            original,
            raw: false,
        };
        terminal.enter_raw(stdout)?;
        Ok(terminal)
    }

    fn enter_raw(&mut self, stdout: &mut impl Write) -> Result<(), TincError> {
        let mut raw = self.original;
        raw.c_iflag &= !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);
        raw.c_oflag &= !libc::OPOST;
        raw.c_cflag |= libc::CS8;
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;

        if unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &raw) } != 0 {
            return Err(TincError::Io {
                path: PathBuf::from("stdin"),
                error: io::Error::last_os_error().to_string(),
            });
        }

        self.raw = true;
        stdout
            .write_all(b"\x1b[?25l")
            .map_err(|error| io_error(Path::new("stdout"), error))?;
        stdout
            .flush()
            .map_err(|error| io_error(Path::new("stdout"), error))
    }

    fn restore(&mut self, stdout: &mut impl Write) -> Result<(), TincError> {
        if self.raw {
            let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
            self.raw = false;
        }

        stdout
            .write_all(b"\x1b[0m\x1b[?25h")
            .map_err(|error| io_error(Path::new("stdout"), error))?;
        stdout
            .flush()
            .map_err(|error| io_error(Path::new("stdout"), error))
    }
}

#[cfg(unix)]
impl Drop for TopTerminal {
    fn drop(&mut self) {
        if self.raw {
            let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
            let _ = io::stdout().write_all(b"\x1b[0m\x1b[?25h");
            let _ = io::stdout().flush();
            self.raw = false;
        }
    }
}

fn top_now_since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

#[cfg(test)]
fn format_top_snapshot(lines: &[String]) -> Result<String, TincError> {
    let mut output =
        "Node                IN pkts     IN bytes    OUT pkts    OUT bytes\n".to_owned();

    for line in lines {
        let fields = line.split_whitespace().collect::<Vec<_>>();

        if fields.len() < 2 || fields[0].parse::<i32>().ok() != Some(Request::Control.number()) {
            return Err(TincError::DumpParse(line.clone()));
        }

        let request = fields[1]
            .parse::<i32>()
            .map_err(|_| TincError::DumpParse(line.clone()))?;

        if request != REQ_DUMP_TRAFFIC {
            return Err(TincError::DumpParse(line.clone()));
        }

        if fields.len() == 2 {
            continue;
        }

        if fields.len() != 7 {
            return Err(TincError::DumpParse(line.clone()));
        }

        let in_packets = parse_u64_field(fields[3], line)?;
        let in_bytes = parse_u64_field(fields[4], line)?;
        let out_packets = parse_u64_field(fields[5], line)?;
        let out_bytes = parse_u64_field(fields[6], line)?;

        output.push_str(&format!(
            "{:<16} {:>10} {:>12} {:>11} {:>12}\n",
            fields[2], in_packets, in_bytes, out_packets, out_bytes
        ));
    }

    Ok(output)
}

fn run_start_command(command: &TincCommand) -> Result<String, TincError> {
    if tincd_is_running(&command.options) {
        return Ok(String::new());
    }

    let invocation = build_tincd_invocation(command);
    start_tincd_invocation(&invocation)
}

#[cfg(unix)]
fn start_tincd_invocation(invocation: &TincdInvocation) -> Result<String, TincError> {
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;

    let (mut parent, child) =
        UnixStream::pair().map_err(|error| TincError::StartFailed(error.to_string()))?;
    let child_fd = child.as_raw_fd();
    let mut process = Command::new(&invocation.executable);
    process
        .args(&invocation.arguments)
        .env("TINC_UMBILICAL", format!("{child_fd} 0"));

    unsafe {
        process.pre_exec(move || {
            clear_close_on_exec(child_fd)?;
            Ok(())
        });
    }

    let mut child_process = process
        .spawn()
        .map_err(|error| TincError::StartFailed(error.to_string()))?;
    drop(child);

    let mut output = Vec::new();
    let mut buffer = [0u8; 1024];

    loop {
        let read = parent
            .read(&mut buffer)
            .map_err(|error| TincError::StartFailed(error.to_string()))?;

        if read == 0 {
            let status = child_process
                .wait()
                .map_err(|error| TincError::StartFailed(error.to_string()))?;
            let stderr = String::from_utf8_lossy(&output).trim().to_owned();
            let detail = if stderr.is_empty() {
                format!("{} exited with {status}", invocation.executable.display())
            } else {
                stderr
            };
            return Err(TincError::StartFailed(detail));
        }

        if let Some(position) = buffer[..read].iter().position(|byte| *byte == 0) {
            output.extend_from_slice(&buffer[..position]);
            let status = child_process
                .wait()
                .map_err(|error| TincError::StartFailed(error.to_string()))?;
            if status.success() {
                return Ok(String::from_utf8_lossy(&output).into_owned());
            }
            let stderr = String::from_utf8_lossy(&output).trim().to_owned();
            let detail = if stderr.is_empty() {
                format!("{} exited with {status}", invocation.executable.display())
            } else {
                stderr
            };
            return Err(TincError::StartFailed(detail));
        }

        output.extend_from_slice(&buffer[..read]);
    }

    fn clear_close_on_exec(fd: RawFd) -> io::Result<()> {
        let flags = libc_fcntl_getfd(fd)?;
        libc_fcntl_setfd(fd, flags & !libc::FD_CLOEXEC)
    }

    fn libc_fcntl_getfd(fd: RawFd) -> io::Result<i32> {
        let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    fn libc_fcntl_setfd(fd: RawFd, flags: i32) -> io::Result<()> {
        let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(unix))]
fn start_tincd_invocation(invocation: &TincdInvocation) -> Result<String, TincError> {
    let output = Command::new(&invocation.executable)
        .args(&invocation.arguments)
        .output()
        .map_err(|error| TincError::StartFailed(error.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let detail = if stderr.is_empty() {
            format!(
                "{} exited with {}",
                invocation.executable.display(),
                output.status
            )
        } else {
            stderr
        };
        return Err(TincError::StartFailed(detail));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_restart_command(command: &TincCommand) -> Result<String, TincError> {
    let stop = TincCommand {
        options: command.options.clone(),
        name: "stop".to_owned(),
        arguments: Vec::new(),
    };
    let _ = run_simple_control_command(&stop);
    run_start_command(command)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TincdInvocation {
    executable: PathBuf,
    arguments: Vec<String>,
}

fn build_tincd_invocation(command: &TincCommand) -> TincdInvocation {
    let executable = tincd_executable_for_program(&command.options.program_name);
    let mut arguments = Vec::new();

    if let Some(confbase) = &command.options.confbase {
        arguments.push("--config".to_owned());
        arguments.push(confbase.to_string_lossy().into_owned());
    }

    if let Some(netname) = &command.options.netname {
        arguments.push("--net".to_owned());
        arguments.push(netname.clone());
    }

    if let Some(pidfile) = &command.options.pidfile {
        arguments.push("--pidfile".to_owned());
        arguments.push(pidfile.to_string_lossy().into_owned());
    }

    arguments.extend(command.arguments.iter().cloned());

    TincdInvocation {
        executable,
        arguments,
    }
}

fn tincd_executable_for_program(program_name: &str) -> PathBuf {
    let program = Path::new(program_name);

    match program.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join("tincd"),
        _ => PathBuf::from("tincd"),
    }
}

fn tincd_is_running(options: &TincOptions) -> bool {
    let path = resolve_pidfile(options);
    let Ok(pidfile) = read_pidfile(&path) else {
        return false;
    };
    let socket = control_socket_path(&path);
    control_socket_handshake_succeeds(&socket, &pidfile)
}

fn run_simple_control_command(command: &TincCommand) -> Result<String, TincError> {
    let request = build_simple_control_request(command)?;
    let path = resolve_pidfile(&command.options);
    let pidfile = read_pidfile(&path)?;
    let socket = control_socket_path(&path);

    if request.request == REQ_STOP {
        send_control_stop_request(&socket, &pidfile, &request)?;
        return Ok(String::new());
    }

    let response = send_control_request(&socket, &pidfile, &request)?;

    if request.request == REQ_SET_DEBUG {
        if response.request != REQ_SET_DEBUG {
            return Err(TincError::ControlResponse(format!(
                "unexpected response {} {}",
                response.request, response.result
            )));
        }

        let level = command
            .arguments
            .first()
            .and_then(|argument| parse_c_i32_prefix(argument))
            .unwrap_or_default();
        return Ok(format!(
            "Old level {}, new level {}.\n",
            response.result, level
        ));
    }

    if response.request != request.request || response.result != 0 {
        return Err(TincError::ControlResponse(format!(
            "unexpected response {} {}",
            response.request, response.result
        )));
    }

    Ok(String::new())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DumpControlRequest {
    lines: Vec<ControlRequestLine>,
    mode: DumpMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DumpMode {
    Nodes { only_reachable: bool },
    Edges,
    Subnets,
    Connections,
    Graph { directed: bool },
    Invitations,
}

fn build_dump_control_request(command: &TincCommand) -> Result<DumpControlRequest, TincError> {
    let mut args = command.arguments.as_slice();
    let mut only_reachable = false;

    if args
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case("reachable"))
    {
        if args.len() < 2 || !args[1].eq_ignore_ascii_case("nodes") {
            return Err(TincError::InvalidArguments(
                "`reachable' only supported for nodes".to_owned(),
            ));
        }

        only_reachable = true;
        args = &args[1..];
    }

    if args.len() != 1 {
        return Err(TincError::InvalidArguments(
            "invalid number of arguments".to_owned(),
        ));
    }

    let control = Request::Control.number();
    let (requests, mode) = match args[0].to_ascii_lowercase().as_str() {
        "nodes" => (
            vec![ControlRequestLine {
                request: REQ_DUMP_NODES,
                line: format!("{control} {REQ_DUMP_NODES}\n"),
            }],
            DumpMode::Nodes { only_reachable },
        ),
        "edges" => (
            vec![ControlRequestLine {
                request: REQ_DUMP_EDGES,
                line: format!("{control} {REQ_DUMP_EDGES}\n"),
            }],
            DumpMode::Edges,
        ),
        "subnets" => (
            vec![ControlRequestLine {
                request: REQ_DUMP_SUBNETS,
                line: format!("{control} {REQ_DUMP_SUBNETS}\n"),
            }],
            DumpMode::Subnets,
        ),
        "connections" => (
            vec![ControlRequestLine {
                request: REQ_DUMP_CONNECTIONS,
                line: format!("{control} {REQ_DUMP_CONNECTIONS}\n"),
            }],
            DumpMode::Connections,
        ),
        "graph" | "digraph" if !only_reachable => (
            vec![
                ControlRequestLine {
                    request: REQ_DUMP_NODES,
                    line: format!("{control} {REQ_DUMP_NODES}\n"),
                },
                ControlRequestLine {
                    request: REQ_DUMP_EDGES,
                    line: format!("{control} {REQ_DUMP_EDGES}\n"),
                },
            ],
            DumpMode::Graph {
                directed: args[0].eq_ignore_ascii_case("digraph"),
            },
        ),
        "invitations" if !only_reachable => (Vec::new(), DumpMode::Invitations),
        _ => return Err(TincError::UnknownDumpType(args[0].clone())),
    };

    Ok(DumpControlRequest {
        lines: requests,
        mode,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlRequestLine {
    request: i32,
    line: String,
}

fn dump_invitations(confbase: &Path) -> Result<String, TincError> {
    let invitations_dir = confbase.join("invitations");
    let entries = match fs::read_dir(&invitations_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(io_error(&invitations_dir, error)),
    };

    let mut invitations = Vec::new();

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };

        if b64decode_tinc(filename).map_or(true, |decoded| decoded.len() != 18) {
            continue;
        }

        let Ok(contents) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Some(first_line) = contents.lines().next() else {
            continue;
        };
        let first_line = first_line.trim_end_matches(['\t', ' ', '\r', '\n']);
        let Some(name) = first_line.strip_prefix("Name = ") else {
            continue;
        };

        if check_id(name) {
            invitations.push((filename.to_owned(), name.to_owned()));
        }
    }

    invitations.sort();

    let mut output = String::new();
    for (filename, name) in invitations {
        output.push_str(&format!("{filename} {name}\n"));
    }

    Ok(output)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DumpNode {
    name: String,
    id: String,
    host: String,
    port: String,
    cipher: i32,
    digest: i32,
    maclength: i32,
    compression: i32,
    options: u32,
    status: u32,
    nexthop: String,
    via: String,
    distance: i32,
    pmtu: i32,
    minmtu: i32,
    maxmtu: i32,
    last_state_change: i64,
    udp_ping_rtt: i32,
    in_packets: u64,
    in_bytes: u64,
    out_packets: u64,
    out_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DumpEdge {
    from: String,
    to: String,
    host: String,
    port: String,
    local_host: String,
    local_port: String,
    options: String,
    weight: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DumpSubnet {
    subnet: Subnet,
    text: String,
    owner: String,
}

fn parse_dump_node_line(line: &str, fields: &[&str]) -> Result<DumpNode, TincError> {
    if fields.len() != 25 || fields[5] != "port" {
        return Err(TincError::DumpParse(line.to_owned()));
    }

    Ok(DumpNode {
        name: fields[2].to_owned(),
        id: fields[3].to_owned(),
        host: fields[4].to_owned(),
        port: fields[6].to_owned(),
        cipher: parse_i32_field(fields[7], line)?,
        digest: parse_i32_field(fields[8], line)?,
        maclength: parse_i32_field(fields[9], line)?,
        compression: parse_i32_field(fields[10], line)?,
        options: parse_hex_u32_field(fields[11], line)?,
        status: parse_hex_u32_field(fields[12], line)?,
        nexthop: fields[13].to_owned(),
        via: fields[14].to_owned(),
        distance: parse_i32_field(fields[15], line)?,
        pmtu: parse_i32_field(fields[16], line)?,
        minmtu: parse_i32_field(fields[17], line)?,
        maxmtu: parse_i32_field(fields[18], line)?,
        last_state_change: fields[19]
            .parse()
            .map_err(|_| TincError::DumpParse(line.to_owned()))?,
        udp_ping_rtt: parse_i32_field(fields[20], line)?,
        in_packets: parse_u64_field(fields[21], line)?,
        in_bytes: parse_u64_field(fields[22], line)?,
        out_packets: parse_u64_field(fields[23], line)?,
        out_bytes: parse_u64_field(fields[24], line)?,
    })
}

fn parse_dump_edge_line(line: &str, fields: &[&str]) -> Result<DumpEdge, TincError> {
    if fields.len() != 12 || fields[5] != "port" || fields[8] != "port" {
        return Err(TincError::DumpParse(line.to_owned()));
    }

    Ok(DumpEdge {
        from: fields[2].to_owned(),
        to: fields[3].to_owned(),
        host: fields[4].to_owned(),
        port: fields[6].to_owned(),
        local_host: fields[7].to_owned(),
        local_port: fields[9].to_owned(),
        options: fields[10].to_owned(),
        weight: parse_i32_field(fields[11], line)?,
    })
}

fn parse_dump_subnet_line(line: &str, fields: &[&str]) -> Result<DumpSubnet, TincError> {
    if fields.len() != 4 {
        return Err(TincError::DumpParse(line.to_owned()));
    }

    let subnet = fields[2]
        .parse::<Subnet>()
        .map_err(|_| TincError::DumpParse(line.to_owned()))?;

    Ok(DumpSubnet {
        subnet,
        text: strip_default_weight(fields[2]).to_owned(),
        owner: fields[3].to_owned(),
    })
}

fn build_simple_control_request(command: &TincCommand) -> Result<ControlRequestLine, TincError> {
    let control = Request::Control.number();

    match command.name.to_ascii_lowercase().as_str() {
        "stop" => {
            if !command.arguments.is_empty() {
                return Err(TincError::TooManyArguments);
            }

            Ok(ControlRequestLine {
                request: REQ_STOP,
                line: format!("{control} {REQ_STOP}\n"),
            })
        }
        "reload" => {
            if !command.arguments.is_empty() {
                return Err(TincError::TooManyArguments);
            }

            Ok(ControlRequestLine {
                request: REQ_RELOAD,
                line: format!("{control} {REQ_RELOAD}\n"),
            })
        }
        "purge" => {
            if !command.arguments.is_empty() {
                return Err(TincError::TooManyArguments);
            }

            Ok(ControlRequestLine {
                request: REQ_PURGE,
                line: format!("{control} {REQ_PURGE}\n"),
            })
        }
        "retry" => {
            if !command.arguments.is_empty() {
                return Err(TincError::TooManyArguments);
            }

            Ok(ControlRequestLine {
                request: REQ_RETRY,
                line: format!("{control} {REQ_RETRY}\n"),
            })
        }
        "debug" => {
            if command.arguments.len() != 1 {
                return Err(TincError::InvalidArguments(
                    "invalid number of arguments".to_owned(),
                ));
            }

            let level = parse_c_i32_prefix(&command.arguments[0]).unwrap_or_default();
            Ok(ControlRequestLine {
                request: REQ_SET_DEBUG,
                line: format!("{control} {REQ_SET_DEBUG} {level}\n"),
            })
        }
        "connect" | "disconnect" => {
            if command.arguments.len() != 1 {
                return Err(TincError::InvalidArguments(
                    "invalid number of arguments".to_owned(),
                ));
            }

            let node = &command.arguments[0];

            if !check_id(node) {
                return Err(TincError::InvalidNodeName(node.clone()));
            }

            let request = if command.name.eq_ignore_ascii_case("connect") {
                REQ_CONNECT
            } else {
                REQ_DISCONNECT
            };

            Ok(ControlRequestLine {
                request,
                line: format!("{control} {request} {node}\n"),
            })
        }
        _ => Err(TincError::UnknownCommand(command.name.clone())),
    }
}

fn format_dump_response(
    request: &DumpControlRequest,
    lines: &[String],
) -> Result<String, TincError> {
    let mut output = String::new();

    if let DumpMode::Graph { directed } = request.mode {
        output.push_str(if directed { "digraph {\n" } else { "graph {\n" });
    }

    for line in lines {
        let fields = line.split_whitespace().collect::<Vec<_>>();

        if fields.len() < 2 || fields[0].parse::<i32>().ok() != Some(Request::Control.number()) {
            return Err(TincError::DumpParse(line.clone()));
        }

        let req = fields[1]
            .parse::<i32>()
            .map_err(|_| TincError::DumpParse(line.clone()))?;

        if fields.len() == 2 {
            if matches!(request.mode, DumpMode::Graph { .. }) && req == REQ_DUMP_NODES {
                continue;
            }

            if matches!(request.mode, DumpMode::Graph { .. }) {
                output.push_str("}\n");
            }

            return Ok(output);
        }

        match req {
            REQ_DUMP_NODES => format_dump_node(&mut output, line, &fields, request.mode)?,
            REQ_DUMP_EDGES => format_dump_edge(&mut output, line, &fields, request.mode)?,
            REQ_DUMP_SUBNETS => format_dump_subnet(&mut output, line, &fields, request.mode)?,
            REQ_DUMP_CONNECTIONS => {
                format_dump_connection(&mut output, line, &fields, request.mode)?
            }
            _ => return Err(TincError::DumpParse(line.clone())),
        }
    }

    Err(TincError::ControlConnection(
        "unexpected end of dump response".to_owned(),
    ))
}

fn format_info_node(item: &str, lines: &[String]) -> Result<String, TincError> {
    let mut found_node = None;
    let mut edges = Vec::new();
    let mut subnets = Vec::new();

    for line in lines {
        let fields = control_fields(line)?;

        if fields.len() == 2 {
            continue;
        }

        let req = control_request_type(line, &fields)?;

        match req {
            REQ_DUMP_NODES => {
                let node = parse_dump_node_line(line, &fields)?;
                if node.name == item {
                    found_node = Some(node);
                }
            }
            REQ_DUMP_EDGES => {
                let edge = parse_dump_edge_line(line, &fields)?;
                if edge.from == item {
                    edges.push(edge.to);
                }
            }
            REQ_DUMP_SUBNETS => {
                let subnet = parse_dump_subnet_line(line, &fields)?;
                if subnet.owner == item {
                    subnets.push(subnet.text);
                }
            }
            _ => return Err(TincError::DumpParse(line.clone())),
        }
    }

    let Some(node) = found_node else {
        return Err(TincError::UnknownNode(item.to_owned()));
    };

    let mut output = String::new();
    output.push_str(&format!("Node:         {item}\n"));
    output.push_str(&format!("Node ID:      {}\n", node.id));
    output.push_str(&format!("Address:      {} port {}\n", node.host, node.port));

    let seen = format_local_time(node.last_state_change);
    if node_status_reachable(node.status) {
        output.push_str(&format!("Online since: {seen}\n"));
    } else {
        output.push_str(&format!("Last seen:    {seen}\n"));
    }

    output.push_str("Status:      ");
    append_status_words(&mut output, node.status);
    output.push('\n');

    output.push_str("Options:     ");
    append_option_words(&mut output, node.options);
    output.push('\n');

    output.push_str(&format!(
        "Protocol:     {PROT_MAJOR}.{}\n",
        option_version(node.options)
    ));
    output.push_str("Reachability: ");
    append_reachability(&mut output, item, &node);

    output.push_str(&format!(
        "RX:           {} packets  {} bytes\n",
        node.in_packets, node.in_bytes
    ));
    output.push_str(&format!(
        "TX:           {} packets  {} bytes\n",
        node.out_packets, node.out_bytes
    ));

    output.push_str("Edges:       ");
    for edge in edges {
        output.push_str(&format!(" {edge}"));
    }
    output.push('\n');

    output.push_str("Subnets:     ");
    for subnet in subnets {
        output.push_str(&format!(" {subnet}"));
    }
    output.push('\n');

    Ok(output)
}

fn format_info_subnet_or_address(item: &str, lines: &[String]) -> Result<String, TincError> {
    let query = item.parse::<Subnet>().map_err(|_| {
        TincError::InvalidArguments(format!("could not parse subnet or address {item}"))
    })?;
    let address = !item.contains('/');
    let weight = item.contains('#');
    let mut output = String::new();

    for line in lines {
        let fields = control_fields(line)?;

        if fields.len() == 2 {
            continue;
        }

        if control_request_type(line, &fields)? != REQ_DUMP_SUBNETS {
            return Err(TincError::DumpParse(line.clone()));
        }

        let candidate = parse_dump_subnet_line(line, &fields)?;

        if subnet_query_matches(&query, &candidate.subnet, address, weight) {
            output.push_str(&format!(
                "Subnet: {}\nOwner:  {}\n",
                candidate.text, candidate.owner
            ));
        }
    }

    if output.is_empty() {
        if address {
            Err(TincError::UnknownAddress(item.to_owned()))
        } else {
            Err(TincError::UnknownSubnet(item.to_owned()))
        }
    } else {
        Ok(output)
    }
}

fn control_fields(line: &str) -> Result<Vec<&str>, TincError> {
    let fields = line.split_whitespace().collect::<Vec<_>>();

    if fields.len() < 2 || fields[0].parse::<i32>().ok() != Some(Request::Control.number()) {
        return Err(TincError::DumpParse(line.to_owned()));
    }

    Ok(fields)
}

fn control_request_type(line: &str, fields: &[&str]) -> Result<i32, TincError> {
    fields[1]
        .parse()
        .map_err(|_| TincError::DumpParse(line.to_owned()))
}

fn append_status_words(output: &mut String, status: u32) {
    if node_status_valid_key(status) {
        output.push_str(" validkey");
    }
    if node_status_visited(status) {
        output.push_str(" visited");
    }
    if node_status_reachable(status) {
        output.push_str(" reachable");
    }
    if node_status_indirect(status) {
        output.push_str(" indirect");
    }
    if node_status_sptps(status) {
        output.push_str(" sptps");
    }
    if node_status_udp_confirmed(status) {
        output.push_str(" udp_confirmed");
    }
}

fn append_option_words(output: &mut String, options: u32) {
    if options & OPTION_INDIRECT != 0 {
        output.push_str(" indirect");
    }
    if options & OPTION_TCPONLY != 0 {
        output.push_str(" tcponly");
    }
    if options & OPTION_PMTU_DISCOVERY != 0 {
        output.push_str(" pmtu_discovery");
    }
    if options & OPTION_CLAMP_MSS != 0 {
        output.push_str(" clamp_mss");
    }
}

fn append_reachability(output: &mut String, item: &str, node: &DumpNode) {
    if node.host == "MYSELF" {
        output.push_str("can reach itself\n");
    } else if !node_status_reachable(node.status) {
        output.push_str("unreachable\n");
    } else if node.via != item {
        output.push_str(&format!("indirectly via {}\n", node.via));
    } else if !node_status_valid_key(node.status) {
        output.push_str("unknown\n");
    } else if node.minmtu > 0 {
        output.push_str(&format!("directly with UDP\nPMTU:         {}\n", node.pmtu));

        if node.udp_ping_rtt != -1 {
            output.push_str(&format!(
                "RTT:          {}.{:03}\n",
                node.udp_ping_rtt / 1000,
                node.udp_ping_rtt % 1000
            ));
        }
    } else if node.nexthop == item {
        output.push_str("directly with TCP\n");
    } else {
        output.push_str(&format!("none, forwarded via {}\n", node.nexthop));
    }
}

fn subnet_query_matches(query: &Subnet, candidate: &Subnet, address: bool, weight: bool) -> bool {
    if weight && query.weight != candidate.weight {
        return false;
    }

    match (&query.kind, &candidate.kind) {
        (SubnetKind::Mac(query), SubnetKind::Mac(candidate)) => query == candidate,
        (
            SubnetKind::Ipv4 {
                address: query,
                prefix_len: query_prefix,
            },
            SubnetKind::Ipv4 {
                address: candidate,
                prefix_len: candidate_prefix,
            },
        ) => {
            if address {
                candidate_ipv4_matches(*query, *candidate, *candidate_prefix)
            } else {
                query_prefix == candidate_prefix && query == candidate
            }
        }
        (
            SubnetKind::Ipv6 {
                address: query,
                prefix_len: query_prefix,
            },
            SubnetKind::Ipv6 {
                address: candidate,
                prefix_len: candidate_prefix,
            },
        ) => {
            if address {
                candidate_ipv6_matches(*query, *candidate, *candidate_prefix)
            } else {
                query_prefix == candidate_prefix && query == candidate
            }
        }
        _ => false,
    }
}

fn candidate_ipv4_matches(query: Ipv4Addr, candidate: Ipv4Addr, prefix_len: u8) -> bool {
    Subnet::ipv4(candidate, prefix_len).is_ok_and(|subnet| subnet.matches_ipv4(query))
}

fn candidate_ipv6_matches(query: Ipv6Addr, candidate: Ipv6Addr, prefix_len: u8) -> bool {
    Subnet::ipv6(candidate, prefix_len).is_ok_and(|subnet| subnet.matches_ipv6(query))
}

fn format_dump_node(
    output: &mut String,
    line: &str,
    fields: &[&str],
    mode: DumpMode,
) -> Result<(), TincError> {
    let node = parse_dump_node_line(line, fields)?;

    match mode {
        DumpMode::Nodes { only_reachable } => {
            if only_reachable && !node_status_reachable(node.status) {
                return Ok(());
            }

            output.push_str(&format!(
                "{} id {} at {} port {} cipher {} digest {} maclength {} compression {} \
                 options {:x} status {:04x} nexthop {} via {} distance {} pmtu {} \
                 (min {} max {}) rx {} {} tx {} {}",
                node.name,
                node.id,
                node.host,
                node.port,
                node.cipher,
                node.digest,
                node.maclength,
                node.compression,
                node.options,
                node.status,
                node.nexthop,
                node.via,
                node.distance,
                node.pmtu,
                node.minmtu,
                node.maxmtu,
                node.in_packets,
                node.in_bytes,
                node.out_packets,
                node.out_bytes
            ));

            if node.udp_ping_rtt != -1 {
                output.push_str(&format!(
                    " rtt {}.{:03}",
                    node.udp_ping_rtt / 1000,
                    node.udp_ping_rtt % 1000
                ));
            }

            output.push('\n');
            Ok(())
        }
        DumpMode::Graph { .. } => {
            let color = if node.host == "MYSELF" {
                "green"
            } else if !node_status_reachable(node.status) {
                "red"
            } else if node.via != node.name {
                "orange"
            } else if !node_status_valid_key(node.status) {
                "black"
            } else if node.minmtu > 0 {
                "green"
            } else {
                "black"
            };
            let style = if node.host == "MYSELF" {
                ", style = \"filled\""
            } else {
                ""
            };
            output.push_str(&format!(
                " \"{}\" [label = \"{}\", color = \"{color}\"{style}];\n",
                node.name, node.name
            ));
            Ok(())
        }
        _ => Err(TincError::DumpParse(line.to_owned())),
    }
}

fn format_dump_edge(
    output: &mut String,
    line: &str,
    fields: &[&str],
    mode: DumpMode,
) -> Result<(), TincError> {
    let edge = parse_dump_edge_line(line, fields)?;

    match mode {
        DumpMode::Edges => {
            output.push_str(&format!(
                "{} to {} at {} port {} local {} port {} options {} weight {}\n",
                edge.from,
                edge.to,
                edge.host,
                edge.port,
                edge.local_host,
                edge.local_port,
                edge.options,
                edge.weight
            ));
            Ok(())
        }
        DumpMode::Graph { directed } => {
            let w = 1.0f32 + 65536.0f32 / edge.weight as f32;

            if directed {
                output.push_str(&format!(
                    " \"{}\" -> \"{}\" [w = {w:.6}, weight = {w:.6}];\n",
                    edge.from, edge.to
                ));
            } else if edge.from > edge.to {
                output.push_str(&format!(
                    " \"{}\" -- \"{}\" [w = {w:.6}, weight = {w:.6}];\n",
                    edge.from, edge.to
                ));
            }

            Ok(())
        }
        _ => Err(TincError::DumpParse(line.to_owned())),
    }
}

fn format_dump_subnet(
    output: &mut String,
    line: &str,
    fields: &[&str],
    mode: DumpMode,
) -> Result<(), TincError> {
    if fields.len() != 4 || !matches!(mode, DumpMode::Subnets) {
        return Err(TincError::DumpParse(line.to_owned()));
    }
    let subnet = parse_dump_subnet_line(line, fields)?;

    output.push_str(&format!("{} owner {}\n", subnet.text, subnet.owner));
    Ok(())
}

fn format_dump_connection(
    output: &mut String,
    line: &str,
    fields: &[&str],
    mode: DumpMode,
) -> Result<(), TincError> {
    if fields.len() != 9 || fields[4] != "port" || !matches!(mode, DumpMode::Connections) {
        return Err(TincError::DumpParse(line.to_owned()));
    }

    output.push_str(&format!(
        "{} at {} port {} options {} socket {} status {}\n",
        fields[2], fields[3], fields[5], fields[6], fields[7], fields[8]
    ));
    Ok(())
}

fn parse_i32_field(value: &str, line: &str) -> Result<i32, TincError> {
    value
        .parse()
        .map_err(|_| TincError::DumpParse(line.to_owned()))
}

fn parse_u64_field(value: &str, line: &str) -> Result<u64, TincError> {
    value
        .parse()
        .map_err(|_| TincError::DumpParse(line.to_owned()))
}

fn parse_hex_u32_field(value: &str, line: &str) -> Result<u32, TincError> {
    u32::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|_| TincError::DumpParse(line.to_owned()))
}

fn node_status_valid_key(status: u32) -> bool {
    status & (1 << 1) != 0
}

fn node_status_visited(status: u32) -> bool {
    status & (1 << 3) != 0
}

fn node_status_reachable(status: u32) -> bool {
    status & (1 << 4) != 0
}

fn node_status_indirect(status: u32) -> bool {
    status & (1 << 5) != 0
}

fn node_status_sptps(status: u32) -> bool {
    status & (1 << 6) != 0
}

fn node_status_udp_confirmed(status: u32) -> bool {
    status & (1 << 7) != 0
}

fn strip_default_weight(subnet: &str) -> &str {
    subnet.strip_suffix("#10").unwrap_or(subnet)
}

fn format_local_time(timestamp: i64) -> String {
    if timestamp == 0 {
        return "never".to_owned();
    }

    #[cfg(unix)]
    {
        let time = timestamp as libc::time_t;
        // SAFETY: `tm` is initialized by localtime_r before use, and strftime writes
        // into a fixed-size stack buffer with the provided length.
        unsafe {
            let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
            if libc::localtime_r(&time, tm.as_mut_ptr()).is_null() {
                return timestamp.to_string();
            }

            let tm = tm.assume_init();
            let mut buffer = [0 as libc::c_char; 32];
            let format = b"%Y-%m-%d %H:%M:%S\0";
            let written = libc::strftime(
                buffer.as_mut_ptr(),
                buffer.len(),
                format.as_ptr().cast(),
                &tm,
            );

            if written == 0 {
                return timestamp.to_string();
            }

            std::ffi::CStr::from_ptr(buffer.as_ptr())
                .to_string_lossy()
                .into_owned()
        }
    }

    #[cfg(not(unix))]
    {
        timestamp.to_string()
    }
}

fn pcap_global_header(snaplen: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(24);
    output.extend_from_slice(&0xa1b2c3d4u32.to_ne_bytes());
    output.extend_from_slice(&2u16.to_ne_bytes());
    output.extend_from_slice(&4u16.to_ne_bytes());
    output.extend_from_slice(&0u32.to_ne_bytes());
    output.extend_from_slice(&0u32.to_ne_bytes());
    output.extend_from_slice(&snaplen.to_ne_bytes());
    output.extend_from_slice(&1u32.to_ne_bytes());
    output
}

fn pcap_packet_header(len: u32) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut output = Vec::with_capacity(16);
    output.extend_from_slice(&(now.as_secs() as u32).to_ne_bytes());
    output.extend_from_slice(&now.subsec_micros().to_ne_bytes());
    output.extend_from_slice(&len.to_ne_bytes());
    output.extend_from_slice(&len.to_ne_bytes());
    output
}

fn parse_c_i32_prefix(input: &str) -> Option<i32> {
    let trimmed = input.trim_start();
    let mut end = 0;

    for (index, ch) in trimmed.char_indices() {
        if index == 0 && matches!(ch, '-' | '+') {
            end = ch.len_utf8();
            continue;
        }

        if ch.is_ascii_digit() {
            end = index + ch.len_utf8();
        } else {
            break;
        }
    }

    if end == 0 || matches!(trimmed[..end].as_bytes(), [b'+' | b'-']) {
        return None;
    }

    trimmed[..end].parse().ok()
}

fn parse_c_u32_prefix(input: &str) -> Option<u32> {
    parse_c_i32_prefix(input).map(|value| value as u32)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlResponseLine {
    request: i32,
    result: i32,
}

fn control_socket_path(pidfile: &Path) -> PathBuf {
    let path = pidfile.to_string_lossy();

    if let Some(prefix) = path.strip_suffix(".pid") {
        PathBuf::from(format!("{prefix}.socket"))
    } else {
        PathBuf::from(format!("{path}.socket"))
    }
}

struct ControlSocket {
    stream: Box<dyn ReadWrite>,
    reader: BufReader<Box<dyn ReadWrite>>,
}

trait ReadWrite: Read + Write + Send {}

impl<T> ReadWrite for T where T: Read + Write + Send {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ControlTarget {
    #[cfg(unix)]
    Unix(PathBuf),
    #[cfg_attr(unix, allow(dead_code))]
    Tcp { host: String, port: String },
}

fn control_target(socket: &Path, pidfile: &PidFile) -> ControlTarget {
    #[cfg(unix)]
    {
        let _ = pidfile;
        ControlTarget::Unix(socket.to_path_buf())
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        ControlTarget::Tcp {
            host: pidfile.host.clone(),
            port: pidfile.port.clone(),
        }
    }
}

fn open_control_socket(socket: &Path, pidfile: &PidFile) -> Result<ControlSocket, TincError> {
    open_control_target(control_target(socket, pidfile), pidfile)
}

fn open_control_target(
    target: ControlTarget,
    pidfile: &PidFile,
) -> Result<ControlSocket, TincError> {
    let (mut stream, reader_stream) = open_control_streams(target)?;
    let mut reader = BufReader::new(reader_stream);
    let id = Request::Id.number();
    let ack = Request::Ack.number();

    write!(
        stream,
        "{id} ^{} {TINC_CTL_VERSION_CURRENT}\n",
        pidfile.cookie
    )
    .map_err(|error| TincError::ControlConnection(error.to_string()))?;
    stream
        .flush()
        .map_err(|error| TincError::ControlConnection(error.to_string()))?;

    let greeting = read_control_line(&mut reader)?;
    let greeting_fields = greeting.split_whitespace().collect::<Vec<_>>();

    if greeting_fields.len() != 3
        || greeting_fields[0].parse::<i32>().ok() != Some(id)
        || !is_control_protocol_version(greeting_fields[2])
    {
        return Err(TincError::ControlHandshake(greeting));
    }

    let ack_line = read_control_line(&mut reader)?;
    let ack_fields = ack_line.split_whitespace().collect::<Vec<_>>();

    if ack_fields.len() != 3
        || ack_fields[0].parse::<i32>().ok() != Some(ack)
        || ack_fields[1].parse::<i32>().ok() != Some(TINC_CTL_VERSION_CURRENT)
    {
        return Err(TincError::ControlHandshake(ack_line));
    }

    Ok(ControlSocket { stream, reader })
}

fn open_control_streams(
    target: ControlTarget,
) -> Result<(Box<dyn ReadWrite>, Box<dyn ReadWrite>), TincError> {
    match target {
        #[cfg(unix)]
        ControlTarget::Unix(socket) => open_unix_control_streams(&socket),
        ControlTarget::Tcp { host, port } => open_tcp_control_streams(&host, &port),
    }
}

#[cfg(unix)]
fn open_unix_control_streams(
    socket: &Path,
) -> Result<(Box<dyn ReadWrite>, Box<dyn ReadWrite>), TincError> {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket)
        .map_err(|error| TincError::ControlConnection(error.to_string()))?;
    let reader = stream
        .try_clone()
        .map_err(|error| TincError::ControlConnection(error.to_string()))?;
    Ok((Box::new(stream), Box::new(reader)))
}

fn open_tcp_control_streams(
    host: &str,
    port: &str,
) -> Result<(Box<dyn ReadWrite>, Box<dyn ReadWrite>), TincError> {
    let mut last_error = None;

    for socket_addr in resolve_tcp_control_addresses(host, port)? {
        match TcpStream::connect(socket_addr) {
            Ok(stream) => {
                let reader = stream
                    .try_clone()
                    .map_err(|error| TincError::ControlConnection(error.to_string()))?;
                return Ok((Box::new(stream), Box::new(reader)));
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(TincError::ControlConnection(
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| format!("could not resolve {host} port {port}")),
    ))
}

#[cfg(unix)]
fn resolve_tcp_control_addresses(host: &str, port: &str) -> Result<Vec<SocketAddr>, TincError> {
    let host = CString::new(host)
        .map_err(|_| TincError::ControlConnection("control host contains NUL".to_owned()))?;
    let port = CString::new(port)
        .map_err(|_| TincError::ControlConnection("control port contains NUL".to_owned()))?;
    let hints = libc::addrinfo {
        ai_flags: 0,
        ai_family: libc::AF_UNSPEC,
        ai_socktype: libc::SOCK_STREAM,
        ai_protocol: libc::IPPROTO_TCP,
        ai_addrlen: 0,
        ai_addr: std::ptr::null_mut(),
        ai_canonname: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };
    let mut result = std::ptr::null_mut();
    let error = unsafe { libc::getaddrinfo(host.as_ptr(), port.as_ptr(), &hints, &mut result) };

    if error != 0 || result.is_null() {
        return Err(TincError::ControlConnection(format!(
            "Cannot resolve {} port {}: {}",
            host.to_string_lossy(),
            port.to_string_lossy(),
            gai_error(error)
        )));
    }

    let mut addresses = Vec::new();
    let mut current = result;
    while !current.is_null() {
        if let Some(address) = unsafe { socket_addr_from_addrinfo(&*current) } {
            addresses.push(address);
        }
        current = unsafe { (*current).ai_next };
    }

    unsafe {
        libc::freeaddrinfo(result);
    }

    if addresses.is_empty() {
        return Err(TincError::ControlConnection(format!(
            "Cannot resolve {} port {}",
            host.to_string_lossy(),
            port.to_string_lossy()
        )));
    }

    Ok(addresses)
}

#[cfg(not(unix))]
fn resolve_tcp_control_addresses(host: &str, port: &str) -> Result<Vec<SocketAddr>, TincError> {
    if host.contains('\0') {
        return Err(TincError::ControlConnection(
            "control host contains NUL".to_owned(),
        ));
    }
    if port.contains('\0') {
        return Err(TincError::ControlConnection(
            "control port contains NUL".to_owned(),
        ));
    }

    let addresses = if let Ok(port) = port.parse::<u16>() {
        (host, port)
            .to_socket_addrs()
            .map_err(|error| {
                TincError::ControlConnection(format!("Cannot resolve {host} port {port}: {error}"))
            })?
            .collect::<Vec<_>>()
    } else {
        return Err(TincError::ControlConnection(format!(
            "Cannot resolve {host} port {port}: unsupported service name"
        )));
    };

    if addresses.is_empty() {
        return Err(TincError::ControlConnection(format!(
            "Cannot resolve {host} port {port}"
        )));
    }

    Ok(addresses)
}

#[cfg(unix)]
unsafe fn socket_addr_from_addrinfo(info: &libc::addrinfo) -> Option<SocketAddr> {
    if info.ai_addr.is_null() {
        return None;
    }

    match info.ai_family {
        libc::AF_INET => {
            let address = unsafe { *(info.ai_addr.cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
            let port = u16::from_be(address.sin_port);
            Some(SocketAddr::new(ip.into(), port))
        }
        libc::AF_INET6 => {
            let address = unsafe { *(info.ai_addr.cast::<libc::sockaddr_in6>()) };
            let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
            let port = u16::from_be(address.sin6_port);
            Some(SocketAddr::new(ip.into(), port))
        }
        _ => None,
    }
}

#[cfg(unix)]
fn gai_error(error: i32) -> String {
    if error == 0 {
        return "no addresses".to_owned();
    }

    unsafe {
        CStr::from_ptr(libc::gai_strerror(error))
            .to_string_lossy()
            .into_owned()
    }
}

fn is_control_protocol_version(value: &str) -> bool {
    value.parse::<i32>().is_ok()
        || value.split_once('.').is_some_and(|(major, minor)| {
            major.parse::<i32>().is_ok() && minor.parse::<i32>().is_ok()
        })
}

fn send_control_request(
    socket: &Path,
    pidfile: &PidFile,
    request: &ControlRequestLine,
) -> Result<ControlResponseLine, TincError> {
    let mut socket = open_control_socket(socket, pidfile)?;
    send_control_line(&mut socket, request)?;
    read_control_response(&mut socket)
}

fn send_control_stop_request(
    socket: &Path,
    pidfile: &PidFile,
    request: &ControlRequestLine,
) -> Result<(), TincError> {
    let mut socket = open_control_socket(socket, pidfile)?;
    send_control_line(&mut socket, request)?;

    loop {
        match read_control_line(&mut socket.reader) {
            Ok(line) => {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() == 3
                    && fields[0].parse::<i32>().ok() == Some(Request::Control.number())
                    && fields[1].parse::<i32>().ok() == Some(REQ_STOP)
                    && fields[2].parse::<i32>().ok() == Some(0)
                {
                    continue;
                }

                return Err(TincError::ControlResponse(line));
            }
            Err(TincError::ControlConnection(_)) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn control_socket_handshake_succeeds(socket: &Path, pidfile: &PidFile) -> bool {
    open_control_socket(socket, pidfile).is_ok()
}

fn verify_control_socket(socket: &Path, pidfile: &PidFile) -> Result<(), TincError> {
    open_control_socket(socket, pidfile).map(|_| ())
}

fn send_control_dump_requests(
    socket: &Path,
    pidfile: &PidFile,
    requests: &[ControlRequestLine],
) -> Result<Vec<String>, TincError> {
    let mut socket = open_control_socket(socket, pidfile)?;

    for request in requests {
        send_control_line(&mut socket, request)?;
    }

    let mut lines = Vec::new();
    let mut completed = 0;

    while completed < requests.len() {
        let line = read_control_line(&mut socket.reader)?;
        let fields = line.split_whitespace().collect::<Vec<_>>();

        if fields.len() < 2 || fields[0].parse::<i32>().ok() != Some(Request::Control.number()) {
            return Err(TincError::ControlResponse(line));
        }

        if fields.len() == 2 {
            completed += 1;
        }

        lines.push(line);
    }

    Ok(lines)
}

fn send_control_log_request(
    socket: &Path,
    pidfile: &PidFile,
    request: &ControlRequestLine,
) -> Result<String, TincError> {
    let mut socket = open_control_socket(socket, pidfile)?;
    send_control_line(&mut socket, request)?;

    let mut output = Vec::new();

    loop {
        let line = match read_control_line(&mut socket.reader) {
            Ok(line) => line,
            Err(TincError::ControlConnection(_)) => break,
            Err(error) => return Err(error),
        };
        let fields = line.split_whitespace().collect::<Vec<_>>();

        if fields.len() != 3
            || fields[0].parse::<i32>().ok() != Some(Request::Control.number())
            || fields[1].parse::<i32>().ok() != Some(REQ_LOG)
        {
            break;
        }

        let len = fields[2]
            .parse::<isize>()
            .map_err(|_| TincError::ControlResponse(line.clone()))?;

        if len < 0 || len as usize > LOG_CONTROL_BUFFER_SIZE {
            break;
        }

        let mut data = vec![0u8; len as usize];
        socket
            .reader
            .read_exact(&mut data)
            .map_err(|error| TincError::ControlConnection(error.to_string()))?;
        output.extend_from_slice(&data);
        output.push(b'\n');
    }

    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn send_control_pcap_request(
    socket: &Path,
    pidfile: &PidFile,
    request: &ControlRequestLine,
    snaplen: u32,
) -> Result<Vec<u8>, TincError> {
    let mut socket = open_control_socket(socket, pidfile)?;
    send_control_line(&mut socket, request)?;

    let mut output = pcap_global_header(if snaplen == 0 {
        PCAP_CONTROL_BUFFER_SIZE as u32
    } else {
        snaplen
    });

    loop {
        let line = match read_control_line(&mut socket.reader) {
            Ok(line) => line,
            Err(TincError::ControlConnection(_)) => break,
            Err(error) => return Err(error),
        };
        let fields = line.split_whitespace().collect::<Vec<_>>();

        if fields.len() != 3
            || fields[0].parse::<i32>().ok() != Some(Request::Control.number())
            || fields[1].parse::<i32>().ok() != Some(REQ_PCAP)
        {
            break;
        }

        let len = fields[2]
            .parse::<usize>()
            .map_err(|_| TincError::ControlResponse(line.clone()))?;

        if len > PCAP_CONTROL_BUFFER_SIZE {
            break;
        }

        let mut data = vec![0u8; len];
        socket
            .reader
            .read_exact(&mut data)
            .map_err(|error| TincError::ControlConnection(error.to_string()))?;
        output.extend_from_slice(&pcap_packet_header(len as u32));
        output.extend_from_slice(&data);
    }

    Ok(output)
}

fn send_control_line(
    socket: &mut ControlSocket,
    request: &ControlRequestLine,
) -> Result<(), TincError> {
    socket
        .stream
        .write_all(request.line.as_bytes())
        .map_err(|error| TincError::ControlConnection(error.to_string()))?;
    socket
        .stream
        .flush()
        .map_err(|error| TincError::ControlConnection(error.to_string()))
}

fn read_control_response(socket: &mut ControlSocket) -> Result<ControlResponseLine, TincError> {
    let response = read_control_line(&mut socket.reader)?;
    let fields = response.split_whitespace().collect::<Vec<_>>();

    if fields.len() != 3 || fields[0].parse::<i32>().ok() != Some(Request::Control.number()) {
        return Err(TincError::ControlResponse(response));
    }

    let request = fields[1]
        .parse::<i32>()
        .map_err(|_| TincError::ControlResponse(response.clone()))?;
    let result = fields[2]
        .parse::<i32>()
        .map_err(|_| TincError::ControlResponse(response.clone()))?;

    Ok(ControlResponseLine { request, result })
}

fn read_control_line(reader: &mut impl BufRead) -> Result<String, TincError> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|error| TincError::ControlConnection(error.to_string()))?;

    if read == 0 {
        return Err(TincError::ControlConnection(
            "unexpected end of control socket".to_owned(),
        ));
    }

    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn resolve_pidfile(options: &TincOptions) -> PathBuf {
    options
        .pidfile
        .clone()
        .unwrap_or_else(|| resolve_confbase(options).join("pid"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PidFile {
    pid: i32,
    cookie: String,
    host: String,
    port: String,
}

fn read_pidfile(path: &Path) -> Result<PidFile, TincError> {
    parse_pidfile(path, &read_config_text(path)?)
}

fn parse_pidfile(path: &Path, contents: &str) -> Result<PidFile, TincError> {
    let mut fields = contents.split_whitespace();
    let Some(pid) = fields.next().and_then(|value| value.parse::<i32>().ok()) else {
        return Err(TincError::InvalidPidFile(path.to_path_buf()));
    };
    let Some(cookie) = fields.next() else {
        return Err(TincError::InvalidPidFile(path.to_path_buf()));
    };
    let Some(host) = fields.next() else {
        return Err(TincError::InvalidPidFile(path.to_path_buf()));
    };
    let Some(port_marker) = fields.next() else {
        return Err(TincError::InvalidPidFile(path.to_path_buf()));
    };
    let Some(port) = fields.next() else {
        return Err(TincError::InvalidPidFile(path.to_path_buf()));
    };

    if !port_marker.eq_ignore_ascii_case("port")
        || cookie.len() > 64
        || host.len() > 128
        || port.len() > 128
    {
        return Err(TincError::InvalidPidFile(path.to_path_buf()));
    }

    Ok(PidFile {
        pid,
        cookie: cookie.to_owned(),
        host: host.to_owned(),
        port: port.to_owned(),
    })
}

fn generate_ed25519_keypair() -> Result<TincEd25519PrivateKey, TincError> {
    let mut seed = [0u8; ED25519_SEED_LEN];
    getrandom::getrandom(&mut seed).map_err(|error| TincError::Random(error.to_string()))?;
    Ok(TincEd25519PrivateKey::from_seed(seed))
}

fn parse_rsa_key_bits(value: Option<&str>) -> Result<usize, TincError> {
    let bits = match value {
        Some(value) => value.parse::<usize>().unwrap_or(0),
        None => DEFAULT_RSA_BITS,
    } & !0x7;

    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
        return Err(TincError::InvalidArguments(format!(
            "invalid key size {bits} specified; it should be between {MIN_RSA_BITS} and {MAX_RSA_BITS} bits"
        )));
    }

    Ok(bits)
}

fn generate_rsa_keypair(bits: usize) -> Result<RsaPrivateKey, TincError> {
    RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|error| TincError::Random(format!("RSA key generation failed: {error}")))
}

fn write_rsa_keypair(
    confbase: &Path,
    name: Option<&str>,
    key: &RsaPrivateKey,
) -> Result<(), TincError> {
    let private_path = confbase.join("rsa_key.priv");
    let private_pem = key.to_pkcs1_pem(LineEnding::LF).map_err(|error| {
        TincError::InvalidArguments(format!("could not encode RSA key: {error}"))
    })?;
    append_config_text(&private_path, private_pem.as_str(), FilePrivacy::Private)?;

    let public_key = RsaPublicKey::from(key);
    let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).map_err(|error| {
        TincError::InvalidArguments(format!("could not encode RSA public key: {error}"))
    })?;
    let public_path = match name {
        Some(name) => {
            if !check_id(name) {
                return Err(TincError::InvalidNodeName(name.to_owned()));
            }

            confbase.join("hosts").join(name)
        }
        None => confbase.join("rsa_key.pub"),
    };

    append_config_text(&public_path, &public_pem, FilePrivacy::Public)
}

fn write_ed25519_keypair(
    confbase: &Path,
    name: Option<&str>,
    key: &TincEd25519PrivateKey,
) -> Result<(), TincError> {
    let private_path = confbase.join("ed25519_key.priv");
    append_config_text(&private_path, &key.to_pem(), FilePrivacy::Private)?;

    let public_line = format!("Ed25519PublicKey = {}\n", key.public_key().to_base64());
    let public_path = match name {
        Some(name) => {
            if !check_id(name) {
                return Err(TincError::InvalidNodeName(name.to_owned()));
            }

            confbase.join("hosts").join(name)
        }
        None => confbase.join("ed25519_key.pub"),
    };

    append_config_text(&public_path, &public_line, FilePrivacy::Public)
}

fn create_default_tinc_up(confbase: &Path) -> Result<(), TincError> {
    #[cfg(unix)]
    {
        let path = confbase.join("tinc-up");

        if path.exists() {
            return Ok(());
        }

        let script = "#!/bin/sh\n\n\
echo 'Unconfigured tinc-up script, please edit '$0'!'\n\n\
#ifconfig $INTERFACE <your vpn IP address> netmask <netmask of whole VPN>\n";
        fs::write(&path, script).map_err(|error| io_error(&path, error))?;

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|error| io_error(&path, error))?;
    }

    Ok(())
}

fn parse_config_edit(command: &str, args: &[String]) -> Result<ConfigEdit, TincError> {
    let mut action = config_action_from_command(command).unwrap_or(ConfigAction::Get);
    let mut start = 0;

    if command.eq_ignore_ascii_case("config") {
        let Some(first) = args.first() else {
            return Err(TincError::InvalidArguments(
                "invalid number of arguments".to_owned(),
            ));
        };

        if let Some(parsed) = config_action_from_command(first) {
            action = parsed;
            start = 1;
        }
    }

    if args.len() <= start {
        return Err(TincError::InvalidArguments(
            "invalid number of arguments".to_owned(),
        ));
    }

    let line = args[start..].join(" ");
    let (selector, value) = parse_config_selector_and_value(&line)?;
    let (node, variable) = match selector.split_once('.') {
        Some((node, variable)) => (Some(node.to_owned()), variable.to_owned()),
        None => (None, selector),
    };

    if variable.is_empty() {
        return Err(TincError::InvalidArguments("no variable given".to_owned()));
    }

    let value = if value.is_empty() { None } else { Some(value) };

    if matches!(action, ConfigAction::Set | ConfigAction::Add) && value.is_none() {
        return Err(TincError::MissingValue(variable));
    }

    if action == ConfigAction::Get && value.is_some() {
        action = ConfigAction::Set;
    }

    Ok(ConfigEdit {
        action,
        node,
        variable,
        value,
    })
}

fn config_action_from_command(command: &str) -> Option<ConfigAction> {
    match command.to_ascii_lowercase().as_str() {
        "get" => Some(ConfigAction::Get),
        "del" => Some(ConfigAction::Delete),
        "set" | "replace" | "change" => Some(ConfigAction::Set),
        "add" => Some(ConfigAction::Add),
        _ => None,
    }
}

fn parse_config_selector_and_value(line: &str) -> Result<(String, String), TincError> {
    let trimmed = line.trim_start_matches(['\t', ' ']);
    let selector_end = trimmed.find(['\t', ' ', '=']).unwrap_or(trimmed.len());
    let selector = trimmed[..selector_end].to_owned();
    let mut rest = &trimmed[selector_end..];

    rest = rest.trim_start_matches(['\t', ' ']);

    if let Some(stripped) = rest.strip_prefix('=') {
        rest = stripped.trim_start_matches(['\t', ' ']);
    }

    if selector.is_empty() {
        return Err(TincError::InvalidArguments("no variable given".to_owned()));
    }

    Ok((selector, rest.to_owned()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedConfigEdit {
    path: PathBuf,
    action: ConfigAction,
    variable: String,
    value: Option<String>,
}

fn prepare_config_edit(
    mut edit: ConfigEdit,
    confbase: &Path,
    force: bool,
) -> Result<PreparedConfigEdit, TincError> {
    let variable = lookup_variable(&edit.variable);

    if let Some(spec) = variable {
        edit.variable = spec.name.to_owned();

        if spec.name.eq_ignore_ascii_case("Subnet") {
            if let Some(value) = &edit.value {
                validate_subnet(value)?;
            }
        }

        if matches!(edit.action, ConfigAction::Set | ConfigAction::Add)
            && spec.is_obsolete()
            && !force
        {
            return Err(TincError::ObsoleteVariable(edit.variable));
        }

        if edit.node.is_some()
            && matches!(edit.action, ConfigAction::Set | ConfigAction::Add)
            && !spec.is_host()
            && !force
        {
            return Err(TincError::ServerVariableInHostFile(edit.variable));
        }

        if edit.node.is_none() && !spec.is_server() {
            edit.node = Some(read_local_name(confbase)?);
        }

        if edit.action == ConfigAction::Add && !spec.is_multiple() {
            edit.action = ConfigAction::Set;
        }
    } else if !force && matches!(edit.action, ConfigAction::Set | ConfigAction::Add) {
        return Err(TincError::UnknownVariable(edit.variable));
    }

    if let Some(node) = &edit.node {
        if !check_id(node) {
            return Err(TincError::InvalidNodeName(node.clone()));
        }
    }

    let path = match &edit.node {
        Some(node) => confbase.join("hosts").join(node),
        None => confbase.join("tinc.conf"),
    };

    Ok(PreparedConfigEdit {
        path,
        action: edit.action,
        variable: edit.variable,
        value: edit.value,
    })
}

fn lookup_variable(variable: &str) -> Option<VariableSpec> {
    VARIABLES
        .iter()
        .copied()
        .find(|candidate| candidate.name.eq_ignore_ascii_case(variable))
}

fn validate_subnet(value: &str) -> Result<(), TincError> {
    let subnet = value
        .parse::<Subnet>()
        .map_err(|_| TincError::MalformedSubnet(value.to_owned()))?;

    if !subnet.has_canonical_mask() {
        return Err(TincError::NonCanonicalSubnet(value.to_owned()));
    }

    Ok(())
}

fn read_local_name(confbase: &Path) -> Result<String, TincError> {
    let path = confbase.join("tinc.conf");
    let contents = read_config_text(&path)?;

    for line in contents.lines() {
        let (variable, value) = parse_config_file_line(line);

        if variable.eq_ignore_ascii_case("Name") && !value.is_empty() {
            return Ok(value.to_owned());
        }
    }

    Err(TincError::MissingLocalName)
}

fn read_private_ed25519_key(confbase: &Path) -> Result<TincEd25519PrivateKey, TincError> {
    let path = confbase.join("ed25519_key.priv");
    let contents = read_config_text(&path)?;

    TincEd25519PrivateKey::from_pem(&contents).map_err(|error| {
        TincError::InvalidArguments(format!(
            "could not read private key from {}: {error}",
            path.display()
        ))
    })
}

fn read_host_ed25519_public_key(
    confbase: &Path,
    name: &str,
) -> Result<TincEd25519PublicKey, TincError> {
    if !check_id(name) {
        return Err(TincError::InvalidNodeName(name.to_owned()));
    }

    let path = confbase.join("hosts").join(name);
    let contents = read_config_text(&path)?;

    for line in contents.lines() {
        let (variable, value) = parse_config_file_line(line);

        if variable.eq_ignore_ascii_case("Ed25519PublicKey") && !value.is_empty() {
            return TincEd25519PublicKey::from_base64(value).map_err(|error| {
                TincError::InvalidArguments(format!(
                    "could not read public key from {}: {error}",
                    path.display()
                ))
            });
        }
    }

    Err(TincError::InvalidArguments(format!(
        "could not read public key from {}",
        path.display()
    )))
}

fn parse_verify_node(confbase: &Path, node: &str) -> Result<Option<String>, TincError> {
    if node == "*" {
        return Ok(None);
    }

    if node == "." {
        return Ok(Some(read_local_name(confbase)?));
    }

    if !check_id(node) {
        return Err(TincError::InvalidNodeName(node.to_owned()));
    }

    Ok(Some(node.to_owned()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSignature {
    signer: String,
    timestamp: u64,
    signature: [u8; ED25519_SIGNATURE_LEN],
}

fn split_signature_input(data: &[u8]) -> Result<(&[u8], &[u8]), TincError> {
    let newline = data
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| TincError::InvalidArguments("invalid input".to_owned()))?;

    Ok((&data[..newline], &data[newline + 1..]))
}

fn parse_signature_header(header: &[u8]) -> Result<FileSignature, TincError> {
    let header = std::str::from_utf8(header)
        .map_err(|_| TincError::InvalidArguments("invalid input".to_owned()))?;
    let mut fields = header.split_whitespace();

    if fields.next() != Some("Signature") || fields.next() != Some("=") {
        return Err(TincError::InvalidArguments("invalid input".to_owned()));
    }

    let Some(signer) = fields.next() else {
        return Err(TincError::InvalidArguments("invalid input".to_owned()));
    };
    let Some(timestamp) = fields.next() else {
        return Err(TincError::InvalidArguments("invalid input".to_owned()));
    };
    let Some(signature) = fields.next() else {
        return Err(TincError::InvalidArguments("invalid input".to_owned()));
    };

    if fields.next().is_some() || !check_id(signer) {
        return Err(TincError::InvalidArguments("invalid input".to_owned()));
    }

    let timestamp = timestamp
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| TincError::InvalidArguments("invalid input".to_owned()))?;
    let decoded = b64decode_tinc(signature)
        .map_err(|_| TincError::InvalidArguments("invalid input".to_owned()))?;

    if decoded.len() != ED25519_SIGNATURE_LEN {
        return Err(TincError::InvalidArguments("invalid input".to_owned()));
    }

    let signature = decoded
        .try_into()
        .expect("signature length checked before conversion");

    Ok(FileSignature {
        signer: signer.to_owned(),
        timestamp,
        signature,
    })
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn export_host(confbase: &Path, name: &str) -> Result<String, TincError> {
    if !check_id(name) {
        return Err(TincError::InvalidNodeName(name.to_owned()));
    }

    let path = confbase.join("hosts").join(name);
    let contents = read_config_text(&path)?;
    let mut output = format!("Name = {name}\n");

    for line in contents.split_inclusive('\n') {
        let raw = line.strip_suffix('\n').unwrap_or(line);
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let (variable, _) = parse_config_file_line(raw);

        if variable.eq_ignore_ascii_case("Name") {
            continue;
        }

        output.push_str(raw);

        if line.ends_with('\n') {
            output.push('\n');
        }
    }

    Ok(output)
}

fn import_hosts(confbase: &Path, input: &str, force: bool) -> Result<usize, TincError> {
    let hosts_dir = confbase.join("hosts");
    fs::create_dir_all(&hosts_dir).map_err(|error| io_error(&hosts_dir, error))?;

    let mut current: Option<ImportHost> = None;
    let mut count = 0;
    let mut firstline = true;

    for line in input.split_inclusive('\n') {
        if let Some(name) = parse_import_name(line) {
            firstline = false;

            if !check_id(name) {
                return Err(TincError::InvalidNodeName(name.to_owned()));
            }

            if let Some(host) = current.take() {
                write_import_host(&hosts_dir, host)?;
            }

            let path = hosts_dir.join(name);

            if path.exists() && !force {
                current = None;
                continue;
            }

            current = Some(ImportHost {
                name: name.to_owned(),
                contents: String::new(),
            });
            count += 1;
            continue;
        } else if firstline {
            firstline = false;
        }

        if line == "#---------------------------------------------------------------#\n" {
            continue;
        }

        if let Some(host) = &mut current {
            host.contents.push_str(line);
        }
    }

    if let Some(host) = current {
        write_import_host(&hosts_dir, host)?;
    }

    if count == 0 {
        return Err(TincError::NoHostConfigurationsImported);
    }

    Ok(count)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImportHost {
    name: String,
    contents: String,
}

fn parse_import_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("Name = ")?;
    rest.split_whitespace().next()
}

fn write_import_host(hosts_dir: &Path, host: ImportHost) -> Result<(), TincError> {
    let path = hosts_dir.join(host.name);
    fs::write(&path, host.contents).map_err(|error| io_error(&path, error))
}

fn edit_config_file(edit: PreparedConfigEdit) -> Result<String, TincError> {
    let contents = read_config_text(&edit.path)?;
    let mut output = String::new();

    if edit.action == ConfigAction::Get {
        for line in contents.lines() {
            let (variable, value) = parse_config_file_line(line);

            if variable.eq_ignore_ascii_case(&edit.variable) {
                output.push_str(value);
                output.push('\n');
            }
        }

        if output.is_empty() {
            return Err(TincError::NoMatchingConfigurationVariables);
        }

        return Ok(output);
    }

    let mut rewritten = String::new();
    let mut set = false;
    let mut found_duplicate = false;
    let mut removed = false;

    for line in contents.split_inclusive('\n') {
        let has_newline = line.ends_with('\n');
        let raw = line.strip_suffix('\n').unwrap_or(line);
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let (variable, existing_value) = parse_config_file_line(raw);

        if variable.eq_ignore_ascii_case(&edit.variable) {
            match edit.action {
                ConfigAction::Delete => {
                    if edit
                        .value
                        .as_deref()
                        .is_none_or(|value| existing_value.eq_ignore_ascii_case(value))
                    {
                        removed = true;
                        continue;
                    }
                }
                ConfigAction::Set => {
                    let value = edit
                        .value
                        .as_deref()
                        .ok_or_else(|| TincError::MissingValue(edit.variable.clone()))?;

                    if set {
                        continue;
                    }

                    rewritten.push_str(&format!("{} = {value}\n", edit.variable));
                    set = true;
                    continue;
                }
                ConfigAction::Add => {
                    let value = edit
                        .value
                        .as_deref()
                        .ok_or_else(|| TincError::MissingValue(edit.variable.clone()))?;

                    if existing_value.eq_ignore_ascii_case(value) {
                        found_duplicate = true;
                    }
                }
                ConfigAction::Get => unreachable!("get returned before rewriting"),
            }
        }

        rewritten.push_str(raw);

        if has_newline {
            rewritten.push('\n');
        } else if !raw.is_empty() {
            rewritten.push('\n');
        }
    }

    if matches!(edit.action, ConfigAction::Add) && !found_duplicate {
        let value = edit
            .value
            .as_deref()
            .ok_or_else(|| TincError::MissingValue(edit.variable.clone()))?;
        rewritten.push_str(&format!("{} = {value}\n", edit.variable));
    } else if edit.action == ConfigAction::Set && !set {
        let value = edit
            .value
            .as_deref()
            .ok_or_else(|| TincError::MissingValue(edit.variable.clone()))?;
        rewritten.push_str(&format!("{} = {value}\n", edit.variable));
    }

    if edit.action == ConfigAction::Delete && !removed {
        return Err(TincError::NoConfigurationVariablesDeleted);
    }

    write_config_text(&edit.path, &rewritten)?;
    Ok(output)
}

fn parse_config_file_line(line: &str) -> (&str, &str) {
    let trimmed = line.trim_start_matches(['\t', ' ']);
    let variable_end = trimmed.find(['\t', ' ', '=']).unwrap_or(trimmed.len());
    let variable = &trimmed[..variable_end];
    let mut value = &trimmed[variable_end..];

    value = value.trim_start_matches(['\t', ' ']);

    if let Some(stripped) = value.strip_prefix('=') {
        value = stripped.trim_start_matches(['\t', ' ']);
    }

    (variable, value.trim_end_matches(['\t', ' ', '\r']))
}

fn read_config_text(path: &Path) -> Result<String, TincError> {
    fs::read_to_string(path).map_err(|error| io_error(path, error))
}

fn write_config_text(path: &Path, contents: &str) -> Result<(), TincError> {
    let tmp = path.with_file_name(format!(
        "{}.config.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("tinc")
    ));

    fs::write(&tmp, contents).map_err(|error| io_error(&tmp, error))?;
    fs::rename(&tmp, path).map_err(|error| io_error(path, error))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FilePrivacy {
    Public,
    Private,
}

fn append_config_text(path: &Path, contents: &str, privacy: FilePrivacy) -> Result<(), TincError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
    }

    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        if privacy == FilePrivacy::Private {
            options.mode(0o600);
        }
    }

    let mut file = options.open(path).map_err(|error| io_error(path, error))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| io_error(path, error))?;

    #[cfg(unix)]
    if privacy == FilePrivacy::Private {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error(path, error))?;
    }

    Ok(())
}

fn write_private_text(path: &Path, contents: &str) -> Result<(), TincError> {
    write_private_text_with_options(path, contents, false)
}

fn write_private_text_create_new(path: &Path, contents: &str) -> Result<(), TincError> {
    write_private_text_with_options(path, contents, true)
}

fn write_private_text_with_options(
    path: &Path,
    contents: &str,
    create_new: bool,
) -> Result<(), TincError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true);

    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|error| io_error(path, error))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| io_error(path, error))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error(path, error))?;
    }

    Ok(())
}

fn io_error(path: &Path, error: io::Error) -> TincError {
    TincError::Io {
        path: path.to_path_buf(),
        error: error.to_string(),
    }
}

fn next_arg(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, TincError> {
    args.next().ok_or_else(|| TincError::MissingArgument {
        option: option.to_owned(),
    })
}

fn value_after_equals(argument: &str) -> String {
    argument
        .split_once('=')
        .map(|(_, value)| value)
        .unwrap_or_default()
        .to_owned()
}

fn usage(program_name: &str) -> String {
    format!(
        "Usage: {program_name} [options] command\n\
\n\
Valid options are:\n\
  -b, --batch             Don't ask for anything (non-interactive mode).\n\
  -c, --config=DIR        Read configuration options from DIR.\n\
  -n, --net=NETNAME       Connect to net NETNAME.\n\
      --pidfile=FILENAME  Read control cookie from FILENAME.\n\
      --force             Force some commands to work despite warnings.\n\
      --help              Display this help and exit.\n\
      --version           Output version information and exit.\n\
\n\
Valid commands are:\n\
  init [name]                Create initial configuration files.\n\
  get VARIABLE               Print current value of VARIABLE\n\
  set VARIABLE VALUE         Set VARIABLE to VALUE\n\
  add VARIABLE VALUE         Add VARIABLE with the given VALUE\n\
  del VARIABLE [VALUE]       Remove VARIABLE [only ones with watching VALUE]\n\
  start [tincd options]      Start tincd.\n\
  stop                       Stop tincd.\n\
  restart [tincd options]    Restart tincd.\n\
  reload                     Partially reload configuration of running tincd.\n\
  pid                        Show PID of currently running tincd.\n\
  generate-keys [bits]       Generate new RSA and Ed25519 public/private key pairs.\n\
  generate-rsa-keys [bits]   Generate a new RSA public/private key pair.\n\
  generate-ed25519-keys      Generate a new Ed25519 public/private key pair.\n\
  dump                       Dump a list of one of the following things:\n\
    [reachable] nodes        - all known nodes in the VPN\n\
    edges                    - all known connections in the VPN\n\
    subnets                  - all known subnets in the VPN\n\
    connections              - all meta connections with ourself\n\
    [di]graph                - graph of the VPN in dotty format\n\
    invitations              - outstanding invitations\n\
  info NODE|SUBNET|ADDRESS   Give information about a particular NODE, SUBNET or ADDRESS.\n\
  purge                      Purge unreachable nodes\n\
  debug N                    Set debug level\n\
  retry                      Retry all outgoing connections\n\
  disconnect NODE            Close meta connection with NODE\n\
  top                        Show real-time statistics\n\
  pcap [snaplen]             Dump traffic in pcap format [up to snaplen bytes per packet]\n\
  log [level]                Dump log output [up to the specified level]\n\
  export                     Export host configuration of local node to standard output\n\
  export-all                 Export all host configuration files to standard output\n\
  import                     Import host configuration file(s) from standard input\n\
  exchange                   Same as export followed by import\n\
  exchange-all               Same as export-all followed by import\n\
  invite NODE [...]          Generate an invitation for NODE\n\
  join INVITATION            Join a VPN using an INVITATION\n\
  network [NETNAME]          List all known networks, or switch to the one named NETNAME.\n\
  edit FILENAME              Start an editor for a configuration file.\n\
  fsck                       Check the configuration files for problems.\n\
  sign [FILE]                Generate a signed version of a file.\n\
  verify NODE [FILE]         Verify that a file was signed by the given NODE.\n\
\n\
Report bugs to tinc@tinc-vpn.org.\n"
    )
}

fn version() -> String {
    format!(
        "tinc version {} (protocol {PROT_MAJOR}.{PROT_MINOR})\n\
Features: rust\n\
\n\
Copyright (C) 1998-2018 Ivo Timmermans, Guus Sliepen and others.\n\
See the AUTHORS file for a complete list.\n\
\n\
tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n\
and you are welcome to redistribute it under certain conditions;\n\
see the file COPYING for details.\n",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
    use std::fs;
    use std::net::TcpListener;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn temp_confbase(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "tincctl-{test_name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("hosts")).unwrap();
        path
    }

    fn top_snapshot_line_has(
        output: &str,
        node: &str,
        in_packets: u64,
        in_bytes: u64,
        out_packets: u64,
        out_bytes: u64,
    ) -> bool {
        output.lines().any(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            fields.len() == 5
                && fields[0] == node
                && fields[1].parse::<u64>().ok() == Some(in_packets)
                && fields[2].parse::<u64>().ok() == Some(in_bytes)
                && fields[3].parse::<u64>().ok() == Some(out_packets)
                && fields[4].parse::<u64>().ok() == Some(out_bytes)
        })
    }

    #[cfg(unix)]
    fn spawn_fake_control_server(
        socket: &Path,
        cookie: &'static str,
        pid: i32,
    ) -> std::thread::JoinHandle<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let listener = UnixListener::bind(socket).unwrap_or_else(|error| {
            panic!(
                "failed to bind test Unix socket {}: {error}",
                socket.display()
            )
        });
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!(format!("0 ^{cookie} 0\n"), line);
            write!(stream, "0 tinc 17\n4 0 {pid}\n").unwrap();
        })
    }

    #[test]
    fn parses_tincctl_options_and_command_arguments() {
        tinc_test_support::assert_can_create_netns();
        let ParsedCommand::Command(command) = parse_args(args(&[
            "tinc",
            "--batch",
            "--config=/tmp/vpn",
            "-n",
            "prod",
            "--pidfile",
            "/tmp/tinc.pid",
            "--force",
            "dump",
            "reachable",
            "nodes",
        ]))
        .unwrap() else {
            panic!("expected command");
        };

        assert_eq!("dump", command.name);
        assert_eq!(vec!["reachable", "nodes"], command.arguments);
        assert!(command.options.batch);
        assert_eq!(Some(PathBuf::from("/tmp/vpn")), command.options.confbase);
        assert!(command.options.confbase_given);
        assert_eq!(Some("prod".to_owned()), command.options.netname);
        assert_eq!(
            Some(PathBuf::from("/tmp/tinc.pid")),
            command.options.pidfile
        );
        assert!(command.options.force);
    }

    #[test]
    fn parses_help_version_and_command_aliases() {
        tinc_test_support::assert_can_create_netns();
        assert!(matches!(
            parse_args(args(&["tinc", "--help"])),
            Ok(ParsedCommand::Help(_))
        ));
        assert_eq!(
            Ok(ParsedCommand::Version),
            parse_args(args(&["tinc", "--version"]))
        );

        let ParsedCommand::Command(command) =
            parse_args(args(&["tinc", "list", "nodes"])).expect("list is a dump alias")
        else {
            panic!("expected command");
        };

        assert_eq!("list", command.name);
        assert_eq!(vec!["nodes"], command.arguments);
    }

    #[test]
    fn start_builds_tincd_invocation_from_control_options_and_extra_args() {
        tinc_test_support::assert_can_create_netns();
        let ParsedCommand::Command(command) = parse_args(args(&[
            "/usr/local/bin/tinc",
            "--batch",
            "--config",
            "/tmp/vpn",
            "--net",
            "prod",
            "--pidfile",
            "/tmp/tinc.pid",
            "--force",
            "start",
            "-D",
            "--debug=5",
        ]))
        .unwrap() else {
            panic!("expected command");
        };

        let invocation = build_tincd_invocation(&command);
        assert_eq!(PathBuf::from("/usr/local/bin/tincd"), invocation.executable);
        assert_eq!(
            vec![
                "--config".to_owned(),
                "/tmp/vpn".to_owned(),
                "--net".to_owned(),
                "prod".to_owned(),
                "--pidfile".to_owned(),
                "/tmp/tinc.pid".to_owned(),
                "-D".to_owned(),
                "--debug=5".to_owned(),
            ],
            invocation.arguments
        );

        let command = TincCommand {
            options: TincOptions::new("tinc".to_owned()),
            name: "start".to_owned(),
            arguments: Vec::new(),
        };
        assert_eq!(
            PathBuf::from("tincd"),
            build_tincd_invocation(&command).executable
        );
    }

    #[cfg(unix)]
    #[test]
    fn start_waits_for_umbilical_success_byte() {
        tinc_test_support::assert_can_create_netns();
        let invocation = TincdInvocation {
            executable: PathBuf::from("/bin/sh"),
            arguments: vec![
                "-c".to_owned(),
                "fd=${TINC_UMBILICAL%% *}; printf '\\000' >&$fd".to_owned(),
            ],
        };

        assert_eq!(Ok(String::new()), start_tincd_invocation(&invocation));
    }

    #[cfg(unix)]
    #[test]
    fn start_checks_umbilical_child_exit_status_like_tincctl() {
        tinc_test_support::assert_can_create_netns();
        let invocation = TincdInvocation {
            executable: PathBuf::from("/bin/sh"),
            arguments: vec![
                "-c".to_owned(),
                "fd=${TINC_UMBILICAL%% *}; printf '\\000' >&$fd; exit 7".to_owned(),
            ],
        };

        let error = start_tincd_invocation(&invocation).unwrap_err();
        assert!(
            error.to_string().contains("exited with exit status: 7"),
            "unexpected start failure: {error}"
        );
    }

    #[test]
    fn rejects_invalid_options_netnames_and_unknown_commands() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(TincError::MissingArgument {
                option: "-c".to_owned()
            }),
            parse_args(args(&["tinc", "-c"]))
        );
        assert_eq!(
            Err(TincError::InvalidNetname("bad/name".to_owned())),
            parse_args(args(&["tinc", "-n", "bad/name", "pid"]))
        );
        assert_eq!(
            Err(TincError::UnknownOption("--bad".to_owned())),
            parse_args(args(&["tinc", "--bad"]))
        );
        let ParsedCommand::Shell(options) = parse_args(args(&["tinc"])).unwrap() else {
            panic!("expected shell when no command is given");
        };
        assert_eq!("tinc", options.program_name);
        assert_eq!(
            Err(TincError::UnknownCommand("unknown".to_owned())),
            parse_args(args(&["tinc", "unknown"]))
        );
    }

    #[test]
    fn resolves_default_and_netname_config_directories() {
        tinc_test_support::assert_can_create_netns();
        let mut options = TincOptions::new("tinc".to_owned());
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
    fn help_and_version_match_original_user_visible_surface() {
        tinc_test_support::assert_can_create_netns();
        let help = match run(args(&["tinc", "help"])).unwrap() {
            CliAction::Exit { output, .. } => output,
            _ => panic!("expected help exit"),
        };

        assert!(help.contains("Usage: tinc [options] command"));
        assert!(help.contains("Valid options are:"));
        assert!(help.contains("start [tincd options]"));
        assert!(help.contains("generate-keys [bits]"));
        assert!(help.contains("generate-ed25519-keys"));
        assert!(help.contains("generate-rsa-keys [bits]"));
        assert!(help.contains("verify NODE [FILE]"));

        let version = match run(args(&["tinc", "version"])).unwrap() {
            CliAction::Exit { output, .. } => output,
            _ => panic!("expected version exit"),
        };

        assert!(version.contains("tinc version"));
        assert!(version.contains("protocol 17.7"));
        assert!(version.contains("ABSOLUTELY NO WARRANTY"));
    }

    #[test]
    fn visible_command_list_keeps_hidden_config_out() {
        tinc_test_support::assert_can_create_netns();
        let commands = visible_commands().collect::<Vec<_>>();
        assert!(commands.contains(&"start"));
        assert!(commands.contains(&"generate-keys"));
        assert!(commands.contains(&"generate-rsa-keys"));
        assert!(commands.contains(&"verify"));
        assert!(!commands.contains(&"config"));
    }

    #[test]
    fn shell_runs_commands_until_quit_like_tincctl() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("shell-basic");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        let options = TincOptions {
            confbase: Some(confbase.clone()),
            confbase_given: true,
            ..TincOptions::new("tinc".to_owned())
        };

        let action = run_shell_bytes(
            options,
            b"#comment\n\nset Mode router\nget Mode\nquit\nget Mode\n",
            false,
        )
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "router\n".to_owned()
            },
            action
        );
        assert!(
            fs::read_to_string(confbase.join("tinc.conf"))
                .unwrap()
                .contains("Mode = router\n")
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn shell_accumulates_command_errors_and_continues_like_tincctl() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("shell-errors");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\nMode = switch\n").unwrap();
        let options = TincOptions {
            confbase: Some(confbase.clone()),
            confbase_given: true,
            ..TincOptions::new("tinc".to_owned())
        };

        let action = run_shell_bytes(options, b"unknown\nget Mode\nexit\n", false).unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 1,
                output: "Unknown command `unknown'.\nswitch\n".to_owned()
            },
            action
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn shell_history_file_preserves_existing_and_records_known_commands_like_readline() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("shell-history");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\nMode = switch\n").unwrap();
        let history = confbase.join("history");
        fs::write(&history, "get Name\n").unwrap();
        let options = TincOptions {
            confbase: Some(confbase.clone()),
            confbase_given: true,
            ..TincOptions::new("tinc".to_owned())
        };

        let action = run_shell_bytes_with_history(
            options,
            b"#comment\n\nget Mode\nunknown\nset Mode router\nquit\nget Name\n",
            true,
            &history,
        )
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 1,
                output: "switch\nUnknown command `unknown'.\n".to_owned(),
            },
            action
        );
        assert_eq!(
            "get Name\nget Mode\nset Mode router\n",
            fs::read_to_string(&history).unwrap()
        );
        assert!(
            fs::read_to_string(confbase.join("tinc.conf"))
                .unwrap()
                .contains("Mode = router\n")
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn config_get_set_add_and_delete_edit_server_config_like_tincctl() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("server-config");
        let tinc_conf = confbase.join("tinc.conf");
        fs::write(
            &tinc_conf,
            "Name = alpha\nMode = router\nConnectTo = beta\nConnectTo = gamma\n",
        )
        .unwrap();

        let output = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "get",
            "Mode",
        ]))
        .unwrap();
        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "router\n".to_owned()
            },
            output
        );

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "set",
            "Mode",
            "hub",
        ]))
        .unwrap();
        assert!(
            fs::read_to_string(&tinc_conf)
                .unwrap()
                .contains("Mode = hub\n")
        );

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "add",
            "ConnectTo",
            "beta",
        ]))
        .unwrap();
        assert_eq!(
            1,
            fs::read_to_string(&tinc_conf)
                .unwrap()
                .matches("ConnectTo = beta\n")
                .count()
        );

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "add",
            "ConnectTo",
            "delta",
        ]))
        .unwrap();
        assert!(
            fs::read_to_string(&tinc_conf)
                .unwrap()
                .contains("ConnectTo = delta\n")
        );

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "del",
            "ConnectTo",
            "beta",
        ]))
        .unwrap();
        let contents = fs::read_to_string(&tinc_conf).unwrap();
        assert!(!contents.contains("ConnectTo = beta\n"));
        assert!(contents.contains("ConnectTo = gamma\n"));

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "del",
            "ConnectTo",
        ]))
        .unwrap();
        assert!(
            !fs::read_to_string(&tinc_conf)
                .unwrap()
                .contains("ConnectTo = ")
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn config_command_routes_host_variables_to_local_or_named_host_file() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("host-config");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(
            confbase.join("hosts").join("alpha"),
            "Subnet = 10.0.0.0/8\n",
        )
        .unwrap();
        fs::write(confbase.join("hosts").join("beta"), "").unwrap();

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "add",
            "Subnet",
            "10.1.0.0/16",
        ]))
        .unwrap();
        assert!(
            fs::read_to_string(confbase.join("hosts").join("alpha"))
                .unwrap()
                .contains("Subnet = 10.1.0.0/16\n")
        );

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "set",
            "beta.Subnet",
            "10.2.0.0/16",
        ]))
        .unwrap();
        assert_eq!(
            "Subnet = 10.2.0.0/16\n",
            fs::read_to_string(confbase.join("hosts").join("beta")).unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn config_edit_rejects_invalid_values_and_protected_variables() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("validation");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(confbase.join("hosts").join("alpha"), "").unwrap();
        fs::write(confbase.join("hosts").join("beta"), "").unwrap();

        assert_eq!(
            Err(TincError::ServerVariableInHostFile("Mode".to_owned())),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "set",
                "beta.Mode",
                "router",
            ]))
        );
        assert_eq!(
            Err(TincError::UnknownVariable("MadeUp".to_owned())),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "set",
                "MadeUp",
                "value",
            ]))
        );
        assert_eq!(
            Err(TincError::NonCanonicalSubnet("10.0.1.1/24".to_owned())),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "add",
                "Subnet",
                "10.0.1.1/24",
            ]))
        );

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "--force",
            "set",
            "MadeUp",
            "value",
        ]))
        .unwrap();
        assert!(
            fs::read_to_string(confbase.join("tinc.conf"))
                .unwrap()
                .contains("MadeUp = value\n")
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn edit_resolves_configuration_filenames_like_tincctl() {
        tinc_test_support::assert_can_create_netns();
        let confbase = PathBuf::from("/tmp/tinc-edit");
        let invalid = Err(TincError::InvalidArguments(
            "Invalid configuration filename.".to_owned(),
        ));

        assert_eq!(
            confbase.join("tinc.conf"),
            resolve_edit_target_in_confbase(&confbase, "tinc.conf").unwrap()
        );
        assert_eq!(
            confbase.join("tinc-up"),
            resolve_edit_target_in_confbase(&confbase, "tinc-up").unwrap()
        );
        assert_eq!(
            confbase.join("hosts").join("alpha"),
            resolve_edit_target_in_confbase(&confbase, "alpha").unwrap()
        );
        assert_eq!(
            confbase.join("hosts").join("alpha"),
            resolve_edit_target_in_confbase(&confbase, "hosts/alpha").unwrap()
        );
        assert_eq!(
            confbase.join("hosts").join("alpha-up"),
            resolve_edit_target_in_confbase(&confbase, "alpha-up").unwrap()
        );
        assert_eq!(
            confbase.join("hosts").join("tinc-up"),
            resolve_edit_target_in_confbase(&confbase, "hosts/tinc-up").unwrap()
        );
        assert_eq!(
            invalid,
            resolve_edit_target_in_confbase(&confbase, "alpha-restart")
        );
        assert_eq!(
            Err(TincError::InvalidArguments(
                "Invalid configuration filename.".to_owned()
            )),
            resolve_edit_target_in_confbase(&confbase, "bad/name-up")
        );
    }

    #[test]
    fn export_outputs_local_host_config_with_name_header() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("export");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(
            confbase.join("hosts").join("alpha"),
            "Name = stale\nSubnet = 10.0.0.0/8\nEd25519PublicKey = abc\n",
        )
        .unwrap();

        let output = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "export",
        ]))
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "Name = alpha\nSubnet = 10.0.0.0/8\nEd25519PublicKey = abc\n".to_owned()
            },
            output
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn export_all_outputs_every_valid_host_with_separator() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("export-all");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(
            confbase.join("hosts").join("alpha"),
            "Subnet = 10.0.0.0/8\n",
        )
        .unwrap();
        fs::write(
            confbase.join("hosts").join("beta"),
            "Name = ignored\nSubnet = 10.2.0.0/16\n",
        )
        .unwrap();
        fs::write(
            confbase.join("hosts").join("bad-name"),
            "Subnet = 10.3.0.0/16\n",
        )
        .unwrap();

        let output = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "export-all",
        ]))
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "Name = alpha\nSubnet = 10.0.0.0/8\n\n#---------------------------------------------------------------#\nName = beta\nSubnet = 10.2.0.0/16\n".to_owned()
            },
            output
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn export_rejects_extra_arguments_and_missing_local_name() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("export-errors");
        fs::write(confbase.join("tinc.conf"), "").unwrap();
        fs::write(confbase.join("hosts").join("alpha"), "").unwrap();

        assert_eq!(
            Err(TincError::TooManyArguments),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "export",
                "extra",
            ]))
        );
        assert_eq!(
            Err(TincError::MissingLocalName),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "export",
            ]))
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn import_writes_host_configs_from_name_sections() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("import");
        let input = "junk ignored\nName = alpha\nSubnet = 10.0.0.0/8\n#---------------------------------------------------------------#\nName = beta\nSubnet = 10.2.0.0/16\n";

        let output = run_with_input(
            args(&["tinc", "--config", confbase.to_str().unwrap(), "import"]),
            input,
        )
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            output
        );
        assert_eq!(
            "Subnet = 10.0.0.0/8\n",
            fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap()
        );
        assert_eq!(
            "Subnet = 10.2.0.0/16\n",
            fs::read_to_string(confbase.join("hosts").join("beta")).unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn import_skips_existing_hosts_unless_forced() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("import-force");
        fs::write(
            confbase.join("hosts").join("alpha"),
            "Subnet = 10.0.0.0/8\n",
        )
        .unwrap();

        run_with_input(
            args(&["tinc", "--config", confbase.to_str().unwrap(), "import"]),
            "Name = alpha\nSubnet = 10.9.0.0/16\n",
        )
        .unwrap_err();
        assert_eq!(
            "Subnet = 10.0.0.0/8\n",
            fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap()
        );

        run_with_input(
            args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "--force",
                "import",
            ]),
            "Name = alpha\nSubnet = 10.9.0.0/16\n",
        )
        .unwrap();
        assert_eq!(
            "Subnet = 10.9.0.0/16\n",
            fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn import_rejects_invalid_names_and_empty_inputs() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("import-errors");

        assert_eq!(
            Err(TincError::InvalidNodeName("bad-name".to_owned())),
            run_with_input(
                args(&["tinc", "--config", confbase.to_str().unwrap(), "import"]),
                "Name = bad-name\nSubnet = 10.0.0.0/8\n",
            )
        );
        assert_eq!(
            Err(TincError::NoHostConfigurationsImported),
            run_with_input(
                args(&["tinc", "--config", confbase.to_str().unwrap(), "import"]),
                "# no name here\n",
            )
        );
        assert_eq!(
            Err(TincError::TooManyArguments),
            run_with_input(
                args(&[
                    "tinc",
                    "--config",
                    confbase.to_str().unwrap(),
                    "import",
                    "extra",
                ]),
                "Name = alpha\n",
            )
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn exchange_exports_local_host_and_imports_stdin() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("exchange");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(
            confbase.join("hosts").join("alpha"),
            "Subnet = 10.0.0.0/8\n",
        )
        .unwrap();

        let output = run_with_input(
            args(&["tinc", "--config", confbase.to_str().unwrap(), "exchange"]),
            "Name = beta\nSubnet = 10.2.0.0/16\n",
        )
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "Name = alpha\nSubnet = 10.0.0.0/8\n".to_owned()
            },
            output
        );
        assert_eq!(
            "Subnet = 10.2.0.0/16\n",
            fs::read_to_string(confbase.join("hosts").join("beta")).unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn exchange_all_exports_all_hosts_and_imports_stdin() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("exchange-all");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
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

        let output = run_with_input(
            args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "exchange-all",
            ]),
            "Name = gamma\nSubnet = 10.3.0.0/16\n",
        )
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "Name = alpha\nSubnet = 10.0.0.0/8\n\n#---------------------------------------------------------------#\nName = beta\nSubnet = 10.2.0.0/16\n".to_owned()
            },
            output
        );
        assert_eq!(
            "Subnet = 10.3.0.0/16\n",
            fs::read_to_string(confbase.join("hosts").join("gamma")).unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn command_requires_stdin_only_for_importing_commands() {
        tinc_test_support::assert_can_create_netns();
        assert!(command_requires_stdin(args(&["tinc", "import"])));
        assert!(command_requires_stdin(args(&["tinc", "exchange"])));
        assert!(command_requires_stdin(args(&["tinc", "exchange-all"])));
        assert!(command_requires_stdin(args(&["tinc", "sign"])));
        assert!(command_requires_stdin(args(&["tinc", "verify", "alpha"])));
        assert!(command_requires_stdin(args(&["tinc", "join"])));
        assert!(!command_requires_stdin(args(&["tinc", "export"])));
        assert!(!command_requires_stdin(args(&["tinc", "get", "Name"])));
        assert!(!command_requires_stdin(args(&[
            "tinc",
            "join",
            "host/token"
        ])));
        assert!(!command_requires_stdin(args(&[
            "tinc",
            "sign",
            "payload.txt"
        ])));
        assert!(!command_requires_stdin(args(&[
            "tinc",
            "verify",
            "alpha",
            "signed.txt"
        ])));
    }

    fn write_ed25519_test_config(confbase: &Path, name: &str, seed: u8) -> TincEd25519PrivateKey {
        let key = TincEd25519PrivateKey::from_seed([seed; ED25519_SEED_LEN]);
        fs::write(confbase.join("tinc.conf"), format!("Name = {name}\n")).unwrap();
        fs::write(confbase.join("ed25519_key.priv"), key.to_pem()).unwrap();
        fs::write(
            confbase.join("hosts").join(name),
            format!("Ed25519PublicKey = {}\n", key.public_key().to_base64()),
        )
        .unwrap();
        key
    }

    #[test]
    fn sign_and_verify_roundtrip_stdin_payload() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("sign-verify");
        write_ed25519_test_config(&confbase, "alpha", 7);
        let payload = b"\x00hello\nworld\x7f";

        let signed = run_with_input_bytes(
            args(&["tinc", "--config", confbase.to_str().unwrap(), "sign"]),
            payload,
        )
        .unwrap();
        let CliAction::ExitBytes {
            code,
            output: signed,
        } = signed
        else {
            panic!("sign should return byte output");
        };

        assert_eq!(0, code);
        let header_end = signed.iter().position(|byte| *byte == b'\n').unwrap();
        let header = std::str::from_utf8(&signed[..header_end]).unwrap();
        let fields = header.split_whitespace().collect::<Vec<_>>();
        assert_eq!(vec!["Signature", "=", "alpha"], fields[..3]);
        assert_eq!(86, fields[4].len());
        assert_eq!(payload, &signed[header_end + 1..]);

        assert_eq!(
            CliAction::ExitBytes {
                code: 0,
                output: payload.to_vec()
            },
            run_with_input_bytes(
                args(&[
                    "tinc",
                    "--config",
                    confbase.to_str().unwrap(),
                    "verify",
                    "."
                ]),
                &signed,
            )
            .unwrap()
        );
        assert_eq!(
            CliAction::ExitBytes {
                code: 0,
                output: payload.to_vec()
            },
            run_with_input_bytes(
                args(&[
                    "tinc",
                    "--config",
                    confbase.to_str().unwrap(),
                    "verify",
                    "*"
                ]),
                &signed,
            )
            .unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn sign_and_verify_accept_file_arguments() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("sign-verify-files");
        write_ed25519_test_config(&confbase, "alpha", 8);
        let payload_path = confbase.join("payload.bin");
        let signed_path = confbase.join("signed.bin");
        let payload = b"payload from file\n";
        fs::write(&payload_path, payload).unwrap();

        let signed = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "sign",
            payload_path.to_str().unwrap(),
        ]))
        .unwrap();
        let CliAction::ExitBytes {
            code,
            output: signed,
        } = signed
        else {
            panic!("sign should return byte output");
        };
        assert_eq!(0, code);
        fs::write(&signed_path, &signed).unwrap();

        assert_eq!(
            CliAction::ExitBytes {
                code: 0,
                output: payload.to_vec()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "verify",
                "alpha",
                signed_path.to_str().unwrap(),
            ]))
            .unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_signer_and_tampered_payloads() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("sign-verify-errors");
        write_ed25519_test_config(&confbase, "alpha", 9);
        let beta = TincEd25519PrivateKey::from_seed([10; ED25519_SEED_LEN]);
        fs::write(
            confbase.join("hosts").join("beta"),
            format!("Ed25519PublicKey = {}\n", beta.public_key().to_base64()),
        )
        .unwrap();
        let signed = run_with_input_bytes(
            args(&["tinc", "--config", confbase.to_str().unwrap(), "sign"]),
            b"payload",
        )
        .unwrap();
        let CliAction::ExitBytes { output, .. } = signed else {
            panic!("sign should return byte output");
        };

        assert_eq!(
            Err(TincError::InvalidArguments(
                "signature is not made by beta".to_owned()
            )),
            run_with_input_bytes(
                args(&[
                    "tinc",
                    "--config",
                    confbase.to_str().unwrap(),
                    "verify",
                    "beta"
                ]),
                &output,
            )
        );

        let mut tampered = output.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            Err(TincError::InvalidArguments("invalid signature".to_owned())),
            run_with_input_bytes(
                args(&[
                    "tinc",
                    "--config",
                    confbase.to_str().unwrap(),
                    "verify",
                    "*"
                ]),
                &tampered,
            )
        );

        assert_eq!(
            Err(TincError::InvalidArguments("invalid input".to_owned())),
            run_with_input_bytes(
                args(&[
                    "tinc",
                    "--config",
                    confbase.to_str().unwrap(),
                    "verify",
                    "*"
                ]),
                b"not signed",
            )
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn generate_ed25519_keys_writes_private_key_and_local_host_public_key() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("ed25519-local");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(
            confbase.join("hosts").join("alpha"),
            "Subnet = 10.0.0.0/8\n",
        )
        .unwrap();

        let output = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "generate-ed25519-keys",
        ]))
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            output
        );

        let private_pem = fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
        let private_key = TincEd25519PrivateKey::from_pem(&private_pem).unwrap();
        let public_config = fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap();
        let public_line = public_config
            .lines()
            .find_map(|line| line.strip_prefix("Ed25519PublicKey = "))
            .unwrap();

        assert_eq!(private_key.public_key().to_base64(), public_line);
        assert!(public_config.contains("Subnet = 10.0.0.0/8\n"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                0o600,
                fs::metadata(confbase.join("ed25519_key.priv"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
        }

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn generate_ed25519_keys_without_name_writes_public_key_file() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("ed25519-no-name");
        fs::write(confbase.join("tinc.conf"), "").unwrap();

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "generate-ed25519-keys",
        ]))
        .unwrap();

        let private_pem = fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
        let private_key = TincEd25519PrivateKey::from_pem(&private_pem).unwrap();
        let public_config = fs::read_to_string(confbase.join("ed25519_key.pub")).unwrap();

        assert_eq!(
            format!(
                "Ed25519PublicKey = {}\n",
                private_key.public_key().to_base64()
            ),
            public_config
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn generate_ed25519_keys_rejects_arguments() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(TincError::TooManyArguments),
            run(args(&["tinc", "generate-ed25519-keys", "extra"]))
        );
        assert_eq!(
            Err(TincError::TooManyArguments),
            run(args(&["tinc", "generate-keys", "2048", "extra"]))
        );
        assert_eq!(
            Err(TincError::TooManyArguments),
            run(args(&["tinc", "generate-rsa-keys", "2048", "extra"]))
        );
        assert!(matches!(
            run(args(&["tinc", "generate-rsa-keys", "1000"])),
            Err(TincError::InvalidArguments(message)) if message.contains("between 1024 and 8192")
        ));
        assert!(matches!(
            run(args(&["tinc", "generate-keys", "9000"])),
            Err(TincError::InvalidArguments(message)) if message.contains("between 1024 and 8192")
        ));
    }

    #[test]
    fn generate_rsa_keys_writes_pkcs1_private_key_and_local_host_public_key() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("rsa-local");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(
            confbase.join("hosts").join("alpha"),
            "Subnet = 10.0.0.0/8\n",
        )
        .unwrap();

        let output = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "generate-rsa-keys",
            "1024",
        ]))
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            output
        );

        let private_pem = fs::read_to_string(confbase.join("rsa_key.priv")).unwrap();
        let public_config = fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap();
        assert!(private_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
        assert!(private_pem.ends_with("-----END RSA PRIVATE KEY-----\n"));
        assert!(RsaPrivateKey::from_pkcs1_pem(&private_pem).is_ok());
        assert!(public_config.contains("Subnet = 10.0.0.0/8\n"));
        assert!(public_config.contains("-----BEGIN RSA PUBLIC KEY-----\n"));
        assert!(public_config.contains("-----END RSA PUBLIC KEY-----\n"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                0o600,
                fs::metadata(confbase.join("rsa_key.priv"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
        }

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn generate_rsa_keys_without_name_writes_public_key_file() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("rsa-no-name");
        fs::write(confbase.join("tinc.conf"), "").unwrap();

        run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "generate-rsa-keys",
            "1024",
        ]))
        .unwrap();

        let private_pem = fs::read_to_string(confbase.join("rsa_key.priv")).unwrap();
        let public_pem = fs::read_to_string(confbase.join("rsa_key.pub")).unwrap();
        let private = RsaPrivateKey::from_pkcs1_pem(&private_pem).unwrap();
        let public = RsaPublicKey::from_pkcs1_pem(&public_pem).unwrap();

        assert_eq!(RsaPublicKey::from(&private), public);

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn generate_keys_writes_rsa_and_ed25519_keypairs() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("generate-keys-both");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(confbase.join("hosts").join("alpha"), "").unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "generate-keys",
                "1024",
            ]))
            .unwrap()
        );

        let rsa_private_pem = fs::read_to_string(confbase.join("rsa_key.priv")).unwrap();
        let ed25519_private_pem = fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
        let ed25519_private = TincEd25519PrivateKey::from_pem(&ed25519_private_pem).unwrap();
        let public_config = fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap();

        assert!(RsaPrivateKey::from_pkcs1_pem(&rsa_private_pem).is_ok());
        assert!(public_config.contains("-----BEGIN RSA PUBLIC KEY-----\n"));
        assert!(public_config.contains(&format!(
            "Ed25519PublicKey = {}\n",
            ed25519_private.public_key().to_base64()
        )));

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn generate_keys_alias_writes_ed25519_keypair() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("generate-keys-alias");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(confbase.join("hosts").join("alpha"), "").unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "generate-keys",
                "1024",
            ]))
            .unwrap()
        );

        assert!(
            fs::read_to_string(confbase.join("rsa_key.priv"))
                .unwrap()
                .contains("BEGIN RSA PRIVATE KEY")
        );
        let private_pem = fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
        let private_key = TincEd25519PrivateKey::from_pem(&private_pem).unwrap();
        let public_config = fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap();

        assert!(public_config.contains(&format!(
            "Ed25519PublicKey = {}\n",
            private_key.public_key().to_base64()
        )));

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn init_creates_initial_configuration_and_rsa_ed25519_keys() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("init");
        fs::remove_file(confbase.join("tinc.conf")).ok();

        let output = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "init",
            "alpha",
        ]))
        .unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            output
        );
        assert_eq!(
            "Name = alpha\n",
            fs::read_to_string(confbase.join("tinc.conf")).unwrap()
        );
        assert!(confbase.join("conf.d").is_dir());
        assert!(confbase.join("cache").is_dir());

        let rsa_private_pem = fs::read_to_string(confbase.join("rsa_key.priv")).unwrap();
        let rsa_private = RsaPrivateKey::from_pkcs1_pem(&rsa_private_pem).unwrap();
        let ed25519_private_pem = fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap();
        let ed25519_private = TincEd25519PrivateKey::from_pem(&ed25519_private_pem).unwrap();
        let host_config = fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap();

        assert!(host_config.contains("-----BEGIN RSA PUBLIC KEY-----\n"));
        assert!(host_config.contains("-----END RSA PUBLIC KEY-----\n"));
        let rsa_public_pem = host_config
            .split("Ed25519PublicKey = ")
            .next()
            .expect("host config contains RSA public key");
        assert_eq!(
            RsaPublicKey::from(&rsa_private),
            RsaPublicKey::from_pkcs1_pem(rsa_public_pem).unwrap()
        );
        assert!(host_config.contains(&format!(
            "Ed25519PublicKey = {}\n",
            ed25519_private.public_key().to_base64()
        )));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                0o600,
                fs::metadata(confbase.join("rsa_key.priv"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
            let tinc_up = confbase.join("tinc-up");
            assert!(
                fs::read_to_string(&tinc_up)
                    .unwrap()
                    .contains("Unconfigured tinc-up script")
            );
            assert_eq!(
                0o755,
                fs::metadata(tinc_up).unwrap().permissions().mode() & 0o777
            );
        }

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn init_check_port_keeps_default_port_when_available_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("init-port-default");
        let host_path = confbase.join("hosts").join("alpha");
        fs::write(&host_path, "Ed25519PublicKey = test\n").unwrap();

        let mut attempted = Vec::new();
        let port = check_init_port(
            &confbase,
            "alpha",
            || panic!("random port should not be requested when 655 binds"),
            |port| {
                attempted.push(port);
                port == DEFAULT_TINC_PORT
            },
        )
        .unwrap();

        assert_eq!(DEFAULT_TINC_PORT, port);
        assert_eq!(vec![DEFAULT_TINC_PORT], attempted);
        assert_eq!(
            "Ed25519PublicKey = test\n",
            fs::read_to_string(host_path).unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn init_check_port_appends_random_port_when_default_is_busy_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("init-port-random");
        let host_path = confbase.join("hosts").join("alpha");
        fs::write(&host_path, "Ed25519PublicKey = test\n").unwrap();
        let mut random_ports = [4567u16, 8123u16].into_iter();
        let mut attempted = Vec::new();

        let port = check_init_port(
            &confbase,
            "alpha",
            || Ok(random_ports.next().expect("expected another random port")),
            |port| {
                attempted.push(port);
                port == 8123
            },
        )
        .unwrap();

        assert_eq!(8123, port);
        assert_eq!(vec![DEFAULT_TINC_PORT, 4567, 8123], attempted);
        assert_eq!(
            "Ed25519PublicKey = test\nPort = 8123\n",
            fs::read_to_string(host_path).unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn init_uses_check_port_after_key_generation_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("init-port-command");
        fs::remove_file(confbase.join("tinc.conf")).ok();
        let command = TincCommand {
            options: TincOptions {
                confbase: Some(confbase.clone()),
                ..TincOptions::new("tinc".to_owned())
            },
            name: "init".to_owned(),
            arguments: vec!["alpha".to_owned()],
        };
        let mut read_name = || panic!("name should come from argv");
        let mut random_ports = [7654u16].into_iter();

        run_init_command_with_name_reader_and_ports(
            &command,
            false,
            &mut read_name,
            || Ok(random_ports.next().expect("expected replacement port")),
            |port| port == 7654,
        )
        .unwrap();

        let host_config = fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap();
        assert!(host_config.contains("-----BEGIN RSA PUBLIC KEY-----\n"));
        assert!(host_config.contains("Ed25519PublicKey = "));
        assert!(host_config.ends_with("Port = 7654\n"));
        assert!(confbase.join("tinc-up").exists());

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn init_reads_missing_name_interactively_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("init-interactive-name");
        fs::remove_file(confbase.join("tinc.conf")).ok();
        let command = TincCommand {
            options: TincOptions {
                confbase: Some(confbase.clone()),
                ..TincOptions::new("tinc".to_owned())
            },
            name: "init".to_owned(),
            arguments: Vec::new(),
        };
        let mut input = io::Cursor::new(b"alpha\t \r\n".as_slice());

        let output = run_init_command_with_name_reader(&command, true, || {
            read_init_name_from_reader(&mut input)
        })
        .unwrap();

        assert_eq!(String::new(), output);
        assert_eq!(
            "Name = alpha\n",
            fs::read_to_string(confbase.join("tinc.conf")).unwrap()
        );
        assert!(confbase.join("rsa_key.priv").exists());
        assert!(confbase.join("ed25519_key.priv").exists());
        assert!(confbase.join("hosts").join("alpha").exists());

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn init_interactive_empty_name_is_rejected_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        let mut input = io::Cursor::new(b"\t \r\n".as_slice());

        assert_eq!(
            Err(TincError::MissingName),
            read_init_name_from_reader(&mut input)
        );
    }

    #[test]
    fn init_rejects_missing_invalid_extra_and_existing_configs() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(Err(TincError::MissingName), run(args(&["tinc", "init"])));
        assert_eq!(
            Err(TincError::InvalidNodeName("bad-name".to_owned())),
            run(args(&["tinc", "init", "bad-name"]))
        );
        assert_eq!(
            Err(TincError::TooManyArguments),
            run(args(&["tinc", "init", "alpha", "extra"]))
        );

        let confbase = temp_confbase("init-existing");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        assert_eq!(
            Err(TincError::ConfigurationExists(confbase.join("tinc.conf"))),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "init",
                "alpha",
            ]))
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn invite_creates_invitation_file_and_url() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("invite");
        let key = TincEd25519PrivateKey::from_seed([11; ED25519_SEED_LEN]);
        fs::write(
            confbase.join("tinc.conf"),
            "Name = alpha\nMode = switch\nBroadcast = mst\n",
        )
        .unwrap();
        fs::write(
            confbase.join("hosts").join("alpha"),
            format!(
                "Address = 203.0.113.1 665\nPort = 0\nSubnet = 10.1.0.0/16\nEd25519PublicKey = {}\n",
                key.public_key().to_base64()
            ),
        )
        .unwrap();
        fs::write(confbase.join("ed25519_key.priv"), key.to_pem()).unwrap();

        let action = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "invite",
            "beta",
        ]))
        .unwrap();
        let CliAction::Exit { code: 0, output } = action else {
            panic!("expected invite output");
        };
        let url = output.trim_end();
        let (authority, token) = url.split_once('/').unwrap();

        assert_eq!("203.0.113.1:665", authority);
        assert_eq!(48, token.len());

        let invitations = confbase.join("invitations");
        let invite_files = fs::read_dir(&invitations)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().into_string().unwrap();
                (name.len() == 24).then_some((name, entry.path()))
            })
            .collect::<Vec<_>>();
        assert_eq!(1, invite_files.len());

        let invitation = fs::read_to_string(&invite_files[0].1).unwrap();
        assert!(invitation.contains("Name = beta\n"));
        assert!(invitation.contains("ConnectTo = alpha\n"));
        assert!(invitation.contains("Mode = switch\n"));
        assert!(invitation.contains("Broadcast = mst\n"));
        assert!(
            invitation
                .contains("#---------------------------------------------------------------#\n")
        );
        assert!(invitation.contains("Name = alpha\n"));
        assert!(invitation.contains("Port = 665\n"));
        assert!(invitation.contains("Subnet = 10.1.0.0/16\n"));

        let dump = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "dump",
            "invitations",
        ]))
        .unwrap();
        let CliAction::Exit { output: dump, .. } = dump else {
            panic!("expected dump output");
        };
        assert_eq!(format!("{} beta\n", invite_files[0].0), dump);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                0o600,
                fs::metadata(invitations.join("ed25519_key.priv"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
            assert_eq!(
                0o600,
                fs::metadata(&invite_files[0].1)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
        }

        fs::remove_dir_all(confbase).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn invite_runs_invitation_created_script_with_c_environment() {
        tinc_test_support::assert_can_create_netns();
        use std::os::unix::fs::PermissionsExt;

        let confbase = temp_confbase("invite-script");
        let output = confbase.join("invitation.env");
        let key = TincEd25519PrivateKey::from_seed([12; ED25519_SEED_LEN]);
        fs::write(
            confbase.join("tinc.conf"),
            "Name = alpha\nScriptsExtension = .sh\n",
        )
        .unwrap();
        fs::write(
            confbase.join("hosts").join("alpha"),
            format!(
                "Address = 203.0.113.1 665\nEd25519PublicKey = {}\n",
                key.public_key().to_base64()
            ),
        )
        .unwrap();
        fs::write(confbase.join("ed25519_key.priv"), key.to_pem()).unwrap();
        fs::write(
            confbase.join("invitation-created"),
            format!(
                "#!/bin/sh\n\
                 printf 'NETNAME=%s\\n' \"$NETNAME\" > {output}\n\
                 printf 'NAME=%s\\n' \"$NAME\" >> {output}\n\
                 printf 'NODE=%s\\n' \"$NODE\" >> {output}\n\
                 printf 'INVITATION_FILE=%s\\n' \"$INVITATION_FILE\" >> {output}\n\
                 printf 'INVITATION_URL=%s\\n' \"$INVITATION_URL\" >> {output}\n\
                 exit 7\n",
                output = output.display()
            ),
        )
        .unwrap();
        fs::set_permissions(
            confbase.join("invitation-created"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let action = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "--net",
            "prod",
            "invite",
            "beta",
        ]))
        .unwrap();
        let CliAction::Exit {
            code: 0,
            output: url,
        } = action
        else {
            panic!("expected invite output");
        };
        let url = url.trim_end();
        let invitations = confbase.join("invitations");
        let invite_files = fs::read_dir(&invitations)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().into_string().unwrap();
                (name.len() == 24).then_some(entry.path())
            })
            .collect::<Vec<_>>();
        assert_eq!(1, invite_files.len());

        let env = fs::read_to_string(output).unwrap();
        assert!(env.contains("NETNAME=prod\n"));
        assert!(env.contains("NAME=alpha\n"));
        assert!(env.contains("NODE=beta\n"));
        assert!(env.contains(&format!("INVITATION_FILE={}\n", invite_files[0].display())));
        assert!(env.contains(&format!("INVITATION_URL={url}\n")));

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn invite_rejects_invalid_arguments_and_existing_hosts() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(TincError::InvalidArguments(
                "invalid number of arguments".to_owned()
            )),
            run(args(&["tinc", "invite"]))
        );
        assert_eq!(
            Err(TincError::InvalidNodeName("bad-name".to_owned())),
            run(args(&["tinc", "invite", "bad-name"]))
        );

        let confbase = temp_confbase("invite-existing");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(confbase.join("hosts").join("beta"), "").unwrap();

        assert_eq!(
            Err(TincError::ConfigurationExists(
                confbase.join("hosts").join("beta")
            )),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "invite",
                "beta",
            ]))
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn parses_invitation_urls_like_tincctl() {
        tinc_test_support::assert_can_create_netns();
        let key_hash = [1u8; 18];
        let cookie = [2u8; 18];
        let token = format!(
            "{}{}",
            b64encode_tinc_urlsafe(&key_hash),
            b64encode_tinc_urlsafe(&cookie)
        );

        assert_eq!(
            ParsedInvitationUrl {
                address: "host.example".to_owned(),
                port: "655".to_owned(),
                key_hash,
                cookie,
            },
            parse_invitation_url(&format!("host.example/{token}")).unwrap()
        );
        assert_eq!(
            ParsedInvitationUrl {
                address: "2001:db8::1".to_owned(),
                port: "1665".to_owned(),
                key_hash,
                cookie,
            },
            parse_invitation_url(&format!("[2001:db8::1]:1665/{token}")).unwrap()
        );

        assert_eq!(
            Err(TincError::InvalidArguments(
                "invalid invitation URL".to_owned()
            )),
            parse_invitation_url("host.example/not-a-token")
        );
    }

    #[test]
    fn finalize_join_data_writes_local_and_imported_configuration() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("join-finalize");
        fs::remove_file(confbase.join("tinc.conf")).ok();
        let alpha_key = TincEd25519PrivateKey::from_seed([12; ED25519_SEED_LEN]);
        let invitation_data = format!(
            "Name = beta\n\
NetName = ignored\n\
ConnectTo = alpha\n\
Mode = switch\n\
Compression = 9\n\
Subnet = 10.2.0.0/16\n\
Device = /dev/null\n\
#---------------------------------------------------------------#\n\
Name = alpha\n\
Address = 203.0.113.1 665\n\
Ed25519PublicKey = {}\n",
            alpha_key.public_key().to_base64()
        );

        assert_eq!(
            "beta",
            finalize_join_data(&confbase, &invitation_data, false).unwrap()
        );

        let tinc_conf = fs::read_to_string(confbase.join("tinc.conf")).unwrap();
        assert!(tinc_conf.contains("Name = beta\n"));
        assert!(tinc_conf.contains("ConnectTo = alpha\n"));
        assert!(tinc_conf.contains("Mode = switch\n"));
        assert!(!tinc_conf.contains("NetName"));
        assert!(!tinc_conf.contains("Device"));

        let beta_host = fs::read_to_string(confbase.join("hosts").join("beta")).unwrap();
        assert!(beta_host.contains("Compression = 9\n"));
        assert!(beta_host.contains("Subnet = 10.2.0.0/16\n"));
        assert!(beta_host.contains("Ed25519PublicKey = "));
        assert!(
            RsaPublicKey::from_pkcs1_pem(&extract_pem_block(&beta_host, "RSA PUBLIC KEY").unwrap())
                .is_ok()
        );
        assert!(!beta_host.contains("Device"));

        let alpha_host = fs::read_to_string(confbase.join("hosts").join("alpha")).unwrap();
        assert_eq!(
            format!(
                "Address = 203.0.113.1 665\nEd25519PublicKey = {}\n",
                alpha_key.public_key().to_base64()
            ),
            alpha_host
        );
        assert_eq!(
            invitation_data,
            fs::read_to_string(confbase.join("invitation-data")).unwrap()
        );
        assert!(
            TincEd25519PrivateKey::from_pem(
                &fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap()
            )
            .is_ok()
        );
        assert!(
            RsaPrivateKey::from_pkcs1_pem(
                &fs::read_to_string(confbase.join("rsa_key.priv")).unwrap()
            )
            .is_ok()
        );
        let tinc_up = fs::read_to_string(confbase.join("tinc-up")).unwrap();
        assert!(tinc_up.contains("Unconfigured tinc-up script"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                0o600,
                fs::metadata(confbase.join("ed25519_key.priv"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
            assert_eq!(
                0o600,
                fs::metadata(confbase.join("rsa_key.priv"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
            assert_eq!(
                0o755,
                fs::metadata(confbase.join("tinc-up"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            );
        }

        fs::remove_dir_all(confbase).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn finalize_join_data_generates_tinc_up_from_ifconfig_and_route_like_tinc() {
        tinc_test_support::assert_can_create_netns();
        use std::os::unix::fs::PermissionsExt;

        let alpha_key = TincEd25519PrivateKey::from_seed([13; ED25519_SEED_LEN]);
        let invitation_data = format!(
            "Name = beta\n\
Ifconfig = 10.9.0.2/24\n\
Ifconfig = dhcp6\n\
Ifconfig = slaac\n\
Route = 10.9.0.0/24\n\
Route = 2001:db8::/64 2001:db8::1/128\n\
ConnectTo = alpha\n\
#---------------------------------------------------------------#\n\
Name = alpha\n\
Address = 203.0.113.1 665\n\
Ed25519PublicKey = {}\n",
            alpha_key.public_key().to_base64()
        );

        let forced = temp_confbase("join-tinc-up-force");
        fs::remove_file(forced.join("tinc.conf")).ok();
        assert_eq!(
            "beta",
            finalize_join_data(&forced, &invitation_data, true).unwrap()
        );
        let tinc_up = fs::read_to_string(forced.join("tinc-up")).unwrap();
        assert_eq!(
            "#!/bin/sh\n\
ip link set \"$INTERFACE\" up\n\
ip addr replace 10.9.0.2/24 dev \"$INTERFACE\"\n\
dhclient -6 -nw \"$INTERFACE\"\n\
echo 1 >\"/proc/sys/net/ipv6/conf/$INTERFACE/accept_ra\"\n\
echo 1 >\"/proc/sys/net/ipv6/conf/$INTERFACE/autoconf\"\n\
ip route add 10.9.0.0/24 dev \"$INTERFACE\"\n\
ip route add 2001:db8::/64 via 2001:db8::1 dev \"$INTERFACE\" onlink\n",
            tinc_up
        );
        assert!(
            !fs::read_to_string(forced.join("tinc.conf"))
                .unwrap()
                .contains("Ifconfig")
        );
        assert_eq!(
            0o755,
            fs::metadata(forced.join("tinc-up"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        );
        fs::remove_dir_all(forced).unwrap();

        let unforced = temp_confbase("join-tinc-up-unforced");
        fs::remove_file(unforced.join("tinc.conf")).ok();
        assert_eq!(
            "beta",
            finalize_join_data(&unforced, &invitation_data, false).unwrap()
        );
        assert!(!unforced.join("tinc-up").exists());
        assert_eq!(
            tinc_up,
            fs::read_to_string(unforced.join("tinc-up.invitation")).unwrap()
        );
        fs::remove_dir_all(unforced).unwrap();
    }

    #[test]
    fn finalize_join_data_rejects_existing_config_and_bad_names() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("join-finalize-errors");
        fs::write(confbase.join("tinc.conf"), "Name = existing\n").unwrap();

        assert_eq!(
            Err(TincError::ConfigurationExists(confbase.join("tinc.conf"))),
            finalize_join_data(&confbase, "Name = beta\n", false)
        );

        fs::remove_file(confbase.join("tinc.conf")).unwrap();
        assert_eq!(
            Err(TincError::InvalidNodeName("bad-name".to_owned())),
            finalize_join_data(&confbase, "Name = bad-name\n", false)
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn join_accepts_invitation_over_sptps_tcp() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("join-network");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_key = TincEd25519PrivateKey::from_seed([42; ED25519_SEED_LEN]);
        let server_public = server_key.public_key().to_base64();
        let cookie = [9u8; 18];
        let invitation_data = format!(
            "Name = beta\n\
ConnectTo = alpha\n\
Mode = switch\n\
Subnet = 10.9.0.0/16\n\
#---------------------------------------------------------------#\n\
Name = alpha\n\
Address = 127.0.0.1 {port}\n\
Ed25519PublicKey = {server_public}\n"
        );
        let token = format!(
            "{}{}",
            hash18_tinc_urlsafe(server_public.as_bytes()),
            b64encode_tinc_urlsafe(&cookie)
        );
        let url = format!("127.0.0.1:{port}/{token}");
        let server = thread::spawn(move || {
            run_fake_invitation_server(listener, server_key, cookie, invitation_data)
        });

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new(),
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "join",
                &url,
            ]))
            .unwrap()
        );

        let returned_public_key = server.join().unwrap();
        let tinc_conf = fs::read_to_string(confbase.join("tinc.conf")).unwrap();
        let beta_host = fs::read_to_string(confbase.join("hosts").join("beta")).unwrap();

        assert!(tinc_conf.contains("Name = beta\n"));
        assert!(tinc_conf.contains("ConnectTo = alpha\n"));
        assert!(tinc_conf.contains("Mode = switch\n"));
        assert!(beta_host.contains("Subnet = 10.9.0.0/16\n"));
        assert!(beta_host.contains(&format!("Ed25519PublicKey = {returned_public_key}\n")));
        assert!(
            TincEd25519PrivateKey::from_pem(
                &fs::read_to_string(confbase.join("ed25519_key.priv")).unwrap()
            )
            .is_ok()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    fn run_fake_invitation_server(
        listener: TcpListener,
        server_key: TincEd25519PrivateKey,
        expected_cookie: [u8; 18],
        invitation_data: String,
    ) -> String {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(INVITATION_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(INVITATION_TIMEOUT)).unwrap();
        let mut connection = InvitationConnection::new(stream);
        let id_line = connection.read_line().unwrap();
        let MetaMessage::Id(id) = parse_meta_message(&id_line).unwrap() else {
            panic!("expected ID");
        };
        let client_public = id.name.strip_prefix('?').unwrap();
        let client_key = TincEd25519PublicKey::from_base64(client_public).unwrap();

        connection
            .write_all(
                format!(
                    "{} alpha {}.{}\n{} {}\n",
                    Request::Id.number(),
                    PROT_MAJOR,
                    PROT_MINOR,
                    Request::Ack.number(),
                    server_key.public_key().to_base64()
                )
                .as_bytes(),
            )
            .unwrap();

        let mut session =
            SptpsHandshakeSession::start_tcp(false, server_key, client_key, INVITATION_LABEL)
                .unwrap();
        let mut decoder = MetaStreamDecoder::new();

        for record in session.drain_outbound() {
            connection.write_all(&record).unwrap();
        }

        loop {
            while let Some(frame) = decoder.next_sptps_frame(session.is_established()).unwrap() {
                let MetaStreamFrame::SptpsRecord(record) = frame else {
                    panic!("expected SPTPS record");
                };
                let events = session.receive_datagram(&record).unwrap();

                for record in session.drain_outbound() {
                    connection.write_all(&record).unwrap();
                }

                for event in events {
                    match event {
                        SptpsHandshakeEvent::HandshakeComplete => {}
                        SptpsHandshakeEvent::ApplicationRecord {
                            record_type: 0,
                            payload,
                        } => {
                            assert_eq!(expected_cookie.as_slice(), payload.as_slice());
                            let data = session.send_record(0, invitation_data.as_bytes()).unwrap();
                            let finalize = session.send_record(1, b"").unwrap();
                            connection.write_all(&data).unwrap();
                            connection.write_all(&finalize).unwrap();
                        }
                        SptpsHandshakeEvent::ApplicationRecord {
                            record_type: 1,
                            payload,
                        } => {
                            let public_key = String::from_utf8(payload).unwrap();
                            let success = session.send_record(2, b"").unwrap();
                            connection.write_all(&success).unwrap();
                            return public_key;
                        }
                        SptpsHandshakeEvent::ApplicationRecord { record_type, .. } => {
                            panic!("unexpected record type {record_type}");
                        }
                    }
                }
            }

            if connection.read_more().unwrap() == 0 {
                panic!("client closed invitation connection");
            }

            decoder.push(&connection.take_buffer());
        }
    }

    #[cfg(unix)]
    #[test]
    fn pid_reads_explicit_and_default_pidfiles() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("pid");
        let explicit = confbase.join("custom.pid");
        fs::write(&explicit, "1234 abcdef 127.0.0.1 port 655\n").unwrap();
        fs::write(confbase.join("pid"), "5678 deadbeef localhost port 12345\n").unwrap();

        let explicit_handle =
            spawn_fake_control_server(&confbase.join("custom.socket"), "abcdef", 1234);
        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "1234\n".to_owned()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "--pidfile",
                explicit.to_str().unwrap(),
                "pid",
            ]))
            .unwrap()
        );
        explicit_handle.join().unwrap();

        let default_handle =
            spawn_fake_control_server(&confbase.join("pid.socket"), "deadbeef", 5678);
        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "5678\n".to_owned()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "pid",
            ]))
            .unwrap()
        );
        default_handle.join().unwrap();

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn pid_rejects_arguments_and_malformed_pidfiles() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("pid-errors");
        let pidfile = confbase.join("pid");
        fs::write(&pidfile, "not-a-pid abc localhost port 12345\n").unwrap();

        assert_eq!(
            Err(TincError::TooManyArguments),
            run(args(&["tinc", "pid", "extra"]))
        );
        assert_eq!(
            Err(TincError::InvalidPidFile(pidfile)),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "pid",
            ]))
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn parse_pidfile_preserves_control_fields_for_future_control_socket_use() {
        tinc_test_support::assert_can_create_netns();
        let path = Path::new("/tmp/tinc.pid");
        let parsed = parse_pidfile(path, "42 cookie host.example port 777\n").unwrap();

        assert_eq!(
            PidFile {
                pid: 42,
                cookie: "cookie".to_owned(),
                host: "host.example".to_owned(),
                port: "777".to_owned(),
            },
            parsed
        );
        assert_eq!(
            Err(TincError::InvalidPidFile(path.to_path_buf())),
            parse_pidfile(path, "42 cookie host.example 777\n")
        );
    }

    #[test]
    fn tcp_control_target_uses_pidfile_host_port_like_c_windows_connect_tincd() {
        tinc_test_support::assert_can_create_netns();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!("0 ^abcdef 0\n", line);
            stream.write_all(b"0 tinc 17.0\n4 0 4321\n").unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 1\n", line);
            stream.write_all(b"18 1 0\n").unwrap();
        });
        let pidfile = PidFile {
            pid: 4321,
            cookie: "abcdef".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: port.to_string(),
        };
        let request = ControlRequestLine {
            request: REQ_RELOAD,
            line: "18 1\n".to_owned(),
        };
        let mut control = open_control_target(
            ControlTarget::Tcp {
                host: pidfile.host.clone(),
                port: pidfile.port.clone(),
            },
            &pidfile,
        )
        .unwrap();

        send_control_line(&mut control, &request).unwrap();
        assert_eq!(
            ControlResponseLine {
                request: REQ_RELOAD,
                result: 0
            },
            read_control_response(&mut control).unwrap()
        );

        handle.join().unwrap();
    }

    #[test]
    fn tcp_control_address_resolution_accepts_separate_ipv6_host_and_port_like_getaddrinfo() {
        tinc_test_support::assert_can_create_netns();
        let addresses = resolve_tcp_control_addresses("::1", "655").unwrap();

        assert!(
            addresses
                .iter()
                .any(|address| address.ip() == Ipv6Addr::LOCALHOST && address.port() == 655),
            "{addresses:?}"
        );
    }

    #[test]
    fn simple_control_requests_match_tinc_wire_format() {
        tinc_test_support::assert_can_create_netns();
        let command = TincCommand {
            options: TincOptions::new("tinc".to_owned()),
            name: "reload".to_owned(),
            arguments: vec![],
        };
        assert_eq!(
            ControlRequestLine {
                request: REQ_RELOAD,
                line: "18 1\n".to_owned()
            },
            build_simple_control_request(&command).unwrap()
        );

        let command = TincCommand {
            options: TincOptions::new("tinc".to_owned()),
            name: "debug".to_owned(),
            arguments: vec!["5extra".to_owned()],
        };
        assert_eq!(
            ControlRequestLine {
                request: REQ_SET_DEBUG,
                line: "18 9 5\n".to_owned()
            },
            build_simple_control_request(&command).unwrap()
        );

        let command = TincCommand {
            options: TincOptions::new("tinc".to_owned()),
            name: "disconnect".to_owned(),
            arguments: vec!["bad-name".to_owned()],
        };
        assert_eq!(
            Err(TincError::InvalidNodeName("bad-name".to_owned())),
            build_simple_control_request(&command)
        );
    }

    #[test]
    fn dump_control_requests_match_tinc_wire_format() {
        tinc_test_support::assert_can_create_netns();
        let command = TincCommand {
            options: TincOptions::new("tinc".to_owned()),
            name: "list".to_owned(),
            arguments: vec!["reachable".to_owned(), "nodes".to_owned()],
        };
        assert_eq!(
            DumpControlRequest {
                lines: vec![ControlRequestLine {
                    request: REQ_DUMP_NODES,
                    line: "18 3\n".to_owned()
                }],
                mode: DumpMode::Nodes {
                    only_reachable: true
                }
            },
            build_dump_control_request(&command).unwrap()
        );

        let command = TincCommand {
            options: TincOptions::new("tinc".to_owned()),
            name: "dump".to_owned(),
            arguments: vec!["digraph".to_owned()],
        };
        assert_eq!(
            DumpControlRequest {
                lines: vec![
                    ControlRequestLine {
                        request: REQ_DUMP_NODES,
                        line: "18 3\n".to_owned()
                    },
                    ControlRequestLine {
                        request: REQ_DUMP_EDGES,
                        line: "18 4\n".to_owned()
                    }
                ],
                mode: DumpMode::Graph { directed: true }
            },
            build_dump_control_request(&command).unwrap()
        );

        let command = TincCommand {
            options: TincOptions::new("tinc".to_owned()),
            name: "dump".to_owned(),
            arguments: vec!["reachable".to_owned(), "edges".to_owned()],
        };
        assert_eq!(
            Err(TincError::InvalidArguments(
                "`reachable' only supported for nodes".to_owned()
            )),
            build_dump_control_request(&command)
        );
    }

    #[test]
    fn dump_response_formats_nodes_edges_subnets_connections_and_graph() {
        tinc_test_support::assert_can_create_netns();
        let nodes = DumpControlRequest {
            lines: vec![ControlRequestLine {
                request: REQ_DUMP_NODES,
                line: "18 3\n".to_owned(),
            }],
            mode: DumpMode::Nodes {
                only_reachable: true,
            },
        };
        let lines = vec![
            "18 3 alpha 010203 host port 655 0 0 0 0 0 12 alpha alpha 0 1500 1400 1518 123 -1 1 2 3 4"
                .to_owned(),
            "18 3 beta 040506 host port 655 0 0 0 0 0 2 beta beta 0 1500 0 1518 123 2500 5 6 7 8"
                .to_owned(),
            "18 3".to_owned(),
        ];
        assert_eq!(
            "alpha id 010203 at host port 655 cipher 0 digest 0 maclength 0 compression 0 options 0 status 0012 nexthop alpha via alpha distance 0 pmtu 1500 (min 1400 max 1518) rx 1 2 tx 3 4\n",
            format_dump_response(&nodes, &lines).unwrap()
        );

        let subnets = DumpControlRequest {
            lines: vec![ControlRequestLine {
                request: REQ_DUMP_SUBNETS,
                line: "18 5\n".to_owned(),
            }],
            mode: DumpMode::Subnets,
        };
        assert_eq!(
            "10.0.0.0/24 owner alpha\n",
            format_dump_response(
                &subnets,
                &["18 5 10.0.0.0/24#10 alpha".to_owned(), "18 5".to_owned()]
            )
            .unwrap()
        );

        let connections = DumpControlRequest {
            lines: vec![ControlRequestLine {
                request: REQ_DUMP_CONNECTIONS,
                line: "18 6\n".to_owned(),
            }],
            mode: DumpMode::Connections,
        };
        assert_eq!(
            "alpha at host port 655 options 0 socket 7 status 2\n",
            format_dump_response(
                &connections,
                &[
                    "18 6 alpha host port 655 0 7 2".to_owned(),
                    "18 6".to_owned()
                ]
            )
            .unwrap()
        );

        let graph = DumpControlRequest {
            lines: vec![
                ControlRequestLine {
                    request: REQ_DUMP_NODES,
                    line: "18 3\n".to_owned(),
                },
                ControlRequestLine {
                    request: REQ_DUMP_EDGES,
                    line: "18 4\n".to_owned(),
                },
            ],
            mode: DumpMode::Graph { directed: false },
        };
        let graph_output = format_dump_response(
            &graph,
            &[
                "18 3 alpha 010203 MYSELF port 655 0 0 0 0 0 12 alpha alpha 0 1500 1400 1518 123 -1 1 2 3 4".to_owned(),
                "18 3".to_owned(),
                "18 4 beta alpha host port 655 local port 655 0 10".to_owned(),
                "18 4".to_owned(),
            ],
        )
        .unwrap();
        assert!(graph_output.starts_with("graph {\n"));
        assert!(
            graph_output
                .contains("\"alpha\" [label = \"alpha\", color = \"green\", style = \"filled\"]")
        );
        assert!(graph_output.contains("\"beta\" -- \"alpha\""));
        assert!(graph_output.ends_with("}\n"));
    }

    #[test]
    fn dump_invitations_lists_valid_local_invitation_files() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("dump-invitations");

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "dump",
                "invitations",
            ]))
            .unwrap()
        );

        let invitations = confbase.join("invitations");
        fs::create_dir_all(&invitations).unwrap();
        let token = tinc_core::utils::b64encode_tinc_urlsafe(b"123456789012345678");
        let trailing_space_token = tinc_core::utils::b64encode_tinc_urlsafe(b"abcdefghijklmnopqr");
        let leading_space_token = tinc_core::utils::b64encode_tinc_urlsafe(b"rstuvwxyzabcdefghi");
        fs::write(invitations.join(&token), "Name = alpha\n").unwrap();
        fs::write(invitations.join("not-a-token"), "Name = beta\n").unwrap();
        fs::write(
            invitations.join(&trailing_space_token),
            "Name = gamma\t \r\n",
        )
        .unwrap();
        fs::write(invitations.join(&leading_space_token), " Name = beta\n").unwrap();
        fs::write(
            invitations.join(tinc_core::utils::b64encode_tinc_urlsafe(
                b"jklmnopqrstuvwxyz0",
            )),
            "Name = bad-name\n",
        )
        .unwrap();

        let mut expected = [
            format!("{token} alpha\n"),
            format!("{trailing_space_token} gamma\n"),
        ];
        expected.sort();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: expected.join("")
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "dump",
                "invitations",
            ]))
            .unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn network_lists_known_configuration_directories() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("network-list");
        fs::write(confbase.join("tinc.conf"), "Name = root\n").unwrap();
        fs::create_dir_all(confbase.join("alpha")).unwrap();
        fs::write(confbase.join("alpha").join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::create_dir_all(confbase.join("beta")).unwrap();
        fs::write(confbase.join("beta").join("not-tinc.conf"), "Name = beta\n").unwrap();
        fs::create_dir_all(confbase.join(".hidden")).unwrap();
        fs::write(
            confbase.join(".hidden").join("tinc.conf"),
            "Name = hidden\n",
        )
        .unwrap();
        fs::write(confbase.join("plain-file"), "").unwrap();

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: ".\nalpha\n".to_owned()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "network",
            ]))
            .unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn network_switch_validates_netname_like_tincctl() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("network-switch");

        assert_eq!(
            Err(TincError::TooManyArguments),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "network",
                "foo",
                "bar",
            ]))
        );
        assert_eq!(
            Err(TincError::InvalidNetname("foo./".to_owned())),
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "network",
                "foo./",
            ]))
        );
        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "Warning: unsafe character in netname!\n".to_owned()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "network",
                "foo.<",
            ]))
            .unwrap()
        );
        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "network",
                ".",
            ]))
            .unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    fn write_fsck_config(confbase: &Path, name: &str, key: &TincEd25519PrivateKey) {
        fs::write(confbase.join("tinc.conf"), format!("Name = {name}\n")).unwrap();
        let rsa = generate_rsa_keypair(1024).unwrap();
        write_rsa_keypair(confbase, Some(name), &rsa).unwrap();
        append_config_text(
            &confbase.join("ed25519_key.priv"),
            &key.to_pem(),
            FilePrivacy::Private,
        )
        .unwrap();
        append_config_text(
            &confbase.join("hosts").join(name),
            &format!("Ed25519PublicKey = {}\n", key.public_key().to_base64()),
            FilePrivacy::Public,
        )
        .unwrap();
    }

    #[test]
    fn fsck_accepts_minimal_rsa_ed25519_configuration() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("fsck-minimal");
        let key = TincEd25519PrivateKey::from_seed([7; ED25519_SEED_LEN]);
        write_fsck_config(&confbase, "alpha", &key);

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "fsck",
            ]))
            .unwrap()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn fsck_reports_missing_rsa_and_ed25519_private_keys() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("fsck-missing-keys");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();
        fs::write(confbase.join("hosts").join("alpha"), "").unwrap();

        let CliAction::Exit { code, output } = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "fsck",
        ]))
        .unwrap() else {
            panic!("expected fsck exit");
        };

        assert_eq!(1, code);
        assert!(output.contains("Neither RSA or Ed25519 private key found"));
        assert!(output.contains("tinc generate-keys"));

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn fsck_reports_missing_tinc_conf_and_name() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("fsck-missing-conf");
        fs::remove_file(confbase.join("tinc.conf")).ok();

        let CliAction::Exit { code, output } = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "fsck",
        ]))
        .unwrap() else {
            panic!("expected fsck exit");
        };

        assert_eq!(1, code);
        assert!(output.contains("No tinc configuration found"));
        assert!(output.contains("tinc cannot run without a valid Name"));

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn fsck_force_writes_missing_ed25519_public_key() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("fsck-force-ed25519");
        let key = TincEd25519PrivateKey::from_seed([8; ED25519_SEED_LEN]);
        write_fsck_config(&confbase, "alpha", &key);
        fs::write(confbase.join("hosts").join("alpha"), "").unwrap();

        let CliAction::Exit { code, output } = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "fsck",
        ]))
        .unwrap() else {
            panic!("expected fsck exit");
        };
        assert_eq!(0, code);
        assert!(output.contains("No (usable) public Ed25519 key found"));
        assert!(
            !fs::read_to_string(confbase.join("hosts").join("alpha"))
                .unwrap()
                .contains("ED25519 PUBLIC KEY")
        );

        let CliAction::Exit { code, output } = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "--force",
            "fsck",
        ]))
        .unwrap() else {
            panic!("expected fsck exit");
        };
        assert_eq!(0, code);
        assert!(output.contains("Wrote Ed25519 public key"));
        assert!(
            fs::read_to_string(confbase.join("hosts").join("alpha"))
                .unwrap()
                .contains("ED25519 PUBLIC KEY")
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn fsck_force_writes_missing_rsa_public_key() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("fsck-force-rsa");
        let key = TincEd25519PrivateKey::from_seed([14; ED25519_SEED_LEN]);
        write_fsck_config(&confbase, "alpha", &key);
        fs::write(
            confbase.join("hosts").join("alpha"),
            format!("Ed25519PublicKey = {}\n", key.public_key().to_base64()),
        )
        .unwrap();

        let CliAction::Exit { code, output } = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "fsck",
        ]))
        .unwrap() else {
            panic!("expected fsck exit");
        };
        assert_eq!(0, code);
        assert!(output.contains("No (usable) public RSA key found"));
        assert!(
            !fs::read_to_string(confbase.join("hosts").join("alpha"))
                .unwrap()
                .contains("RSA PUBLIC KEY")
        );

        let CliAction::Exit { code, output } = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "--force",
            "fsck",
        ]))
        .unwrap() else {
            panic!("expected fsck exit");
        };
        assert_eq!(0, code);
        assert!(output.contains("Wrote RSA public key"));
        assert!(
            fs::read_to_string(confbase.join("hosts").join("alpha"))
                .unwrap()
                .contains("RSA PUBLIC KEY")
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn fsck_reports_variable_warnings_like_tincctl() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("fsck-variables");
        let key = TincEd25519PrivateKey::from_seed([9; ED25519_SEED_LEN]);
        write_fsck_config(&confbase, "alpha", &key);
        append_config_text(
            &confbase.join("tinc.conf"),
            "Port = 655\n",
            FilePrivacy::Public,
        )
        .unwrap();
        append_config_text(
            &confbase.join("hosts").join("alpha"),
            "GraphDumpFile = /tmp/graph\nInterface = tun0\nWeight = \nWeight = 2\n",
            FilePrivacy::Public,
        )
        .unwrap();

        let CliAction::Exit { code, output } = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "fsck",
        ]))
        .unwrap() else {
            panic!("expected fsck exit");
        };

        assert_eq!(0, code);
        assert!(output.contains("host variable Port found in server config"));
        assert!(output.contains("obsolete variable GraphDumpFile"));
        assert!(output.contains("server variable Interface found in host config"));
        assert!(output.contains("No value for variable `Weight"));
        assert!(output.contains("multiple instances of variable Weight"));

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn fsck_reports_unknown_scripts_and_force_fixes_executable_bits() {
        tinc_test_support::assert_can_create_netns();
        let confbase = temp_confbase("fsck-scripts");
        let key = TincEd25519PrivateKey::from_seed([10; ED25519_SEED_LEN]);
        write_fsck_config(&confbase, "alpha", &key);
        fs::write(confbase.join("fake-up"), "").unwrap();
        fs::write(confbase.join("tinc-up"), "#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(confbase.join("tinc-up"), fs::Permissions::from_mode(0o644))
                .unwrap();
        }

        let CliAction::Exit { code, output } = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "--force",
            "fsck",
        ]))
        .unwrap() else {
            panic!("expected fsck exit");
        };

        assert_eq!(0, code);
        assert!(output.contains("Unknown script"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                0,
                fs::metadata(confbase.join("tinc-up"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o100
            );
        }

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn info_formats_node_and_subnet_dump_results() {
        tinc_test_support::assert_can_create_netns();
        let lines = vec![
            "18 3 alpha 010203 host port 655 0 0 0 0 0f 12 alpha alpha 0 1500 1400 1518 0 2500 1 2 3 4".to_owned(),
            "18 3 beta 040506 host port 655 0 0 0 0 0 2 beta beta 0 1500 0 1518 0 -1 5 6 7 8".to_owned(),
            "18 3".to_owned(),
            "18 4 alpha beta host port 655 local port 655 0 10".to_owned(),
            "18 4 beta alpha host port 655 local port 655 0 10".to_owned(),
            "18 4".to_owned(),
            "18 5 10.0.0.0/24#10 alpha".to_owned(),
            "18 5 10.0.1.0/24#20 alpha".to_owned(),
            "18 5 10.0.2.0/24 beta".to_owned(),
            "18 5".to_owned(),
        ];

        let info = format_info_node("alpha", &lines).unwrap();
        assert!(info.contains("Node:         alpha\n"));
        assert!(info.contains("Status:       validkey reachable\n"));
        assert!(info.contains("Options:      indirect tcponly pmtu_discovery clamp_mss\n"));
        assert!(info.contains(
            "Reachability: directly with UDP\nPMTU:         1500\nRTT:          2.500\n"
        ));
        assert!(info.contains("Edges:        beta\n"));
        assert!(info.contains("Subnets:      10.0.0.0/24 10.0.1.0/24#20\n"));

        let subnet_lines = vec![
            "18 5 10.0.0.0/24#10 alpha".to_owned(),
            "18 5 10.0.1.0/24#20 alpha".to_owned(),
            "18 5 10.0.2.0/24 beta".to_owned(),
            "18 5".to_owned(),
        ];
        assert_eq!(
            "Subnet: 10.0.0.0/24\nOwner:  alpha\n",
            format_info_subnet_or_address("10.0.0.1", &subnet_lines).unwrap()
        );
        assert_eq!(
            "Subnet: 10.0.1.0/24#20\nOwner:  alpha\n",
            format_info_subnet_or_address("10.0.1.0/24#20", &subnet_lines).unwrap()
        );
        assert_eq!(
            Err(TincError::UnknownAddress("10.99.0.1".to_owned())),
            format_info_subnet_or_address("10.99.0.1", &subnet_lines)
        );
    }

    #[test]
    fn control_socket_path_matches_tinc_pidfile_rule() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            PathBuf::from("/run/tinc.foo.socket"),
            control_socket_path(Path::new("/run/tinc.foo.pid"))
        );
        assert_eq!(
            PathBuf::from("/tmp/tinc/pid.socket"),
            control_socket_path(Path::new("/tmp/tinc/pid"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn reload_uses_pidfile_cookie_and_control_socket() {
        tinc_test_support::assert_can_create_netns();
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let confbase = temp_confbase("control-reload");
        let pidfile = confbase.join("test.pid");
        let socket = confbase.join("test.socket");
        fs::write(&pidfile, "4321 abcdef localhost port 12345\n").unwrap();

        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(confbase).unwrap();
                return;
            }
            Err(error) => panic!("failed to bind test Unix socket: {error}"),
        };
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!("0 ^abcdef 0\n", line);
            stream.write_all(b"0 tinc 17\n4 0 4321\n").unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 1\n", line);
            stream.write_all(b"18 1 0\n").unwrap();
        });

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: String::new()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "--pidfile",
                pidfile.to_str().unwrap(),
                "reload",
            ]))
            .unwrap()
        );

        handle.join().unwrap();
        fs::remove_dir_all(confbase).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn debug_prints_old_level_from_control_response_like_c_tincctl() {
        tinc_test_support::assert_can_create_netns();
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let confbase = temp_confbase("control-debug");
        let pidfile = confbase.join("test.pid");
        let socket = confbase.join("test.socket");
        fs::write(&pidfile, "4321 abcdef localhost port 12345\n").unwrap();

        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(confbase).unwrap();
                return;
            }
            Err(error) => panic!("failed to bind test Unix socket: {error}"),
        };
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!("0 ^abcdef 0\n", line);
            stream.write_all(b"0 tinc 17\n4 0 4321\n").unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 9 3\n", line);
            stream.write_all(b"18 9 7\n").unwrap();
        });

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "Old level 7, new level 3.\n".to_owned()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "--pidfile",
                pidfile.to_str().unwrap(),
                "debug",
                "3",
            ]))
            .unwrap()
        );

        handle.join().unwrap();
        fs::remove_dir_all(confbase).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dump_reachable_nodes_uses_control_socket_and_formats_response() {
        tinc_test_support::assert_can_create_netns();
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let confbase = temp_confbase("control-dump");
        let pidfile = confbase.join("test.pid");
        let socket = confbase.join("test.socket");
        fs::write(&pidfile, "4321 abcdef localhost port 12345\n").unwrap();

        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(confbase).unwrap();
                return;
            }
            Err(error) => panic!("failed to bind test Unix socket: {error}"),
        };
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!("0 ^abcdef 0\n", line);
            stream.write_all(b"0 tinc 17.0\n4 0 4321\n").unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 3\n", line);
            stream.write_all(
                b"18 3 alpha 010203 host port 655 0 0 0 0 0 12 alpha alpha 0 1500 1400 1518 123 -1 1 2 3 4\n\
18 3 beta 040506 host port 655 0 0 0 0 0 2 beta beta 0 1500 0 1518 123 -1 5 6 7 8\n\
18 3\n",
            )
            .unwrap();
        });

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "alpha id 010203 at host port 655 cipher 0 digest 0 maclength 0 compression 0 options 0 status 0012 nexthop alpha via alpha distance 0 pmtu 1500 (min 1400 max 1518) rx 1 2 tx 3 4\n"
                    .to_owned()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "--pidfile",
                pidfile.to_str().unwrap(),
                "dump",
                "reachable",
                "nodes",
            ]))
            .unwrap()
        );

        handle.join().unwrap();
        fs::remove_dir_all(confbase).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn top_dump_request_uses_existing_control_connection_like_c_top_update() {
        tinc_test_support::assert_can_create_netns();
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let confbase = temp_confbase("control-top");
        let pidfile = confbase.join("test.pid");
        let socket = confbase.join("test.socket");
        fs::write(&pidfile, "4321 abcdef localhost port 12345\n").unwrap();

        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(confbase).unwrap();
                return;
            }
            Err(error) => panic!("failed to bind test Unix socket: {error}"),
        };
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!("0 ^abcdef 0\n", line);
            stream.write_all(b"0 tinc 17.0\n4 0 4321\n").unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 13\n", line);
            stream
                .write_all(b"18 13 alpha 1 200 3 400\n18 13 beta 0 0 5 600\n18 13\n")
                .unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 13\n", line);
            stream
                .write_all(b"18 13 alpha 2 250 4 500\n18 13\n")
                .unwrap();
        });

        let pidfile_data = read_pidfile(&pidfile).unwrap();
        let mut control = open_control_socket(&socket, &pidfile_data).unwrap();
        let first = send_top_dump_request(&mut control).unwrap();
        let second = send_top_dump_request(&mut control).unwrap();

        assert_eq!(
            vec![
                "18 13 alpha 1 200 3 400".to_owned(),
                "18 13 beta 0 0 5 600".to_owned(),
                "18 13".to_owned()
            ],
            first
        );
        assert_eq!(
            vec!["18 13 alpha 2 250 4 500".to_owned(), "18 13".to_owned()],
            second
        );

        handle.join().unwrap();
        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn top_state_matches_c_current_rate_sorting_and_stable_ties() {
        let mut top = TopState::new();
        top.update_from_traffic_lines(
            &[
                "18 13 alpha 10 1000 4 400".to_owned(),
                "18 13 beta 1 100 1 100".to_owned(),
                "18 13".to_owned(),
            ],
            Duration::from_secs(1_000),
        )
        .unwrap();
        top.update_from_traffic_lines(
            &[
                "18 13 alpha 12 1200 5 500".to_owned(),
                "18 13 beta 6 600 3 300".to_owned(),
                "18 13".to_owned(),
            ],
            Duration::from_secs(1_001),
        )
        .unwrap();

        top.sort = TopSort::InPackets;
        let output = top.render(Some("testnet"), false);

        assert!(output.starts_with("Tinc testnet           Nodes:    2  Sort: in pkts"));
        assert!(
            output.find("beta").unwrap() < output.find("alpha").unwrap(),
            "{output}"
        );
        assert!(top_snapshot_line_has(&output, "beta", 5, 500, 2, 200));
        assert!(top_snapshot_line_has(&output, "alpha", 2, 200, 1, 100));

        top.update_from_traffic_lines(
            &[
                "18 13 alpha 14 1400 6 600".to_owned(),
                "18 13 beta 8 800 4 400".to_owned(),
                "18 13".to_owned(),
            ],
            Duration::from_secs(1_002),
        )
        .unwrap();
        let tied = top.render(Some("testnet"), false);

        assert!(
            tied.find("beta").unwrap() < tied.find("alpha").unwrap(),
            "C sortfunc() keeps prior display order when selected values tie: {tied}"
        );
    }

    #[test]
    fn top_state_matches_c_cumulative_sorting_units_and_unknown_nodes() {
        let mut top = TopState::new();
        top.update_from_traffic_lines(
            &[
                "18 13 alpha 10 2 4 3".to_owned(),
                "18 13 beta 1 1 1 1".to_owned(),
                "18 13".to_owned(),
            ],
            Duration::from_secs(100),
        )
        .unwrap();
        top.update_from_traffic_lines(
            &["18 13 alpha 11 2 6 3".to_owned(), "18 13".to_owned()],
            Duration::from_secs(101),
        )
        .unwrap();

        top.cumulative = true;
        top.units = TopUnits::MEGABYTES;
        top.sort = TopSort::TotalPackets;
        let output = top.render(None, false);

        assert!(output.contains("Node                IN kpkt   IN Mbyte   OUT kpkt  OUT Mbyte"));
        assert!(
            output.find("alpha").unwrap() < output.find("beta").unwrap(),
            "{output}"
        );
        assert!(top_snapshot_line_has(&output, "alpha", 0, 0, 0, 0));
        assert!(top_snapshot_line_has(&output, "beta", 0, 0, 0, 0));
        assert!(
            !top.nodes
                .iter()
                .find(|node| node.name == "beta")
                .unwrap()
                .known
        );
    }

    #[test]
    fn top_state_key_mapping_matches_c_top_switch_cases() {
        let mut top = TopState::new();

        top.sort = TopSort::Name;
        top.cumulative = false;
        top.units = TopUnits::BYTES;

        for (key, expected) in [
            (b'n', Some(TopKey::Sort(TopSort::Name))),
            (b'i', Some(TopKey::Sort(TopSort::InBytes))),
            (b'I', Some(TopKey::Sort(TopSort::InPackets))),
            (b'o', Some(TopKey::Sort(TopSort::OutBytes))),
            (b'O', Some(TopKey::Sort(TopSort::OutPackets))),
            (b't', Some(TopKey::Sort(TopSort::TotalBytes))),
            (b'T', Some(TopKey::Sort(TopSort::TotalPackets))),
            (b'b', Some(TopKey::Units(TopUnits::BYTES))),
            (b'k', Some(TopKey::Units(TopUnits::KILOBYTES))),
            (b'M', Some(TopKey::Units(TopUnits::MEGABYTES))),
            (b'G', Some(TopKey::Units(TopUnits::GIGABYTES))),
            (b'c', Some(TopKey::ToggleCumulative)),
            (b's', Some(TopKey::PromptDelay)),
            (b'q', Some(TopKey::Quit)),
            (b'x', None),
        ] {
            let actual = top_key_from_byte(key);
            assert_eq!(expected, actual);
            if let Some(key) = actual {
                apply_top_key_for_test(&mut top, key);
            }
            match key {
                b'n' => assert_eq!(TopSort::Name, top.sort),
                b'i' => assert_eq!(TopSort::InBytes, top.sort),
                b'I' => assert_eq!(TopSort::InPackets, top.sort),
                b'o' => assert_eq!(TopSort::OutBytes, top.sort),
                b'O' => assert_eq!(TopSort::OutPackets, top.sort),
                b't' => assert_eq!(TopSort::TotalBytes, top.sort),
                b'T' => assert_eq!(TopSort::TotalPackets, top.sort),
                b'b' => assert_eq!(TopUnits::BYTES, top.units),
                b'k' => assert_eq!(TopUnits::KILOBYTES, top.units),
                b'M' => assert_eq!(TopUnits::MEGABYTES, top.units),
                b'G' => assert_eq!(TopUnits::GIGABYTES, top.units),
                b'c' => assert!(top.cumulative),
                b's' | b'q' | b'x' => {}
                _ => unreachable!(),
            }
            if key == b'c' {
                top.cumulative = false;
            }
        }

        fn apply_top_key_for_test(top: &mut TopState, key: TopKey) {
            match key {
                TopKey::Quit | TopKey::PromptDelay => {}
                TopKey::ToggleCumulative => top.cumulative = !top.cumulative,
                TopKey::Sort(sort) => top.sort = sort,
                TopKey::Units(units) => top.units = units,
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn top_snapshot_gate_can_refresh_two_frames_without_curses() {
        tinc_test_support::assert_can_create_netns();
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let confbase = temp_confbase("control-top-two-frames");
        let pidfile = confbase.join("test.pid");
        let socket = confbase.join("test.socket");
        fs::write(&pidfile, "4321 abcdef localhost port 12345\n").unwrap();

        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(confbase).unwrap();
                return;
            }
            Err(error) => panic!("failed to bind test Unix socket: {error}"),
        };
        let handle = thread::spawn(move || {
            for frame in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();

                reader.read_line(&mut line).unwrap();
                assert_eq!("0 ^abcdef 0\n", line);
                stream.write_all(b"0 tinc 17.0\n4 0 4321\n").unwrap();

                line.clear();
                reader.read_line(&mut line).unwrap();
                assert_eq!("18 13\n", line);
                match frame {
                    0 => stream
                        .write_all(b"18 13 alpha 1 200 3 400\n18 13\n")
                        .unwrap(),
                    1 => stream
                        .write_all(b"18 13 alpha 2 250 4 500\n18 13 beta 9 900 8 800\n18 13\n")
                        .unwrap(),
                    _ => unreachable!(),
                }
            }
        });

        let command = TincCommand {
            options: TincOptions {
                confbase: Some(confbase.clone()),
                confbase_given: true,
                pidfile: Some(pidfile.clone()),
                ..TincOptions::new("tinc".to_owned())
            },
            name: "top".to_owned(),
            arguments: Vec::new(),
        };
        let output = run_top_snapshots_command(&command, 2).unwrap();

        assert!(output.contains("Frame 1\n"));
        assert!(output.contains("Frame 2\n"));
        assert!(top_snapshot_line_has(&output, "alpha", 1, 200, 3, 400));
        assert!(top_snapshot_line_has(&output, "alpha", 2, 250, 4, 500));
        assert!(top_snapshot_line_has(&output, "beta", 9, 900, 8, 800));

        handle.join().unwrap();
        fs::remove_dir_all(confbase).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn info_node_uses_control_socket_and_multiple_dump_requests() {
        tinc_test_support::assert_can_create_netns();
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let confbase = temp_confbase("control-info");
        let pidfile = confbase.join("test.pid");
        let socket = confbase.join("test.socket");
        fs::write(&pidfile, "4321 abcdef localhost port 12345\n").unwrap();

        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(confbase).unwrap();
                return;
            }
            Err(error) => panic!("failed to bind test Unix socket: {error}"),
        };
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!("0 ^abcdef 0\n", line);
            stream.write_all(b"0 tinc 17.0\n4 0 4321\n").unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 3 alpha\n", line);
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 4 alpha\n", line);
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 5 alpha\n", line);

            stream.write_all(
                b"18 3 alpha 010203 MYSELF port 655 0 0 0 0 0 12 alpha alpha 0 1500 1400 1518 0 -1 1 2 3 4\n\
18 3\n\
18 4 alpha beta host port 655 local port 655 0 10\n\
18 4\n\
18 5 10.0.0.0/24#10 alpha\n\
18 5\n",
            )
            .unwrap();
        });

        let output = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "--pidfile",
            pidfile.to_str().unwrap(),
            "info",
            "alpha",
        ]))
        .unwrap();

        let CliAction::Exit { code, output } = output else {
            panic!("expected info to exit");
        };
        assert_eq!(0, code);
        assert!(output.contains("Node:         alpha\n"));
        assert!(output.contains("Reachability: can reach itself\n"));
        assert!(output.contains("Edges:        beta\n"));
        assert!(output.contains("Subnets:      10.0.0.0/24\n"));

        handle.join().unwrap();
        fs::remove_dir_all(confbase).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn log_uses_control_socket_and_reads_length_prefixed_messages() {
        tinc_test_support::assert_can_create_netns();
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let confbase = temp_confbase("control-log");
        let pidfile = confbase.join("test.pid");
        let socket = confbase.join("test.socket");
        fs::write(&pidfile, "4321 abcdef localhost port 12345\n").unwrap();

        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(confbase).unwrap();
                return;
            }
            Err(error) => panic!("failed to bind test Unix socket: {error}"),
        };
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!("0 ^abcdef 0\n", line);
            stream.write_all(b"0 tinc 17.0\n4 0 4321\n").unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 15 5 0\n", line);
            stream.write_all(b"18 15 5\nfirst18 15 6\nsecond").unwrap();
        });

        assert_eq!(
            CliAction::Exit {
                code: 0,
                output: "first\nsecond\n".to_owned()
            },
            run(args(&[
                "tinc",
                "--config",
                confbase.to_str().unwrap(),
                "--pidfile",
                pidfile.to_str().unwrap(),
                "log",
                "5extra",
            ]))
            .unwrap()
        );

        handle.join().unwrap();
        fs::remove_dir_all(confbase).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pcap_uses_control_socket_and_writes_pcap_records() {
        tinc_test_support::assert_can_create_netns();
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let confbase = temp_confbase("control-pcap");
        let pidfile = confbase.join("test.pid");
        let socket = confbase.join("test.socket");
        fs::write(&pidfile, "4321 abcdef localhost port 12345\n").unwrap();

        let listener = match UnixListener::bind(&socket) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                fs::remove_dir_all(confbase).unwrap();
                return;
            }
            Err(error) => panic!("failed to bind test Unix socket: {error}"),
        };
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();

            reader.read_line(&mut line).unwrap();
            assert_eq!("0 ^abcdef 0\n", line);
            stream.write_all(b"0 tinc 17.0\n4 0 4321\n").unwrap();

            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!("18 14 64\n", line);
            stream.write_all(b"18 14 3\nabc18 14 2\nde").unwrap();
        });

        let action = run(args(&[
            "tinc",
            "--config",
            confbase.to_str().unwrap(),
            "--pidfile",
            pidfile.to_str().unwrap(),
            "pcap",
            "64",
        ]))
        .unwrap();
        let CliAction::ExitBytes { code, output } = action else {
            panic!("expected pcap bytes");
        };

        assert_eq!(0, code);
        assert_eq!(24 + 16 + 3 + 16 + 2, output.len());
        assert_eq!(&0xa1b2c3d4u32.to_ne_bytes(), &output[0..4]);
        assert_eq!(&2u16.to_ne_bytes(), &output[4..6]);
        assert_eq!(&4u16.to_ne_bytes(), &output[6..8]);
        assert_eq!(&64u32.to_ne_bytes(), &output[16..20]);
        assert_eq!(&1u32.to_ne_bytes(), &output[20..24]);
        assert_eq!(&3u32.to_ne_bytes(), &output[32..36]);
        assert_eq!(&3u32.to_ne_bytes(), &output[36..40]);
        assert_eq!(b"abc", &output[40..43]);
        assert_eq!(&2u32.to_ne_bytes(), &output[51..55]);
        assert_eq!(&2u32.to_ne_bytes(), &output[55..59]);
        assert_eq!(b"de", &output[59..61]);

        handle.join().unwrap();
        fs::remove_dir_all(confbase).unwrap();
    }
}
