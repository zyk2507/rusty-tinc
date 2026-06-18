// SPDX-License-Identifier: GPL-2.0-or-later

use std::cmp::Ordering;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::utils::check_id;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigSource {
    pub file: Option<String>,
    pub line: i32,
}

impl ConfigSource {
    pub fn file(file: impl Into<String>, line: i32) -> Self {
        Self {
            file: Some(file.into()),
            line,
        }
    }

    pub const fn command_line(line: i32) -> Self {
        Self { file: None, line }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub variable: String,
    pub value: String,
    pub source: ConfigSource,
}

impl Config {
    pub fn new(
        variable: impl Into<String>,
        value: impl Into<String>,
        source: ConfigSource,
    ) -> Self {
        Self {
            variable: variable.into(),
            value: value.into(),
            source,
        }
    }

    pub fn as_bool(&self) -> Result<bool, ConfigValueError> {
        if self.value.eq_ignore_ascii_case("yes") {
            Ok(true)
        } else if self.value.eq_ignore_ascii_case("no") {
            Ok(false)
        } else {
            Err(ConfigValueError::Bool {
                variable: self.variable.clone(),
            })
        }
    }

    pub fn as_i32(&self) -> Result<i32, ConfigValueError> {
        parse_c_i32_prefix(&self.value).ok_or_else(|| ConfigValueError::Integer {
            variable: self.variable.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigParseError {
    MissingValue {
        variable: String,
        file: Option<String>,
        line: i32,
    },
}

impl fmt::Display for ConfigParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue {
                variable,
                file,
                line,
            } => match file {
                Some(file) => write!(
                    f,
                    "no value for variable `{variable}` on line {line} while reading config file {file}"
                ),
                None => write!(
                    f,
                    "no value for variable `{variable}` in command line option {line}"
                ),
            },
        }
    }
}

impl std::error::Error for ConfigParseError {}

#[derive(Debug)]
pub enum ConfigLoadError {
    Io { path: PathBuf, error: io::Error },
    Parse(ConfigParseError),
}

impl Clone for ConfigLoadError {
    fn clone(&self) -> Self {
        match self {
            Self::Io { path, error } => Self::Io {
                path: path.clone(),
                error: io::Error::new(error.kind(), error.to_string()),
            },
            Self::Parse(error) => Self::Parse(error.clone()),
        }
    }
}

impl PartialEq for ConfigLoadError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Io {
                    path: left_path,
                    error: left_error,
                },
                Self::Io {
                    path: right_path,
                    error: right_error,
                },
            ) => {
                left_path == right_path
                    && left_error.kind() == right_error.kind()
                    && left_error.to_string() == right_error.to_string()
            }
            (Self::Parse(left), Self::Parse(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for ConfigLoadError {}

impl fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, error } => {
                write!(f, "cannot read config file {}: {error}", path.display())
            }
            Self::Parse(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::Parse(error) => Some(error),
        }
    }
}

impl From<ConfigParseError> for ConfigLoadError {
    fn from(error: ConfigParseError) -> Self {
        Self::Parse(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigValueError {
    Bool { variable: String },
    Integer { variable: String },
}

impl fmt::Display for ConfigValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool { variable } => {
                write!(
                    f,
                    "\"yes\" or \"no\" expected for configuration variable {variable}"
                )
            }
            Self::Integer { variable } => {
                write!(f, "integer expected for configuration variable {variable}")
            }
        }
    }
}

impl std::error::Error for ConfigValueError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigTree {
    entries: Vec<Config>,
}

impl ConfigTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Config> {
        self.entries.iter()
    }

    pub fn add(&mut self, config: Config) {
        self.entries.push(config);
        self.entries.sort_by(compare_config);
    }

    pub fn lookup(&self, variable: &str) -> Option<&Config> {
        self.entries
            .iter()
            .find(|config| config.variable.eq_ignore_ascii_case(variable))
    }

    pub fn lookup_all<'a>(&'a self, variable: &'a str) -> impl Iterator<Item = &'a Config> + 'a {
        self.entries
            .iter()
            .filter(move |config| config.variable.eq_ignore_ascii_case(variable))
    }

    pub fn extend_from_file(
        &mut self,
        contents: &str,
        file: impl Into<String>,
    ) -> Result<(), ConfigParseError> {
        let parsed = parse_config_file(contents, file)?;

        for config in parsed {
            self.add(config);
        }

        Ok(())
    }

    pub fn extend_from_path(&mut self, path: impl AsRef<Path>) -> Result<(), ConfigLoadError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|error| ConfigLoadError::Io {
            path: path.to_path_buf(),
            error,
        })?;

        self.extend_from_file(&contents, path.to_string_lossy())
            .map_err(Into::into)
    }

    pub fn apply_command_line_options<'a>(
        &mut self,
        options: impl IntoIterator<Item = &'a Config>,
        prefix: Option<&str>,
    ) {
        let prefix_len = prefix.map(str::len).unwrap_or_default();
        let mut selected = options
            .into_iter()
            .filter_map(|config| {
                let variable = match prefix {
                    Some(prefix) => config
                        .variable
                        .strip_prefix(prefix)
                        .and_then(|rest| rest.strip_prefix('.'))?,
                    None => {
                        if config.variable.contains('.') {
                            return None;
                        }

                        config.variable.as_str()
                    }
                };

                let _ = prefix_len;

                Some(Config::new(
                    variable,
                    &config.value,
                    ConfigSource::command_line(config.source.line),
                ))
            })
            .collect::<Vec<_>>();

        selected.reverse();

        for config in selected {
            self.add(config);
        }
    }

    pub fn read_server_config<'a>(
        &mut self,
        confbase: impl AsRef<Path>,
        command_line_options: impl IntoIterator<Item = &'a Config>,
    ) -> Result<(), ConfigLoadError> {
        let confbase = confbase.as_ref();

        self.apply_command_line_options(command_line_options, None);
        self.extend_from_path(confbase.join("tinc.conf"))?;
        self.extend_from_conf_dir(confbase.join("conf.d"))?;

        Ok(())
    }

    pub fn read_host_config<'a>(
        &mut self,
        confbase: impl AsRef<Path>,
        name: &str,
        command_line_options: impl IntoIterator<Item = &'a Config>,
    ) -> Result<(), ConfigLoadError> {
        self.apply_command_line_options(command_line_options, Some(name));
        self.extend_from_path(confbase.as_ref().join("hosts").join(name))
    }

    pub fn read_all_host_configs<'a>(
        confbase: impl AsRef<Path>,
        command_line_options: impl IntoIterator<Item = &'a Config>,
    ) -> Result<Vec<(String, ConfigTree)>, ConfigLoadError> {
        let confbase = confbase.as_ref();
        let command_line_options = command_line_options
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let hosts_dir = confbase.join("hosts");
        let mut host_names = Vec::new();

        for entry in fs::read_dir(&hosts_dir).map_err(|error| ConfigLoadError::Io {
            path: hosts_dir.clone(),
            error,
        })? {
            let entry = entry.map_err(|error| ConfigLoadError::Io {
                path: hosts_dir.clone(),
                error,
            })?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };

            if check_id(name) {
                host_names.push(name.to_owned());
            }
        }

        host_names.sort();

        let mut hosts = Vec::with_capacity(host_names.len());

        for name in host_names {
            let mut tree = ConfigTree::new();
            tree.read_host_config(confbase, &name, &command_line_options)?;
            hosts.push((name, tree));
        }

        Ok(hosts)
    }

    fn extend_from_conf_dir(&mut self, path: PathBuf) -> Result<(), ConfigLoadError> {
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(ConfigLoadError::Io { path, error }),
        };

        let mut files = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|error| ConfigLoadError::Io {
                path: path.clone(),
                error,
            })?;
            let entry_path = entry.path();

            if entry_path
                .extension()
                .is_some_and(|extension| extension == "conf")
            {
                files.push(entry_path);
            }
        }

        files.sort();

        for file in files {
            self.extend_from_path(file)?;
        }

        Ok(())
    }
}

pub fn parse_config_line(
    line: &str,
    file: Option<&str>,
    line_number: i32,
) -> Result<Config, ConfigParseError> {
    let trimmed = line.trim_end_matches(['\t', ' ']);
    let variable_len = trimmed.find(['\t', ' ', '=']).unwrap_or(trimmed.len());

    let variable = &trimmed[..variable_len];
    let mut value = &trimmed[variable_len..];
    value = value.trim_start_matches(['\t', ' ']);

    if let Some(rest) = value.strip_prefix('=') {
        value = rest.trim_start_matches(['\t', ' ']);
    }

    if value.is_empty() {
        return Err(ConfigParseError::MissingValue {
            variable: variable.to_owned(),
            file: file.map(ToOwned::to_owned),
            line: line_number,
        });
    }

    Ok(Config::new(
        variable,
        value,
        match file {
            Some(file) => ConfigSource::file(file, line_number),
            None => ConfigSource::command_line(line_number),
        },
    ))
}

pub fn parse_config_file(
    contents: &str,
    file: impl Into<String>,
) -> Result<Vec<Config>, ConfigParseError> {
    let file = file.into();
    let mut ignore_pem = false;
    let mut configs = Vec::new();

    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = i32::try_from(index + 1).unwrap_or(i32::MAX);
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if ignore_pem {
            if line.starts_with("-----END") {
                ignore_pem = false;
            }

            continue;
        }

        if line.starts_with("-----BEGIN") {
            ignore_pem = true;
            continue;
        }

        configs.push(parse_config_line(line, Some(&file), line_number)?);
    }

    Ok(configs)
}

pub fn compare_config(a: &Config, b: &Config) -> Ordering {
    let result = compare_case_insensitive(&a.variable, &b.variable);

    if result != Ordering::Equal {
        return result;
    }

    let result = match (&a.source.file, &b.source.file) {
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        _ => Ordering::Equal,
    };

    if result != Ordering::Equal {
        return result;
    }

    let result = a.source.line.cmp(&b.source.line);

    if result != Ordering::Equal {
        return result;
    }

    match (&a.source.file, &b.source.file) {
        (Some(a), Some(b)) => a.cmp(b),
        _ => Ordering::Equal,
    }
}

fn compare_case_insensitive(a: &str, b: &str) -> Ordering {
    a.bytes()
        .map(|byte| byte.to_ascii_lowercase())
        .cmp(b.bytes().map(|byte| byte.to_ascii_lowercase()))
}

fn parse_c_i32_prefix(input: &str) -> Option<i32> {
    let bytes = input.as_bytes();
    let mut index = 0;

    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }

    let negative = match bytes.get(index) {
        Some(b'-') => {
            index += 1;
            true
        }
        Some(b'+') => {
            index += 1;
            false
        }
        _ => false,
    };

    let digit_start = index;
    let mut number = 0i64;

    while index < bytes.len() && bytes[index].is_ascii_digit() {
        number = number
            .saturating_mul(10)
            .saturating_add((bytes[index] - b'0') as i64);
        index += 1;
    }

    if digit_start == index {
        return None;
    }

    if negative {
        number = -number;
    }

    Some(number.clamp(i32::MIN as i64, i32::MAX as i64) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_confbase(test_name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "tinc-core-config-{test_name}-{}-{nonce}",
            std::process::id()
        ));

        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn parse_config_line_accepts_optional_equals_and_spaces() {
        tinc_test_support::assert_can_create_netns();
        let with_equals = parse_config_line("Name = alpha", Some("tinc.conf"), 7).unwrap();
        assert_eq!("Name", with_equals.variable);
        assert_eq!("alpha", with_equals.value);
        assert_eq!(Some("tinc.conf"), with_equals.source.file.as_deref());
        assert_eq!(7, with_equals.source.line);

        let without_equals = parse_config_line("ConnectTo beta\t ", Some("tinc.conf"), 8).unwrap();
        assert_eq!("ConnectTo", without_equals.variable);
        assert_eq!("beta", without_equals.value);

        let tight = parse_config_line("Device=/dev/net/tun", None, 2).unwrap();
        assert_eq!("Device", tight.variable);
        assert_eq!("/dev/net/tun", tight.value);
        assert_eq!(None, tight.source.file);
    }

    #[test]
    fn parse_config_line_requires_a_value() {
        tinc_test_support::assert_can_create_netns();
        assert_eq!(
            Err(ConfigParseError::MissingValue {
                variable: "Name".to_owned(),
                file: Some("tinc.conf".to_owned()),
                line: 2,
            }),
            parse_config_line("Name =   ", Some("tinc.conf"), 2)
        );
    }

    #[test]
    fn parse_config_file_skips_comments_empty_lines_and_pem_blocks() {
        tinc_test_support::assert_can_create_netns();
        let contents = "\
# comment
Name = alpha

-----BEGIN RSA PUBLIC KEY-----
ignored = yes
-----END RSA PUBLIC KEY-----
ConnectTo beta
";
        let configs = parse_config_file(contents, "tinc.conf").unwrap();

        assert_eq!(2, configs.len());
        assert_eq!("Name", configs[0].variable);
        assert_eq!("alpha", configs[0].value);
        assert_eq!(2, configs[0].source.line);
        assert_eq!("ConnectTo", configs[1].variable);
        assert_eq!("beta", configs[1].value);
        assert_eq!(7, configs[1].source.line);
    }

    #[test]
    fn config_values_parse_like_c_helpers() {
        tinc_test_support::assert_can_create_netns();
        assert!(
            Config::new("Experimental", "YES", ConfigSource::command_line(1))
                .as_bool()
                .unwrap()
        );
        assert!(
            !Config::new("Experimental", "no", ConfigSource::command_line(1))
                .as_bool()
                .unwrap()
        );
        assert!(
            Config::new("Experimental", "true", ConfigSource::command_line(1))
                .as_bool()
                .is_err()
        );

        assert_eq!(
            42,
            Config::new("Weight", "42 trailing", ConfigSource::command_line(1))
                .as_i32()
                .unwrap()
        );
        assert_eq!(
            -7,
            Config::new("Weight", " -7", ConfigSource::command_line(1))
                .as_i32()
                .unwrap()
        );
    }

    #[test]
    fn config_tree_lookup_is_case_insensitive_and_prefers_command_line() {
        tinc_test_support::assert_can_create_netns();
        let mut tree = ConfigTree::new();
        tree.add(Config::new(
            "Name",
            "from-file",
            ConfigSource::file("tinc.conf", 3),
        ));
        tree.add(Config::new(
            "name",
            "from-cli",
            ConfigSource::command_line(1),
        ));

        assert_eq!("from-cli", tree.lookup("NAME").unwrap().value);
        assert_eq!(
            vec!["from-cli", "from-file"],
            tree.lookup_all("name")
                .map(|config| config.value.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn command_line_options_can_be_filtered_by_host_prefix() {
        tinc_test_support::assert_can_create_netns();
        let options = [
            Config::new("Name", "alpha", ConfigSource::command_line(1)),
            Config::new("beta.Subnet", "10.0.0.0/8", ConfigSource::command_line(2)),
            Config::new(
                "gamma.Subnet",
                "192.0.2.0/24",
                ConfigSource::command_line(3),
            ),
        ];
        let mut server = ConfigTree::new();
        server.apply_command_line_options(&options, None);

        assert_eq!(1, server.len());
        assert_eq!("Name", server.lookup("name").unwrap().variable);

        let mut host = ConfigTree::new();
        host.apply_command_line_options(&options, Some("beta"));

        assert_eq!(1, host.len());
        let subnet = host.lookup("Subnet").unwrap();
        assert_eq!("Subnet", subnet.variable);
        assert_eq!("10.0.0.0/8", subnet.value);
    }

    #[test]
    fn read_server_config_loads_tinc_conf_and_sorted_conf_d_files() {
        tinc_test_support::assert_can_create_netns();
        let confbase = make_temp_confbase("read-server");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\nPort = 655\n").unwrap();
        fs::create_dir(confbase.join("conf.d")).unwrap();
        fs::write(confbase.join("conf.d").join("z.conf"), "ConnectTo = zed\n").unwrap();
        fs::write(confbase.join("conf.d").join("a.conf"), "ConnectTo = beta\n").unwrap();
        fs::write(
            confbase.join("conf.d").join("ignored.txt"),
            "ConnectTo = ignored\n",
        )
        .unwrap();

        let options = [Config::new("Port", "123", ConfigSource::command_line(1))];
        let mut tree = ConfigTree::new();
        tree.read_server_config(&confbase, &options).unwrap();

        assert_eq!("alpha", tree.lookup("Name").unwrap().value);
        assert_eq!("123", tree.lookup("Port").unwrap().value);
        assert_eq!(
            vec!["beta", "zed"],
            tree.lookup_all("ConnectTo")
                .map(|config| config.value.as_str())
                .collect::<Vec<_>>()
        );

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn read_server_config_accepts_missing_conf_d() {
        tinc_test_support::assert_can_create_netns();
        let confbase = make_temp_confbase("missing-conf-d");
        fs::write(confbase.join("tinc.conf"), "Name = alpha\n").unwrap();

        let mut tree = ConfigTree::new();
        tree.read_server_config(&confbase, []).unwrap();

        assert_eq!("alpha", tree.lookup("Name").unwrap().value);

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn read_host_config_applies_matching_prefixed_command_line_options() {
        tinc_test_support::assert_can_create_netns();
        let confbase = make_temp_confbase("read-host");
        fs::create_dir(confbase.join("hosts")).unwrap();
        fs::write(
            confbase.join("hosts").join("beta"),
            "Address = beta.example\nSubnet = 10.0.0.0/8\n",
        )
        .unwrap();
        let options = [
            Config::new("Name", "alpha", ConfigSource::command_line(1)),
            Config::new("beta.Subnet", "192.0.2.0/24", ConfigSource::command_line(2)),
            Config::new(
                "gamma.Subnet",
                "198.51.100.0/24",
                ConfigSource::command_line(3),
            ),
        ];

        let mut tree = ConfigTree::new();
        tree.read_host_config(&confbase, "beta", &options).unwrap();

        assert_eq!("beta.example", tree.lookup("Address").unwrap().value);
        assert_eq!(
            vec!["192.0.2.0/24", "10.0.0.0/8"],
            tree.lookup_all("Subnet")
                .map(|config| config.value.as_str())
                .collect::<Vec<_>>()
        );
        assert!(tree.lookup("Name").is_none());

        fs::remove_dir_all(confbase).unwrap();
    }

    #[test]
    fn read_all_host_configs_filters_invalid_host_names_and_sorts() {
        tinc_test_support::assert_can_create_netns();
        let confbase = make_temp_confbase("read-all-hosts");
        let hosts = confbase.join("hosts");
        fs::create_dir(&hosts).unwrap();
        fs::write(hosts.join("beta"), "Address = beta.example\n").unwrap();
        fs::write(hosts.join("alpha"), "Address = alpha.example\n").unwrap();
        fs::write(hosts.join("bad-name"), "Address = ignored.example\n").unwrap();
        let options = [Config::new(
            "beta.Subnet",
            "10.0.0.0/8",
            ConfigSource::command_line(1),
        )];

        let configs = ConfigTree::read_all_host_configs(&confbase, &options).unwrap();

        assert_eq!(
            vec!["alpha", "beta"],
            configs
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            "alpha.example",
            configs[0].1.lookup("Address").unwrap().value
        );
        assert_eq!("10.0.0.0/8", configs[1].1.lookup("Subnet").unwrap().value);

        fs::remove_dir_all(confbase).unwrap();
    }
}
