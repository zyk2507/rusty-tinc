// SPDX-License-Identifier: GPL-2.0-or-later

mod prelude;

mod cli;
mod constants;
mod control;
mod device;
mod event_loop;
mod listeners;
mod logging;
mod meta;
mod platform;
mod runtime_config;
mod server;
mod state;
#[cfg(test)]
mod tests;
mod transport;
mod upnp;

pub use cli::{
    CliAction, ParsedCommand, RuntimeKeys, RuntimeRsaPrivateKey, TincdError, TincdOptions,
    load_runtime_config, load_runtime_keys, parse_args, resolve_confbase, run,
};
pub use constants::DEFAULT_CONFDIR;
pub use control::{
    ControlEndpoint, TINC_CTL_VERSION_CURRENT, control_socket_path, remove_control_files,
    resolve_pidfile, write_control_pidfile,
};
pub use listeners::bind_runtime_listeners;
pub use meta::RuntimeMetaConnectionInfo;
pub use server::{
    bind_control_socket, handle_control_request_line, handle_control_stream,
    handle_control_tcp_stream, notify_umbilical_success, run_control_server, run_daemon_server,
    run_foreground_server, run_tcp_control_server,
};
pub use state::{RuntimeDaemonState, RuntimeListenSocketInfo};
pub use transport::RuntimeListenSocket;

pub(crate) use cli::*;
pub(crate) use constants::*;
pub(crate) use control::*;
pub(crate) use device::*;
pub(crate) use event_loop::*;
pub(crate) use listeners::*;
pub(crate) use logging::*;
pub(crate) use meta::*;
pub(crate) use platform::*;
pub(crate) use prelude::*;
pub(crate) use runtime_config::*;
pub(crate) use server::*;
pub(crate) use state::*;
pub(crate) use transport::*;
pub(crate) use upnp::*;
