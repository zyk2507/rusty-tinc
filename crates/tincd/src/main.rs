// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::ExitCode;

use tincd::{CliAction, run};

fn main() -> ExitCode {
    match run(std::env::args().collect()) {
        Ok(CliAction::Exit { code, output }) => {
            print!("{output}");
            ExitCode::from(code)
        }
        Ok(CliAction::Loaded(config)) => {
            println!(
                "Loaded tinc network `{}`: {} ConnectTo entries, {} local subnets",
                config.name,
                config.connect_to.len(),
                config.state.subnets.owner_subnets(&config.name).count()
            );
            ExitCode::SUCCESS
        }
        Ok(CliAction::RunForeground {
            options,
            config,
            control,
            keys,
        }) => {
            println!(
                "Loaded tinc network `{}`: {} ConnectTo entries, {} local subnets",
                config.name,
                config.connect_to.len(),
                config.state.subnets.owner_subnets(&config.name).count()
            );

            match tincd::run_foreground_server(&config, &control, keys, &options) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("{error}");
                    ExitCode::FAILURE
                }
            }
        }
        Ok(CliAction::RunDaemon {
            options,
            config,
            control,
            keys,
        }) => match tincd::run_daemon_server(&config, &control, keys, &options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
