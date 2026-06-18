// SPDX-License-Identifier: GPL-2.0-or-later

use std::process::ExitCode;

use std::io::Write;

use tincctl::{CliAction, run_with_stdio};

fn main() -> ExitCode {
    let args = std::env::args().collect::<Vec<_>>();

    match run_with_stdio(args) {
        Ok(CliAction::Exit { code, output }) => {
            print!("{output}");
            ExitCode::from(code)
        }
        Ok(CliAction::ExitBytes { code, output }) => {
            if let Err(error) = std::io::stdout().write_all(&output) {
                eprintln!("stdout: {error}");
                return ExitCode::FAILURE;
            }

            ExitCode::from(code)
        }
        Ok(CliAction::Command(command)) => {
            eprintln!("command `{}` is not implemented yet", command.name);
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
