//! `secret`: thin client over the local agent. Everything that touches keys
//! happens in `secret-agent`; this binary parses arguments, prompts, and prints.

mod args;
mod browser;
mod commands;
mod edit;
mod format;
mod generate;
mod import;
mod prompt;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = args::Cli::parse();
    match commands::run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
