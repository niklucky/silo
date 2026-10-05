use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "secret",
    version,
    about = "Secrets manager for people and projects"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print CLI and core versions
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("secret {}", env!("CARGO_PKG_VERSION"));
            println!("core   {}", secret_core::version());
        }
    }
}
