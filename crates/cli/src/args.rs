use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use secret_core::vault::SecretKind;

use crate::browser::Browser;

#[derive(Parser)]
#[command(
    name = "secret",
    version,
    about = "Secrets manager for people and projects"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create an account in SECRET_HOME (default ~/.secret) and unlock it
    Init,
    /// Unlock the vault, starting the agent if needed
    Unlock {
        /// How long to stay unlocked, e.g. 8h or 30m (default 12h)
        #[arg(long, value_parser = humantime::parse_duration)]
        ttl: Option<Duration>,
    },
    /// Make the agent forget the keys
    Lock,
    /// Show agent and vault status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Control the background agent
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// List secrets, optionally under a folder
    Ls {
        folder: Option<String>,
        /// Only this folder, not its subfolders
        #[arg(long)]
        exact: bool,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, value_enum)]
        kind: Option<KindArg>,
        #[arg(long)]
        json: bool,
    },
    /// Add a secret
    Add {
        #[command(subcommand)]
        command: AddCommand,
    },
    /// Show a secret. SELECTOR is an id, a folder/title path, or a unique title
    Get {
        selector: String,
        /// Print one field only (login: username, password, totp, notes; env: a variable name)
        #[arg(long, short)]
        field: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Remove a secret
    Rm {
        selector: String,
        /// Do not ask for confirmation
        #[arg(long, short)]
        yes: bool,
    },
    /// Run a command with one or more env sets injected: secret run api/dev -- npm start
    Run {
        #[arg(required = true)]
        selectors: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Print an env set as dotenv, shell exports or JSON
    Export {
        selector: String,
        #[arg(long, value_enum, default_value_t = ExportFormat::Dotenv)]
        format: ExportFormat,
    },
    /// Work with secret files
    File {
        #[command(subcommand)]
        command: FileCommand,
    },
    /// Show logins whose URL patterns cover URL, best match first
    Match {
        url: String,
        #[arg(long)]
        json: bool,
    },
    /// Connect browsers to the agent through native messaging
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
}

#[derive(Subcommand)]
pub enum BrowserCommand {
    /// Write native messaging manifests for the browsers found on this machine
    Install {
        /// Configure only these browsers (default: every supported browser found)
        #[arg(long, value_enum)]
        browser: Vec<Browser>,
        /// Also allow this extension id, e.g. an unpacked build without a pinned id
        #[arg(long = "extension-id")]
        extension_id: Vec<String>,
        /// Write into this directory instead of the browser's known location (needs one --browser)
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Remove the manifests written by install
    Uninstall {
        #[arg(long, value_enum)]
        browser: Vec<Browser>,
    },
    /// Show which browsers are connected
    Status,
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Run the agent in the foreground (what `secret unlock` spawns detached)
    Run,
    /// Stop the running agent
    Stop,
}

#[derive(Subcommand)]
pub enum AddCommand {
    /// Website login. PATH is folder/title, e.g. work/github
    Login {
        path: String,
        #[arg(long, short)]
        username: String,
        /// Prompted if omitted
        #[arg(long, short)]
        password: Option<String>,
        #[arg(long)]
        url: Vec<String>,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Environment variable set from KEY=VALUE arguments and/or a dotenv file
    Env {
        path: String,
        vars: Vec<String>,
        #[arg(long)]
        from_file: Option<PathBuf>,
        #[arg(long)]
        tag: Vec<String>,
    },
    /// A file, stored encrypted
    File {
        path: String,
        file: PathBuf,
        #[arg(long)]
        tag: Vec<String>,
    },
    /// Free-form text; read from stdin if --text is omitted
    Note {
        path: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        tag: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum FileCommand {
    /// Write a secret file to disk
    Pull {
        selector: String,
        /// Output path (default: the stored file name in the current directory)
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long, short)]
        force: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KindArg {
    Login,
    Card,
    Env,
    File,
    Note,
}

impl From<KindArg> for SecretKind {
    fn from(kind: KindArg) -> Self {
        match kind {
            KindArg::Login => Self::Login,
            KindArg::Card => Self::Card,
            KindArg::Env => Self::EnvSet,
            KindArg::File => Self::File,
            KindArg::Note => Self::Note,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Dotenv,
    Shell,
    Json,
}
