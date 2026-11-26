use anyhow::{Context, Result, anyhow, bail};
use silo_agent::Paths;
use silo_agent::protocol::{Reply, Request, TokenAction, TokenScope};
use silo_agent::sync::HttpClient;
use silo_core::access::AccessToken;
use silo_core::vault::EnvSet;
use zeroize::Zeroizing;

use crate::args::TokenCommand;
use crate::commands::{connected, read_admin_token};

pub fn manage(command: TokenCommand) -> Result<()> {
    let action = match command {
        TokenCommand::Create {
            name,
            env_set,
            folder,
        } => {
            let scope = match (env_set, folder) {
                (Some(selector), None) => TokenScope::EnvSet(selector),
                (None, Some(folder)) => TokenScope::Folder(folder),
                _ => bail!("choose one scope with --env-set or --folder"),
            };
            TokenAction::Create { name, scope }
        }
        TokenCommand::List => TokenAction::List,
        TokenCommand::Rotate { name } => TokenAction::Rotate { name },
        TokenCommand::Revoke { name } => TokenAction::Revoke { name },
    };
    let mut agent = connected()?;
    let token = read_admin_token(&Paths::from_env()?)?;
    match agent.call(&Request::ManageToken { token, action })? {
        Reply::TokenIssued(value) => println!("{}", value.as_str()),
        Reply::TokenRevoked => println!("Token revoked."),
        Reply::Tokens(tokens) => {
            for (name, paths) in tokens {
                println!("{name}\t{}", paths.join(", "));
            }
        }
        _ => bail!("unexpected response to token management request"),
    }
    Ok(())
}

pub fn fetch(variable: &str) -> Result<EnvSet> {
    let encoded = Zeroizing::new(std::env::var(variable).map_err(|_| {
        anyhow!("set {variable} to a Silo access token, or supply a local env-set selector")
    })?);
    let token = AccessToken::parse(&encoded)?;
    let server = std::env::var("SILO_SERVER").context("set SILO_SERVER to the Silo server URL")?;
    let bundle = HttpClient::new(&server)?
        .with_token(&token.bearer())
        .fetch_env()?;
    Ok(token.open(bundle)?)
}
