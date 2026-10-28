use anyhow::{Result, bail};
use silo_agent::protocol::{Reply, Request};

use crate::args::ConnectionsCommand;
use crate::commands::{connected, unexpected};

pub fn connections(command: Option<ConnectionsCommand>) -> Result<()> {
    let mut agent = connected()?;
    match command.unwrap_or(ConnectionsCommand::List) {
        ConnectionsCommand::List => {
            let Reply::Connections(peers) = agent.call(&Request::Connections)? else {
                bail!("unexpected connections reply");
            };
            for peer in peers {
                println!(
                    "{}  {:?}{}",
                    peer.username,
                    peer.state,
                    peer.identity
                        .map(|i| format!("  {}", i.fingerprint()))
                        .unwrap_or_default()
                );
            }
        }
        ConnectionsCommand::Request { username } => {
            match agent.call(&Request::Connect { username })? {
                Reply::Connection(peer) => {
                    println!("{}: {:?}", peer.username, peer.state);
                    if let Some(identity) = peer.identity {
                        println!("Fingerprint: {}", identity.fingerprint());
                        println!(
                            "Compare with your teammate's `silo status`, then use `silo connections verify` on both machines."
                        );
                    }
                }
                other => return Err(unexpected(other)),
            }
        }
        ConnectionsCommand::Verify {
            username,
            fingerprint,
        } => {
            agent.call(&Request::VerifyPeer {
                username: username.clone(),
                fingerprint,
            })?;
            println!("Verified {username}. Run `silo sync` to receive their shared secrets.");
        }
        ConnectionsCommand::Remove { username } => {
            agent.call(&Request::Disconnect {
                username: username.clone(),
            })?;
            println!(
                "Disconnected {username}. Existing grants remain; use `silo share <secret> {username} --revoke` to revoke them."
            );
        }
    }
    Ok(())
}

pub fn share(selector: String, usernames: Vec<String>, revoke: bool) -> Result<()> {
    let names = usernames.join(", ");
    let request = if let [username] = usernames.as_slice() {
        Request::Share {
            selector,
            username: username.clone(),
            revoke,
        }
    } else {
        Request::ShareMany {
            selector,
            usernames,
            revoke,
        }
    };
    let reply = connected()?.call(&request)?;
    let Reply::Shared(secret) = reply else {
        return Err(unexpected(reply));
    };
    if revoke {
        println!(
            "Revoked future access to {} for {names} (revision {}).",
            secret.path(),
            secret.revision
        );
        println!(
            "Previously downloaded copies remain readable. Rotate the underlying credentials if necessary."
        );
    } else {
        println!(
            "Shared {} read-only with {names} (id {}; revision {}).",
            secret.path(),
            secret.id,
            secret.revision
        );
    }
    Ok(())
}
