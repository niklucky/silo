//! `silo sync`: set up, run and inspect sync with a silo-server. The agent
//! does the work; this prompts and prints.

use std::time::Duration;

use anyhow::{Result, bail};
use silo_agent::protocol::{Reply, Request, SyncStatusInfo};
use silo_agent::sync::SyncReport;
use silo_agent::{Client, Paths, Store};
use zeroize::Zeroize;

use crate::args::SyncCommand;
use crate::commands::{connected, ensure_agent, unexpected};
use crate::{format, prompt};

pub fn run(command: Option<SyncCommand>) -> Result<()> {
    match command {
        None => sync_now(&mut connected()?),
        Some(SyncCommand::Register {
            server,
            username,
            invite,
            device,
        }) => register(server, username, invite, device),
        Some(SyncCommand::Login {
            server,
            username,
            device,
        }) => login(server, username, device),
        Some(SyncCommand::Status { json }) => status(json),
        Some(SyncCommand::Devices { revoke }) => devices(revoke),
        Some(SyncCommand::Logout) => logout(),
    }
}

fn register(
    server: String,
    username: String,
    invite: String,
    device: Option<String>,
) -> Result<()> {
    let paths = Paths::from_env()?;
    if !paths.account_file().is_file() {
        bail!(
            "no account in {}; run `silo init` first, or `silo sync login` to use an existing account",
            paths.home().display()
        );
    }
    let mut agent = ensure_agent(&paths)?;
    let password = prompt::password("Master password")?;
    let mut request = Request::SyncRegister {
        server,
        username,
        invite,
        password: password.to_string(),
        device_name: device,
    };
    let reply = agent.call(&request);
    if let Request::SyncRegister { password, .. } = &mut request {
        password.zeroize();
    }
    let Reply::SyncStatus(Some(info)) = reply? else {
        bail!("the agent did not set up sync");
    };
    println!(
        "Registered {} on {} (this device: {}).",
        info.username, info.server, info.device_id
    );
    sync_now(&mut agent)
}

fn login(server: String, username: String, device: Option<String>) -> Result<()> {
    let paths = Paths::from_env()?;
    // A new machine has no data directory yet; the agent and its log need one.
    Store::open(paths.clone())?;
    let mut agent = ensure_agent(&paths)?;
    let password = prompt::password("Master password")?;
    let mut request = Request::SyncLogin {
        server,
        username,
        password: password.to_string(),
        device_name: device,
    };
    let reply = agent.call(&request);
    if let Request::SyncLogin { password, .. } = &mut request {
        password.zeroize();
    }
    let Reply::SyncStatus(Some(info)) = reply? else {
        bail!("the agent did not set up sync");
    };
    println!(
        "Logged in as {} on {} (this device: {}).",
        info.username, info.server, info.device_id
    );
    if let Reply::Status(status) = agent.call(&Request::Status)? {
        println!(
            "Fingerprint: {}  (should match `silo status` on your other devices)",
            status.fingerprint.as_deref().unwrap_or("?")
        );
    }
    sync_now(&mut agent)
}

fn sync_now(agent: &mut Client) -> Result<()> {
    let report = match agent.call(&Request::Sync)? {
        Reply::Synced(report) => report,
        other => return Err(unexpected(other)),
    };
    print_report(&report);
    Ok(())
}

fn print_report(report: &SyncReport) {
    if report.pulled + report.removed + report.pushed == 0
        && report.conflicts.is_empty()
        && report.rejected.is_empty()
    {
        println!("Up to date.");
    } else {
        println!(
            "Synced: {} received, {} removed, {} sent.",
            report.pulled, report.removed, report.pushed
        );
    }
    if !report.conflicts.is_empty() {
        println!("Conflicts (see `silo history <secret>`):");
        for line in &report.conflicts {
            println!("  {line}");
        }
    }
    if !report.rejected.is_empty() {
        println!("Refused by the server:");
        for line in &report.rejected {
            println!("  {line}");
        }
    }
    if report.skipped > 0 {
        println!(
            "Ignored {} change(s) from the server not signed by this account.",
            report.skipped
        );
    }
}

fn sync_status(agent: &mut Client) -> Result<Option<SyncStatusInfo>> {
    match agent.call(&Request::SyncStatus)? {
        Reply::SyncStatus(info) => Ok(info),
        other => Err(unexpected(other)),
    }
}

/// One line for `silo status`.
pub fn summary_line(agent: &mut Client) -> Result<String> {
    Ok(match sync_status(agent)? {
        None => "not set up (`silo sync login` or `silo sync register`)".to_owned(),
        Some(info) => {
            let mut line = format!("{} as {}", info.server, info.username);
            match (&info.last_error, info.last_sync) {
                (Some(err), _) => line.push_str(&format!(", last attempt failed: {err}")),
                (None, Some(at)) => line.push_str(&format!(", synced {}", ago(at))),
                (None, None) => line.push_str(", not synced yet"),
            }
            if let Some(pending) = info.pending.filter(|p| *p > 0) {
                line.push_str(&format!(", {pending} change(s) to send"));
            }
            line
        }
    })
}

fn status(json: bool) -> Result<()> {
    let info = sync_status(&mut connected()?)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }
    let Some(info) = info else {
        println!("Sync is not set up. Use `silo sync login` or `silo sync register`.");
        return Ok(());
    };
    println!("Server:    {}", info.server);
    println!("Account:   {}", info.username);
    println!("Device:    {}", info.device_id);
    println!(
        "Last sync: {}",
        info.last_sync.map_or("never".to_owned(), |at| format!(
            "{} ({})",
            format::timestamp(at),
            ago(at)
        ))
    );
    match info.pending {
        Some(pending) => println!("To send:   {pending}"),
        None => println!("To send:   unknown while locked"),
    }
    if let Some(err) = &info.last_error {
        println!("Error:     {err}");
    }
    for line in &info.rejected {
        println!("Refused:   {line}");
    }
    Ok(())
}

fn devices(revoke: Option<String>) -> Result<()> {
    let mut agent = connected()?;
    if let Some(device_id) = revoke {
        agent.call(&Request::SyncRevokeDevice {
            device_id: device_id.clone(),
        })?;
        println!("Revoked {device_id}; it can no longer sync.");
        return Ok(());
    }
    let devices = match agent.call(&Request::SyncDevices)? {
        Reply::Devices(devices) => devices,
        other => return Err(unexpected(other)),
    };
    let rows: Vec<Vec<String>> = devices
        .iter()
        .map(|d| {
            vec![
                d.id.clone(),
                if d.current {
                    format!("{} (this one)", d.name)
                } else {
                    d.name.clone()
                },
                format::timestamp(d.created_at),
                ago(d.last_seen_at),
            ]
        })
        .collect();
    println!(
        "{}",
        format::table(&["ID", "NAME", "ADDED", "LAST SEEN"], &rows)
    );
    Ok(())
}

fn logout() -> Result<()> {
    let mut agent = connected()?;
    match agent.call(&Request::SyncLogout)? {
        Reply::LoggedOut { revoked: true } => {
            println!("Logged out; this device is revoked. The local vault stays.");
        }
        Reply::LoggedOut { revoked: false } => println!(
            "Stopped syncing, but the server could not be reached to revoke this device. \
             Revoke it from another device with `silo sync devices --revoke`."
        ),
        other => return Err(unexpected(other)),
    }
    Ok(())
}

fn ago(unix_secs: u64) -> String {
    let now = silo_agent::unix_now();
    if unix_secs >= now {
        return "just now".to_owned();
    }
    let elapsed = Duration::from_secs(now - unix_secs);
    if elapsed < Duration::from_secs(60) {
        "just now".to_owned()
    } else {
        format!("{} ago", format::duration(elapsed))
    }
}
