use std::io::{IsTerminal, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use silo_agent::protocol::{ListFilter, NewSecret, Reply, Request, SecretView, StatusInfo};
use silo_agent::{Client, ClientError, Paths, Store, client, server};
use silo_core::AccountRecord;
use silo_core::crypto::KdfParams;
use silo_core::vault::{EnvSet, EnvVar, File, FolderPath, Login, Note, SecretBody, Tag};
use zeroize::Zeroize;

use crate::args::{AddCommand, AgentCommand, Command, ExportFormat, FileCommand, InitArgs};
use crate::{browser, edit, format, import, prompt, sync};

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Init(args) => init(args),
        Command::Unlock { ttl } => unlock(ttl),
        Command::Lock => lock(),
        Command::Status { json } => status(json),
        Command::Agent {
            command: AgentCommand::Run,
        } => agent_run(),
        Command::Agent {
            command: AgentCommand::Stop,
        } => agent_stop(),
        Command::Ls {
            folder,
            exact,
            tag,
            kind,
            json,
        } => ls(folder, exact, tag, kind.map(Into::into), json),
        Command::Add { command } => add(command),
        Command::Get {
            selector,
            field,
            json,
        } => get(&selector, field.as_deref(), json),
        Command::Edit(args) => edit::run(args),
        Command::Restore { selector, revision } => edit::restore(&selector, revision),
        Command::Rm { selector, yes } => rm(&selector, yes),
        Command::Run { selectors, command } => run_with_env(&selectors, &command),
        Command::Export { selector, format } => export(&selector, format),
        Command::File {
            command:
                FileCommand::Pull {
                    selector,
                    output,
                    force,
                },
        } => file_pull(&selector, output, force),
        Command::History {
            selector,
            revision,
            json,
        } => history(&selector, revision, json),
        Command::Import {
            file,
            folder,
            tag,
            replace,
            dry_run,
        } => import::run(&file, &folder, &tag, replace, dry_run),
        Command::Match { url, site, json } => match_url(&url, site, json),
        Command::Browser { command } => browser::run(command),
        Command::Sync { command } => sync::run(command),
    }
}

// ---------- account & agent ----------

fn init(args: InitArgs) -> Result<()> {
    let paths = Paths::from_env()?;
    let store = Store::open(paths.clone())?;
    if store.has_account() {
        bail!("an account already exists in {}", paths.home().display());
    }
    let setup = init_sync_setup(args)?;
    if let Some(InitSync {
        server,
        username,
        invite: None,
    }) = setup
    {
        return sync::login_at(&paths, server, username, None);
    }
    let password = prompt::new_password()?;
    let mut rng = rand::rng();
    let kdf = KdfParams::recommended(&mut rng);
    let (record, keys) = AccountRecord::create(&mut rng, password.as_bytes(), kdf)?;
    store.write_account(&record)?;
    println!("Created account in {}", paths.home().display());
    println!("Fingerprint: {}", keys.fingerprint());

    let mut agent = ensure_agent(&paths)?;
    let status = unlock_with(&mut agent, &password, None)?;
    println!(
        "Unlocked for {}.",
        status
            .expires_in_secs
            .map_or("a while".to_owned(), |s| format::duration(
                Duration::from_secs(s)
            ))
    );
    if let Some(InitSync {
        server,
        username,
        invite: Some(invite),
    }) = setup
    {
        sync::register_with(&mut agent, server, username, invite, &password, None)?;
    }
    Ok(())
}

struct InitSync {
    server: String,
    username: String,
    invite: Option<String>,
}

fn init_sync_setup(args: InitArgs) -> Result<Option<InitSync>> {
    let interactive = args.server.is_none() && std::io::stdin().is_terminal();
    let server = if interactive {
        prompt::line("Sync server URL (Enter to skip)", "")?
    } else {
        args.server
    };
    let Some(server) = server else {
        return Ok(None);
    };
    let server = silo_agent::sync::normalize_server(&server)?;
    let username = match args.username {
        Some(username) => username,
        None => prompt::line("Server username", "")?.context("server username required")?,
    };
    let username = silo_core::sync::normalize_username(&username)?;
    let invite = if interactive {
        prompt::line("Invite code (Enter to log in to an existing account)", "")?
    } else {
        args.invite
    };
    Ok(Some(InitSync {
        server,
        username,
        invite,
    }))
}

fn unlock(ttl: Option<Duration>) -> Result<()> {
    let paths = Paths::from_env()?;
    let store = Store::open(paths.clone())?;
    if !store.has_account() {
        bail!("no account in {}; run `silo init`", paths.home().display());
    }
    let mut agent = ensure_agent(&paths)?;
    let password = prompt::password("Master password")?;
    let status = unlock_with(&mut agent, &password, ttl)?;
    println!(
        "Unlocked {} secret(s) for {}. Fingerprint: {}",
        status.secrets,
        status
            .expires_in_secs
            .map_or("a while".to_owned(), |s| format::duration(
                Duration::from_secs(s)
            )),
        status.fingerprint.as_deref().unwrap_or("?")
    );
    Ok(())
}

fn unlock_with(agent: &mut Client, password: &str, ttl: Option<Duration>) -> Result<StatusInfo> {
    let mut request = Request::Unlock {
        password: password.to_owned(),
        ttl_secs: ttl.map(|d| d.as_secs()),
    };
    let reply = agent.call(&request);
    if let Request::Unlock { password, .. } = &mut request {
        password.zeroize();
    }
    match reply? {
        Reply::Unlocked(status) => Ok(status),
        other => Err(unexpected(other)),
    }
}

fn lock() -> Result<()> {
    let paths = Paths::from_env()?;
    match connect(&paths) {
        Ok(mut agent) => {
            agent.call(&Request::Lock)?;
            println!("Locked.");
        }
        Err(AgentUnavailable) => println!("Agent is not running; nothing to lock."),
    }
    Ok(())
}

fn status(json: bool) -> Result<()> {
    let paths = Paths::from_env()?;
    let info = match connect(&paths) {
        Ok(mut agent) => match agent.call(&Request::Status)? {
            Reply::Status(info) => Some(info),
            other => return Err(unexpected(other)),
        },
        Err(AgentUnavailable) => None,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }
    match info {
        None => {
            println!("Agent:   not running");
            println!("Home:    {}", paths.home().display());
            let has_account = paths.account_file().is_file();
            println!(
                "Account: {}",
                if has_account {
                    "present (run `silo unlock`)"
                } else {
                    "none (run `silo init`)"
                }
            );
        }
        Some(info) => {
            println!(
                "Agent:       running (agent {}, core {})",
                info.agent_version, info.core_version
            );
            println!("Home:        {}", info.home);
            if !info.has_account {
                println!("Account:     none (run `silo init`)");
            } else if info.unlocked {
                let expires = info.expires_in_secs.map_or("no expiry".to_owned(), |s| {
                    format!("locks in {}", format::duration(Duration::from_secs(s)))
                });
                println!(
                    "Vault:       unlocked, {} secret(s), {expires}",
                    info.secrets
                );
                println!(
                    "Fingerprint: {}",
                    info.fingerprint.as_deref().unwrap_or("?")
                );
            } else {
                println!("Vault:       locked (run `silo unlock`)");
            }
            if let Ok(mut agent) = connect(&paths) {
                println!("Sync:        {}", sync::summary_line(&mut agent)?);
            }
        }
    }
    Ok(())
}

fn agent_run() -> Result<()> {
    let paths = Paths::from_env()?;
    let store = Store::open(paths)?;
    server::run(server::Config {
        store,
        default_ttl: server::DEFAULT_TTL,
        sync_interval: Some(server::DEFAULT_SYNC_INTERVAL),
    })
    .context("agent failed")
}

fn agent_stop() -> Result<()> {
    let paths = Paths::from_env()?;
    match connect(&paths) {
        Ok(mut agent) => {
            agent.call(&Request::Shutdown)?;
            println!("Agent stopped.");
        }
        Err(AgentUnavailable) => println!("Agent is not running."),
    }
    Ok(())
}

/// Connects to the agent, starting it detached if needed.
pub(crate) fn ensure_agent(paths: &Paths) -> Result<Client> {
    let exe = std::env::current_exe().context("locating the secret binary")?;
    client::connect_or_spawn(paths, || {
        client::spawn_detached(&exe, &["agent", "run"], paths)
    })
    .with_context(|| format!("starting the agent (see {})", paths.log_file().display()))
}

struct AgentUnavailable;

/// Connects without starting an agent. `Err(AgentUnavailable)` when none is listening.
fn connect(paths: &Paths) -> Result<Client, AgentUnavailable> {
    Client::connect(paths.socket_file()).map_err(|_| AgentUnavailable)
}

/// For commands that need an unlocked vault. Turns "not running" into the same
/// hint the agent gives when locked.
pub(crate) fn connected() -> Result<Client> {
    let paths = Paths::from_env()?;
    connect(&paths).map_err(|AgentUnavailable| anyhow!("vault is locked; run `silo unlock`"))
}

pub(crate) fn unexpected(reply: Reply) -> anyhow::Error {
    anyhow!("unexpected reply from agent: {reply:?}")
}

// ---------- secrets ----------

fn ls(
    folder: Option<String>,
    exact: bool,
    tag: Option<String>,
    kind: Option<silo_core::vault::SecretKind>,
    json: bool,
) -> Result<()> {
    let filter = ListFilter {
        folder: folder.as_deref().map(FolderPath::parse).transpose()?,
        exact_folder: exact,
        tag: tag.as_deref().map(Tag::new).transpose()?,
        kind,
    };
    let Reply::List(items) = connected()?.call(&Request::List(filter))? else {
        bail!("unexpected reply")
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("No secrets.");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|s| {
            vec![
                s.path(),
                format::kind_name(s.meta.kind).to_owned(),
                s.meta
                    .tags
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                format::timestamp(s.meta.updated_at),
            ]
        })
        .collect();
    println!(
        "{}",
        format::table(&["PATH", "KIND", "TAGS", "UPDATED"], &rows)
    );
    Ok(())
}

fn add(command: AddCommand) -> Result<()> {
    let new = match command {
        AddCommand::Login {
            path,
            username,
            password,
            url,
            tag,
            notes,
            basic_auth,
        } => {
            let (folder, title) = split_path(&path)?;
            let password = match password {
                Some(password) => password,
                None => prompt::hidden(&format!("Password for {username}"))?.to_string(),
            };
            NewSecret {
                title,
                folder,
                tags: tags(&tag)?,
                urls: url,
                basic_auth,
                body: SecretBody::Login(Login {
                    username,
                    password,
                    totp: None,
                    notes: notes.unwrap_or_default(),
                }),
            }
        }
        AddCommand::Env {
            path,
            vars,
            from_file,
            tag,
        } => {
            let (folder, title) = split_path(&path)?;
            let mut set = EnvSet::default();
            if let Some(file) = from_file {
                for item in dotenvy::from_path_iter(&file)
                    .with_context(|| format!("reading {}", file.display()))?
                {
                    let (key, value) =
                        item.with_context(|| format!("parsing {}", file.display()))?;
                    upsert(&mut set, key, value);
                }
            }
            for var in &vars {
                let (key, value) = var
                    .split_once('=')
                    .ok_or_else(|| anyhow!("expected KEY=VALUE, got {var:?}"))?;
                upsert(&mut set, key.to_owned(), value.to_owned());
            }
            if set.vars.is_empty() {
                bail!("no variables given; pass KEY=VALUE arguments or --from-file .env");
            }
            NewSecret {
                title,
                folder,
                tags: tags(&tag)?,
                urls: vec![],
                basic_auth: false,
                body: SecretBody::EnvSet(set),
            }
        }
        AddCommand::File { path, file, tag } => {
            let (folder, title) = split_path(&path)?;
            let data =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let name = file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| title.clone());
            NewSecret {
                title,
                folder,
                tags: tags(&tag)?,
                urls: vec![],
                basic_auth: false,
                body: SecretBody::File(File {
                    name,
                    mime: None,
                    data,
                }),
            }
        }
        AddCommand::Note { path, text, tag } => {
            let (folder, title) = split_path(&path)?;
            let text = match text {
                Some(text) => text,
                None => {
                    let mut buf = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buf)
                        .context("reading note from stdin")?;
                    buf
                }
            };
            NewSecret {
                title,
                folder,
                tags: tags(&tag)?,
                urls: vec![],
                basic_auth: false,
                body: SecretBody::Note(Note { text }),
            }
        }
    };
    let Reply::Added(summary) = connected()?.call(&Request::Add(new))? else {
        bail!("unexpected reply")
    };
    println!(
        "Added {} ({}) id {}",
        summary.path(),
        format::kind_name(summary.meta.kind),
        summary.id
    );
    Ok(())
}

fn get(selector: &str, field: Option<&str>, json: bool) -> Result<()> {
    let view = fetch(selector)?;
    if let Some(name) = field {
        let value = format::field(&view.body, name)
            .ok_or_else(|| anyhow!("{} has no field {name:?}", view.path()))?;
        println!("{value}");
        return Ok(());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&view)?);
        return Ok(());
    }
    print_view(&view);
    Ok(())
}

fn history(selector: &str, revision: Option<u32>, json: bool) -> Result<()> {
    let Reply::History(views) = connected()?.call(&Request::History {
        selector: selector.to_owned(),
    })?
    else {
        bail!("unexpected reply")
    };
    if let Some(revision) = revision {
        let view = views
            .iter()
            .find(|view| view.revision == revision)
            .ok_or_else(|| anyhow!("{selector} has no earlier revision {revision}"))?;
        if json {
            println!("{}", serde_json::to_string_pretty(view)?);
        } else {
            println!("Revision {revision} of {}", view.path());
            print_view(view);
        }
        return Ok(());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&views)?);
        return Ok(());
    }
    if views.is_empty() {
        println!("{selector} has no earlier revisions.");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = views
        .iter()
        .map(|view| {
            let username = match &view.body {
                SecretBody::Login(login) => login.username.clone(),
                _ => String::new(),
            };
            vec![
                view.revision.to_string(),
                format::timestamp(view.meta.updated_at),
                view.path(),
                username,
            ]
        })
        .collect();
    println!(
        "{}",
        format::table(&["REVISION", "SAVED", "PATH", "USERNAME"], &rows)
    );
    println!("Show one with: silo history {selector} --revision <n>");
    println!("Bring one back with: silo restore {selector} --revision <n>");
    Ok(())
}

fn print_view(view: &SecretView) {
    println!("{}", view.path());
    println!("  id:       {}", view.id);
    println!("  kind:     {}", format::kind_name(view.meta.kind));
    if !view.meta.tags.is_empty() {
        println!(
            "  tags:     {}",
            view.meta
                .tags
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !view.meta.urls.is_empty() {
        println!("  urls:     {}", view.meta.urls.join(", "));
    }
    if view.meta.basic_auth {
        println!("  basic auth: yes");
    }
    println!("  updated:  {}", format::timestamp(view.meta.updated_at));
    println!();
    match &view.body {
        SecretBody::Login(login) => {
            println!("  username: {}", login.username);
            println!("  password: {}", login.password);
            if let Some(totp) = &login.totp {
                println!("  totp:     {totp}");
            }
            if !login.notes.is_empty() {
                println!("  notes:    {}", login.notes);
            }
        }
        SecretBody::Card(card) => {
            println!("  holder:   {}", card.holder);
            println!("  number:   {}", card.number);
            println!("  expiry:   {:02}/{}", card.expiry_month, card.expiry_year);
            println!("  cvv:      {}", card.cvv);
        }
        SecretBody::EnvSet(set) => {
            for var in &set.vars {
                println!("  {}", format::dotenv_line(&var.key, &var.value));
            }
        }
        SecretBody::File(file) => {
            println!(
                "  file:     {} ({} bytes); use `silo file pull {}`",
                file.name,
                file.data.len(),
                view.path()
            );
        }
        SecretBody::Note(note) => println!("{}", note.text),
    }
}

fn rm(selector: &str, yes: bool) -> Result<()> {
    let view = fetch(selector)?;
    if !yes && !prompt::confirm(&format!("Remove {} ({})?", view.path(), view.id))? {
        println!("Aborted.");
        return Ok(());
    }
    let Reply::Removed(summary) = connected()?.call(&Request::Remove {
        selector: view.id.to_string(),
    })?
    else {
        bail!("unexpected reply")
    };
    println!("Removed {}", summary.path());
    Ok(())
}

fn run_with_env(selectors: &[String], command: &[String]) -> Result<()> {
    let mut env: Vec<(String, String)> = Vec::new();
    for selector in selectors {
        let view = fetch(selector)?;
        let SecretBody::EnvSet(set) = &view.body else {
            bail!(
                "{} is a {}, not an env set",
                view.path(),
                format::kind_name(view.meta.kind)
            );
        };
        for var in &set.vars {
            env.retain(|(k, _)| k != &var.key);
            env.push((var.key.clone(), var.value.clone()));
        }
    }
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("no command given after --"))?;
    let err = Process::new(program).args(args).envs(env).exec();
    Err(err).with_context(|| format!("failed to run {program}"))
}

fn export(selector: &str, format: ExportFormat) -> Result<()> {
    let view = fetch(selector)?;
    let SecretBody::EnvSet(set) = &view.body else {
        bail!(
            "{} is a {}, not an env set",
            view.path(),
            format::kind_name(view.meta.kind)
        );
    };
    match format {
        ExportFormat::Dotenv => {
            for var in &set.vars {
                println!("{}", format::dotenv_line(&var.key, &var.value));
            }
        }
        ExportFormat::Shell => {
            for var in &set.vars {
                println!("{}", format::shell_line(&var.key, &var.value));
            }
        }
        ExportFormat::Json => {
            let pairs: Vec<String> = set
                .vars
                .iter()
                .map(|v| {
                    format!(
                        "  {}: {}",
                        serde_json::to_string(&v.key).unwrap_or_default(),
                        serde_json::to_string(&v.value).unwrap_or_default()
                    )
                })
                .collect();
            println!("{{\n{}\n}}", pairs.join(",\n"));
        }
    }
    Ok(())
}

fn file_pull(selector: &str, output: Option<PathBuf>, force: bool) -> Result<()> {
    let view = fetch(selector)?;
    let SecretBody::File(file) = &view.body else {
        bail!(
            "{} is a {}, not a file",
            view.path(),
            format::kind_name(view.meta.kind)
        );
    };
    let target = output.unwrap_or_else(|| PathBuf::from(&file.name));
    if target.exists() && !force {
        bail!("{} exists; pass --force to overwrite", target.display());
    }
    write_private(&target, &file.data).with_context(|| format!("writing {}", target.display()))?;
    println!("Wrote {} ({} bytes)", target.display(), file.data.len());
    Ok(())
}

fn match_url(url: &str, site: bool, json: bool) -> Result<()> {
    let Reply::Matches(items) = connected()?.call(&Request::Match {
        url: url.to_owned(),
        site,
    })?
    else {
        bail!("unexpected reply")
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&items)?);
        return Ok(());
    }
    if items.is_empty() {
        println!("No logins match {url}.");
        println!("Save one with: silo add login <folder/title> -u <user> --url <pattern>");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|s| {
            let basic_auth = if s.meta.basic_auth { "yes" } else { "" };
            vec![s.path(), s.meta.urls.join(", "), basic_auth.to_owned()]
        })
        .collect();
    println!("{}", format::table(&["PATH", "URLS", "BASIC AUTH"], &rows));
    Ok(())
}

// ---------- helpers ----------

pub(crate) fn fetch(selector: &str) -> Result<SecretView> {
    match connected()?.call(&Request::Get {
        selector: selector.to_owned(),
    }) {
        Ok(Reply::Secret(view)) => Ok(view),
        Ok(other) => Err(unexpected(other)),
        Err(ClientError::Agent(err)) => Err(err.into()),
        Err(err) => Err(err.into()),
    }
}

/// Splits `folder/title` into a validated folder and a title.
pub(crate) fn split_path(path: &str) -> Result<(FolderPath, String)> {
    let (folder, title) = path.rsplit_once('/').unwrap_or(("", path));
    if title.trim().is_empty() {
        bail!("missing title in {path:?}; expected folder/title");
    }
    Ok((FolderPath::parse(folder)?, title.to_owned()))
}

pub(crate) fn tags(raw: &[String]) -> Result<Vec<Tag>> {
    raw.iter()
        .flat_map(|s| s.split(','))
        .filter(|s| !s.is_empty())
        .map(|s| Tag::new(s).map_err(Into::into))
        .collect()
}

pub(crate) fn upsert(set: &mut EnvSet, key: String, value: String) {
    if let Some(existing) = set.vars.iter_mut().find(|v| v.key == key) {
        existing.value = value;
    } else {
        set.vars.push(EnvVar { key, value });
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}
