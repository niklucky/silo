//! `secret import`: logins from a password manager's CSV export. Columns are
//! found by name, so exports from Apple Passwords, Chrome, Firefox and
//! Bitwarden all work. New logins go where the extension saves them,
//! `web/<host>` filling on the site's origin, and logins already in the vault
//! are recognised, so running an import twice adds nothing.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use secret_agent::Client;
use secret_agent::protocol::{ListFilter, NewSecret, Reply, Request, SecretUpdate};
use secret_core::vault::{
    FolderPath, Login, SecretBody, SecretId, SecretKind, Tag, Url, url_match,
};

use crate::commands::{connected, tags, unexpected};
use crate::format;

pub fn run(file: &Path, folder: &str, tag: &[String], replace: bool, dry_run: bool) -> Result<()> {
    let (source, rows) = read(file)?;
    let folder = FolderPath::parse(folder)?;
    let tags = tags(tag)?;
    let mut agent = connected()?;
    let saved = saved_logins(&mut agent)?;
    let actions = plan(rows, saved, &folder);
    println!(
        "Read {} logins from {} ({source}).",
        actions.len(),
        file.display()
    );

    let shown: Vec<&Action> = actions
        .iter()
        .filter(|a| dry_run || matches!(a.kind, Kind::Differs { .. } | Kind::Skip(_)))
        .collect();
    if !shown.is_empty() {
        let rows: Vec<Vec<String>> = shown
            .iter()
            .map(|a| {
                vec![
                    a.label(replace).to_owned(),
                    a.path.clone(),
                    a.login.username.clone(),
                    a.url.clone().unwrap_or_default(),
                ]
            })
            .collect();
        println!(
            "{}",
            format::table(&["ACTION", "PATH", "USERNAME", "URL"], &rows)
        );
    }

    let count = |f: fn(&Kind) -> bool| actions.iter().filter(|a| f(&a.kind)).count();
    let added = count(|k| matches!(k, Kind::Add { .. }));
    let same = count(|k| matches!(k, Kind::Same));
    let differs = count(|k| matches!(k, Kind::Differs { .. }));
    let skipped = count(|k| matches!(k, Kind::Skip(_)));

    if !dry_run {
        for action in &actions {
            action
                .apply(&mut agent, &folder, &tags, replace)
                .with_context(|| format!("importing {} (line {})", action.path, action.line))?;
        }
    }

    let verb = if dry_run { "Would add" } else { "Added" };
    println!("{verb} {added} new login(s) to {folder}/.");
    if same > 0 {
        println!("{same} already saved.");
    }
    if differs > 0 {
        if replace {
            let verb = if dry_run { "Would update" } else { "Updated" };
            println!("{verb} {differs} saved with another password; the old ones stay in history.");
        } else {
            println!(
                "{differs} saved with another password, left as they are; --replace updates them."
            );
        }
    }
    if skipped > 0 {
        println!("{skipped} skipped.");
    }
    if dry_run {
        println!("Nothing changed (dry run).");
    } else {
        println!(
            "{} holds your passwords in plain text; delete it.",
            file.display()
        );
    }
    Ok(())
}

/// One row of the export.
struct Row {
    line: u64,
    title: String,
    url: String,
    login: Login,
}

/// Reads the export, naming the program it came from.
fn read(file: &Path) -> Result<(&'static str, Vec<Row>)> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(file)
        .with_context(|| format!("reading {}", file.display()))?;
    let headers: Vec<String> = reader
        .headers()
        .with_context(|| format!("reading {}", file.display()))?
        .iter()
        .map(|h| h.trim_start_matches('\u{feff}').trim().to_lowercase())
        .collect();
    let column = |names: &[&str]| headers.iter().position(|h| names.contains(&h.as_str()));
    let (Some(username), Some(password)) = (
        column(&["username", "login_username"]),
        column(&["password", "login_password"]),
    ) else {
        bail!(
            "{} has no username and password columns (found: {}); export as CSV from your password manager",
            file.display(),
            headers.join(", ")
        );
    };
    let title = column(&["title", "name"]);
    let url = column(&["url", "login_uri", "website"]);
    let notes = column(&["notes", "note", "extra"]);
    let totp = column(&["otpauth", "totp", "login_totp"]);
    let has = |name: &str| headers.iter().any(|h| h == name);
    let source = if has("otpauth") {
        "Apple Passwords"
    } else if has("httprealm") {
        "Firefox"
    } else if has("login_uri") {
        "Bitwarden"
    } else if has("name") && has("note") {
        "Chrome"
    } else {
        "CSV"
    };

    let mut rows = Vec::new();
    for record in reader.records() {
        let record = record.with_context(|| format!("reading {}", file.display()))?;
        let field = |i: Option<usize>| {
            i.and_then(|i| record.get(i))
                .unwrap_or("")
                .trim()
                .to_owned()
        };
        let line = record.position().map_or(0, |p| p.line());
        let totp = field(totp);
        rows.push(Row {
            line,
            title: field(title),
            url: field(url),
            login: Login {
                username: field(Some(username)),
                // Passwords keep their spaces.
                password: record.get(password).unwrap_or("").to_owned(),
                totp: (!totp.is_empty()).then_some(totp),
                notes: field(notes),
            },
        });
    }
    Ok((source, rows))
}

/// A login in the vault, or one this import is about to add.
struct Saved {
    id: Option<SecretId>,
    revision: u32,
    path: String,
    urls: Vec<String>,
    login: Login,
}

fn saved_logins(agent: &mut Client) -> Result<Vec<Saved>> {
    let list = match agent.call(&Request::List(ListFilter {
        kind: Some(SecretKind::Login),
        ..ListFilter::default()
    }))? {
        Reply::List(list) => list,
        other => return Err(unexpected(other)),
    };
    let mut saved = Vec::with_capacity(list.len());
    for summary in list {
        let view = match agent.call(&Request::Get {
            selector: summary.id.to_string(),
        })? {
            Reply::Secret(view) => view,
            other => return Err(unexpected(other)),
        };
        let path = view.path();
        if let SecretBody::Login(login) = &view.body {
            saved.push(Saved {
                id: Some(view.id),
                revision: view.revision,
                path,
                urls: view.meta.urls.clone(),
                login: login.clone(),
            });
        }
    }
    Ok(saved)
}

struct Action {
    line: u64,
    path: String,
    url: Option<String>,
    login: Login,
    kind: Kind,
}

enum Kind {
    Add {
        title: String,
    },
    /// Already saved with this password.
    Same,
    /// Saved for this site and username with another password.
    Differs {
        id: SecretId,
        revision: u32,
        saved: Login,
    },
    Skip(&'static str),
}

impl Action {
    fn label(&self, replace: bool) -> &'static str {
        match &self.kind {
            Kind::Add { .. } => "add",
            Kind::Same => "already saved",
            Kind::Differs { .. } if replace => "update password",
            Kind::Differs { .. } => "other password saved",
            Kind::Skip(reason) => reason,
        }
    }

    fn apply(
        &self,
        agent: &mut Client,
        folder: &FolderPath,
        tags: &[Tag],
        replace: bool,
    ) -> Result<()> {
        let request = match &self.kind {
            Kind::Add { title } => Request::Add(NewSecret {
                title: title.clone(),
                folder: folder.clone(),
                tags: tags.to_vec(),
                urls: self.url.iter().cloned().collect(),
                body: SecretBody::Login(self.login.clone()),
            }),
            Kind::Differs {
                id,
                revision,
                saved,
            } if replace => {
                let mut login = saved.clone();
                login.password.clone_from(&self.login.password);
                if login.totp.is_none() {
                    login.totp.clone_from(&self.login.totp);
                }
                Request::Update(SecretUpdate {
                    selector: id.to_string(),
                    revision: Some(*revision),
                    title: None,
                    folder: None,
                    tags: None,
                    urls: None,
                    body: Some(SecretBody::Login(login)),
                })
            }
            _ => return Ok(()),
        };
        match agent.call(&request)? {
            Reply::Added(_) | Reply::Updated(_) => Ok(()),
            other => Err(unexpected(other)),
        }
    }
}

/// Decides what happens to each row. Rows are compared with the vault and
/// with the rows before them, so duplicates in the file are added once.
fn plan(rows: Vec<Row>, mut saved: Vec<Saved>, folder: &FolderPath) -> Vec<Action> {
    let prefix = if folder.is_root() {
        String::new()
    } else {
        format!("{folder}/")
    };
    let mut taken: HashSet<String> = saved
        .iter()
        .filter_map(|s| s.path.strip_prefix(&prefix).map(str::to_owned))
        .filter(|title| !title.contains('/'))
        .collect();
    let mut actions = Vec::with_capacity(rows.len());
    for row in rows {
        let site = web_site(&row.url);
        let mut action = Action {
            line: row.line,
            path: String::new(),
            url: site.as_ref().map(|(origin, _, _)| origin.clone()),
            login: row.login,
            kind: Kind::Skip("no password"),
        };
        if action.login.password.is_empty() {
            action.path = if row.title.is_empty() {
                row.url
            } else {
                row.title
            };
            actions.push(action);
            continue;
        }

        let same_user: Vec<&Saved> = saved
            .iter()
            .filter(|s| same_username(&s.login.username, &action.login.username))
            .filter(|s| match &site {
                Some((_, _, url)) => s.urls.iter().any(|p| url_match(p, url).is_some()),
                // Without a web address, only a login of the same title.
                None => s.urls.is_empty() && s.path.rsplit('/').next() == Some(row.title.as_str()),
            })
            .collect();
        if let Some(found) = same_user
            .iter()
            .find(|s| s.login.password == action.login.password)
        {
            action.path = found.path.clone();
            action.kind = Kind::Same;
        } else if let Some(found) = same_user.iter().find(|s| s.id.is_some()) {
            action.path = found.path.clone();
            action.kind = Kind::Differs {
                id: found.id.expect("filtered above"),
                revision: found.revision,
                saved: found.login.clone(),
            };
        } else {
            let base = match &site {
                Some((_, host, _)) => host.clone(),
                None if !row.title.is_empty() => row.title.replace('/', "-"),
                None => "untitled".to_owned(),
            };
            let mut title = base.clone();
            for n in 2.. {
                if !taken.contains(&title) {
                    break;
                }
                title = format!("{base} ({n})");
            }
            taken.insert(title.clone());
            action.path = format!("{prefix}{title}");
            saved.push(Saved {
                id: None,
                revision: 0,
                path: action.path.clone(),
                urls: action.url.iter().cloned().collect(),
                login: action.login.clone(),
            });
            action.kind = Kind::Add { title };
        }
        actions.push(action);
    }
    actions
}

/// Origin (the URL pattern), host with port (the title) and the parsed URL
/// of a web address; `None` for anything else, such as an app's identifier.
fn web_site(raw: &str) -> Option<(String, String, Url)> {
    let url = if raw.contains("://") {
        Url::parse(raw).ok()?
    } else if !raw.is_empty() && !raw.contains(char::is_whitespace) {
        // A bare `example.com/login`.
        Url::parse(&format!("https://{raw}")).ok()?
    } else {
        return None;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.to_owned();
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Some((url.origin().ascii_serialization(), host, url))
}

fn same_username(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(username: &str, password: &str) -> Login {
        Login {
            username: username.into(),
            password: password.into(),
            totp: None,
            notes: String::new(),
        }
    }

    fn row(url: &str, username: &str, password: &str) -> Row {
        Row {
            line: 2,
            title: String::new(),
            url: url.into(),
            login: login(username, password),
        }
    }

    fn saved(path: &str, url: &str, username: &str, password: &str) -> Saved {
        Saved {
            id: Some(SecretId::from_random_bytes([3; 16])),
            revision: 2,
            path: path.into(),
            urls: vec![url.into()],
            login: login(username, password),
        }
    }

    #[test]
    fn reads_an_apple_passwords_export() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("Passwords.csv");
        std::fs::write(
            &file,
            "\u{feff}Title,URL,Username,Password,Notes,OTPAuth\n\
             github.com (me),https://github.com/login,me, pass word ,\"line 1, with comma\nline 2\",otpauth://totp/x?secret=ABC\n\
             app,,app-user,pw,,\n",
        )
        .unwrap();
        let (source, rows) = read(&file).unwrap();
        assert_eq!(source, "Apple Passwords");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].url, "https://github.com/login");
        assert_eq!(rows[0].login.username, "me");
        assert_eq!(rows[0].login.password, " pass word ");
        assert_eq!(rows[0].login.notes, "line 1, with comma\nline 2");
        assert_eq!(
            rows[0].login.totp.as_deref(),
            Some("otpauth://totp/x?secret=ABC")
        );
        assert_eq!(rows[1].title, "app");
        assert_eq!(rows[1].login.totp, None);
    }

    #[test]
    fn names_other_exports_and_refuses_unknown_ones() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.csv");
        std::fs::write(&file, "name,url,username,password,note\n").unwrap();
        assert_eq!(read(&file).unwrap().0, "Chrome");
        std::fs::write(
            &file,
            "url,username,password,httpRealm,formActionOrigin,guid\n",
        )
        .unwrap();
        assert_eq!(read(&file).unwrap().0, "Firefox");
        std::fs::write(&file, "a,b\n1,2\n").unwrap();
        let Err(err) = read(&file) else {
            panic!("read an unknown export")
        };
        assert!(err.to_string().contains("found: a, b"), "{err}");
    }

    #[test]
    fn plans_new_same_differing_and_skipped_rows() {
        let folder = FolderPath::parse("web").unwrap();
        let vault = vec![
            saved("web/github.com", "github.com", "me", "same"),
            saved("web/gitlab.com", "https://gitlab.com", "me", "old"),
            saved("web/example.com", "https://other.org", "x", "x"),
        ];
        let rows = vec![
            row("https://github.com/login", "Me", "same"),
            row("https://gitlab.com/users/sign_in", "me", "new"),
            row("https://example.com/", "me", "pw"),
            row("https://example.com/again", "me", "pw"),
            row("http://localhost:8099/private", "nikita", "s3cret"),
            row("https://nopass.com", "me", ""),
            row("bare.example.org/login", "me", "pw"),
            Row {
                title: "My app".into(),
                ..row("android://hash@com.example", "me", "pw")
            },
        ];
        let actions = plan(rows, vault, &folder);
        let summary: Vec<(&str, &str, Option<&str>)> = actions
            .iter()
            .map(|a| (a.label(false), a.path.as_str(), a.url.as_deref()))
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "already saved",
                    "web/github.com",
                    Some("https://github.com")
                ),
                (
                    "other password saved",
                    "web/gitlab.com",
                    Some("https://gitlab.com")
                ),
                ("add", "web/example.com (2)", Some("https://example.com")),
                (
                    "already saved",
                    "web/example.com (2)",
                    Some("https://example.com")
                ),
                ("add", "web/localhost:8099", Some("http://localhost:8099")),
                (
                    "no password",
                    "https://nopass.com",
                    Some("https://nopass.com")
                ),
                (
                    "add",
                    "web/bare.example.org",
                    Some("https://bare.example.org")
                ),
                ("add", "web/My app", None),
            ]
        );
    }
}
