//! `secret edit`: changes parts of a secret through the agent's `update`, which
//! keeps the replaced revision in the secret's history. Options say what to
//! change; without any, the user is asked field by field.

use std::io::{IsTerminal, Read};

use anyhow::{Context, Result, anyhow, bail};
use secret_agent::ClientError;
use secret_agent::protocol::{AgentError, Reply, Request, SecretUpdate, SecretView};
use secret_core::vault::{SecretBody, SecretKind};
use zeroize::Zeroizing;

use crate::args::EditArgs;
use crate::commands::{connected, fetch, split_path, tags, unexpected, upsert};
use crate::{format, generate, prompt};

pub fn run(args: EditArgs) -> Result<()> {
    let view = fetch(&args.selector)?;
    let changes = if args.is_empty() {
        ask(&view)?
    } else {
        Changes::from_args(args)?
    };
    let generated = changes.generated;
    let (update, changed) = apply(&view, changes)?;
    if changed.is_empty() {
        println!("Nothing changed.");
        return Ok(());
    }
    let summary = match connected()?.call(&Request::Update(update)) {
        Ok(Reply::Updated(summary)) => summary,
        Ok(other) => return Err(unexpected(other)),
        Err(ClientError::Agent(AgentError::Invalid { message }))
            if message.contains("unknown variant `update`") =>
        {
            bail!(
                "the running agent predates `secret edit`; restart it with \
                 `secret agent stop && secret unlock`"
            )
        }
        Err(err) => return Err(err.into()),
    };
    let path = summary.path();
    println!(
        "Updated {path}: {} (revision {}; `secret history {path}` keeps the old one)",
        changed.join(", "),
        summary.revision
    );
    if generated {
        println!("Show the new password with `secret get {path} -f password`.");
    }
    Ok(())
}

impl EditArgs {
    fn is_empty(&self) -> bool {
        self.vars.is_empty()
            && self.path.is_none()
            && self.username.is_none()
            && self.password.is_none()
            && !self.generate
            && self.notes.is_none()
            && self.add_url.is_empty()
            && self.rm_url.is_empty()
            && self.add_tag.is_empty()
            && self.rm_tag.is_empty()
            && self.unset.is_empty()
            && self.text.is_none()
            && self.file.is_none()
    }
}

/// What to change, from options or answers. Unset fields keep their value.
#[derive(Default)]
struct Changes {
    path: Option<String>,
    username: Option<String>,
    password: Option<Zeroizing<String>>,
    generated: bool,
    notes: Option<String>,
    urls: ListEdit,
    tags: ListEdit,
    set: Vec<(String, String)>,
    unset: Vec<String>,
    text: Option<String>,
    file: Option<Vec<u8>>,
}

#[derive(Default)]
struct ListEdit {
    replace: Option<Vec<String>>,
    add: Vec<String>,
    remove: Vec<String>,
}

impl ListEdit {
    fn apply(&self, current: &[String], what: &str, path: &str) -> Result<Vec<String>> {
        let mut list = self.replace.clone().unwrap_or_else(|| current.to_vec());
        for gone in &self.remove {
            let before = list.len();
            list.retain(|item| item != gone);
            if list.len() == before {
                bail!("{path} has no {what} {gone:?}");
            }
        }
        for item in &self.add {
            if !list.contains(item) {
                list.push(item.clone());
            }
        }
        Ok(list)
    }
}

impl Changes {
    fn from_args(args: EditArgs) -> Result<Self> {
        let generated = args.generate;
        let password = match args.password {
            _ if generated => Some(generate::password()),
            Some(Some(password)) => Some(Zeroizing::new(password)),
            Some(None) => Some(prompt::new_secret("New password")?),
            None => None,
        };
        let text = match args.text.as_deref() {
            Some("-") => {
                let mut buf = String::new();
                std::io::stdin()
                    .read_to_string(&mut buf)
                    .context("reading the note from stdin")?;
                Some(buf)
            }
            _ => args.text,
        };
        let file = match &args.file {
            Some(file) => {
                Some(std::fs::read(file).with_context(|| format!("reading {}", file.display()))?)
            }
            None => None,
        };
        let set = args
            .vars
            .iter()
            .map(|var| {
                var.split_once('=')
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .ok_or_else(|| anyhow!("expected KEY=VALUE, got {var:?}"))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            path: args.path,
            username: args.username,
            password,
            generated,
            notes: args.notes,
            urls: ListEdit {
                replace: None,
                add: args.add_url,
                remove: args.rm_url,
            },
            tags: ListEdit {
                replace: None,
                add: split_tags(&args.add_tag),
                remove: split_tags(&args.rm_tag),
            },
            set,
            unset: args.unset,
            text,
            file,
        })
    }

    /// The options that only make sense for one kind of secret, by kind.
    fn kind_specific(&self) -> [(SecretKind, &'static str, bool); 4] {
        [
            (
                SecretKind::Login,
                "--username, --password, --generate and --notes",
                self.username.is_some() || self.password.is_some() || self.notes.is_some(),
            ),
            (
                SecretKind::EnvSet,
                "KEY=VALUE and --unset",
                !self.set.is_empty() || !self.unset.is_empty(),
            ),
            (SecretKind::Note, "--text", self.text.is_some()),
            (SecretKind::File, "--file", self.file.is_some()),
        ]
    }
}

/// Asks for each field, showing the current value; Enter keeps it.
fn ask(view: &SecretView) -> Result<Changes> {
    if !std::io::stdin().is_terminal() {
        bail!("nothing to change; see `secret edit --help`");
    }
    println!(
        "Editing {} ({}). Press Enter to keep a value; \"-\" empties a list.",
        view.path(),
        format::kind_name(view.meta.kind)
    );
    let mut changes = Changes {
        path: prompt::line("Path", &view.path())?,
        ..Changes::default()
    };
    if let SecretBody::Login(login) = &view.body {
        changes.username = prompt::line("Username", &login.username)?;
        let password = prompt::hidden("Password (Enter to keep)")?;
        if !password.is_empty() {
            if *prompt::hidden("Repeat")? != *password {
                bail!("passwords do not match");
            }
            changes.password = Some(password);
        }
    }
    if let Some(urls) = prompt::line("URLs", &view.meta.urls.join(", "))? {
        changes.urls.replace = Some(split_list(&urls));
    }
    let current_tags: Vec<&str> = view.meta.tags.iter().map(|t| t.as_str()).collect();
    if let Some(tags) = prompt::line("Tags", &current_tags.join(", "))? {
        changes.tags.replace = Some(split_list(&tags));
    }
    Ok(changes)
}

/// The update to send, and the names of what it changes (empty: nothing does).
fn apply(view: &SecretView, changes: Changes) -> Result<(SecretUpdate, Vec<&'static str>)> {
    let path = view.path();
    for (kind, options, used) in changes.kind_specific() {
        if used && view.meta.kind != kind {
            let actual = format::kind_name(view.meta.kind);
            let article = if actual.starts_with(['a', 'e', 'i', 'o', 'u']) {
                "an"
            } else {
                "a"
            };
            bail!(
                "{options} only work on {} secrets; {path} is {article} {actual}",
                format::kind_name(kind)
            );
        }
    }

    let mut update = SecretUpdate {
        selector: view.id.to_string(),
        revision: Some(view.revision),
        title: None,
        folder: None,
        tags: None,
        urls: None,
        body: None,
    };
    let mut changed = Vec::new();

    if let Some(new_path) = &changes.path {
        let (folder, title) = split_path(new_path)?;
        if title != view.meta.title {
            update.title = Some(title);
        }
        if folder != view.meta.folder {
            update.folder = Some(folder);
        }
        if update.title.is_some() || update.folder.is_some() {
            changed.push("path");
        }
    }

    let urls = changes.urls.apply(&view.meta.urls, "URL", &path)?;
    if urls != view.meta.urls {
        update.urls = Some(urls);
        changed.push("urls");
    }

    let current_tags: Vec<String> = view.meta.tags.iter().map(|t| t.to_string()).collect();
    let mut new_tags = changes.tags.apply(&current_tags, "tag", &path)?;
    new_tags.sort();
    new_tags.dedup();
    if new_tags != current_tags {
        update.tags = Some(tags(&new_tags)?);
        changed.push("tags");
    }

    let mut body = view.body.clone();
    match &mut body {
        SecretBody::Login(login) => {
            if let Some(username) = changes.username
                && username != login.username
            {
                login.username = username;
                changed.push("username");
            }
            if let Some(password) = &changes.password
                && **password != login.password
            {
                login.password = password.to_string();
                changed.push("password");
            }
            if let Some(notes) = changes.notes
                && notes != login.notes
            {
                login.notes = notes;
                changed.push("notes");
            }
        }
        SecretBody::EnvSet(set) => {
            for key in &changes.unset {
                let before = set.vars.len();
                set.vars.retain(|var| &var.key != key);
                if set.vars.len() == before {
                    bail!("{path} has no variable {key:?}");
                }
            }
            for (key, value) in changes.set {
                upsert(set, key, value);
            }
            if set.vars.is_empty() {
                bail!("an env set needs at least one variable; remove it with `secret rm {path}`");
            }
        }
        SecretBody::Note(note) => {
            if let Some(text) = changes.text {
                note.text = text;
            }
        }
        SecretBody::File(file) => {
            if let Some(data) = changes.file {
                file.data = data;
            }
        }
        SecretBody::Card(_) => {}
    }
    if body != view.body {
        match body {
            SecretBody::EnvSet(_) => changed.push("variables"),
            SecretBody::Note(_) => changed.push("text"),
            SecretBody::File(_) => changed.push("contents"),
            _ => {}
        }
        update.body = Some(body);
    }
    Ok((update, changed))
}

fn split_tags(raw: &[String]) -> Vec<String> {
    raw.iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A comma-separated answer; "-" is the empty list.
fn split_list(answer: &str) -> Vec<String> {
    if answer == "-" {
        return Vec::new();
    }
    split_tags(&[answer.to_owned()])
}

#[cfg(test)]
mod tests {
    use secret_core::vault::{EnvSet, EnvVar, FolderPath, Login, SecretId, SecretMeta, Tag};

    use super::*;

    fn view(body: SecretBody, urls: &[&str], tags: &[&str]) -> SecretView {
        SecretView {
            id: SecretId::from_random_bytes([1; 16]),
            revision: 4,
            meta: SecretMeta {
                title: "github".into(),
                kind: body.kind(),
                folder: FolderPath::parse("work").unwrap(),
                tags: tags.iter().map(|t| Tag::new(t).unwrap()).collect(),
                urls: urls.iter().map(|u| (*u).to_owned()).collect(),
                created_at: 1,
                updated_at: 1,
            },
            body,
        }
    }

    fn login(username: &str, password: &str) -> SecretBody {
        SecretBody::Login(Login {
            username: username.into(),
            password: password.into(),
            totp: None,
            notes: String::new(),
        })
    }

    #[test]
    fn login_fields_and_urls_change_and_pin_the_revision() {
        let current = view(login("me", "old"), &["github.com"], &[]);
        let changes = Changes {
            password: Some(Zeroizing::new("new".into())),
            urls: ListEdit {
                add: vec!["gist.github.com".into()],
                ..ListEdit::default()
            },
            ..Changes::default()
        };
        let (update, changed) = apply(&current, changes).unwrap();
        assert_eq!(changed, ["urls", "password"]);
        assert_eq!(update.revision, Some(4));
        assert_eq!(update.selector, current.id.to_string());
        assert_eq!(
            update.urls.unwrap(),
            ["github.com".to_owned(), "gist.github.com".to_owned()]
        );
        assert_eq!(update.body, Some(login("me", "new")));
        assert!(update.title.is_none() && update.folder.is_none() && update.tags.is_none());
    }

    #[test]
    fn same_values_change_nothing() {
        let current = view(login("me", "pw"), &["github.com"], &["a"]);
        let changes = Changes {
            path: Some("work/github".into()),
            username: Some("me".into()),
            password: Some(Zeroizing::new("pw".into())),
            urls: ListEdit {
                add: vec!["github.com".into()],
                ..ListEdit::default()
            },
            tags: ListEdit {
                replace: Some(vec!["a".into()]),
                ..ListEdit::default()
            },
            ..Changes::default()
        };
        let (update, changed) = apply(&current, changes).unwrap();
        assert!(changed.is_empty(), "{changed:?}");
        assert!(update.body.is_none());
    }

    #[test]
    fn moves_and_renames() {
        let current = view(login("me", "pw"), &[], &[]);
        let changes = Changes {
            path: Some("personal/gh".into()),
            ..Changes::default()
        };
        let (update, changed) = apply(&current, changes).unwrap();
        assert_eq!(changed, ["path"]);
        assert_eq!(update.title.as_deref(), Some("gh"));
        assert_eq!(update.folder, Some(FolderPath::parse("personal").unwrap()));
    }

    #[test]
    fn removing_what_is_not_there_fails() {
        let current = view(login("me", "pw"), &["github.com"], &["a"]);
        let changes = Changes {
            urls: ListEdit {
                remove: vec!["gitlab.com".into()],
                ..ListEdit::default()
            },
            ..Changes::default()
        };
        let err = apply(&current, changes).unwrap_err().to_string();
        assert!(err.contains("no URL \"gitlab.com\""), "{err}");
    }

    #[test]
    fn tags_are_compared_sorted() {
        let current = view(login("me", "pw"), &[], &["a", "c"]);
        let changes = Changes {
            tags: ListEdit {
                add: vec!["b".into()],
                remove: vec!["c".into()],
                ..ListEdit::default()
            },
            ..Changes::default()
        };
        let (update, changed) = apply(&current, changes).unwrap();
        assert_eq!(changed, ["tags"]);
        let names: Vec<String> = update.tags.unwrap().iter().map(|t| t.to_string()).collect();
        assert_eq!(names, ["a", "b"]);
    }

    #[test]
    fn env_vars_are_set_and_unset() {
        let env = SecretBody::EnvSet(EnvSet {
            vars: vec![
                EnvVar {
                    key: "A".into(),
                    value: "1".into(),
                },
                EnvVar {
                    key: "B".into(),
                    value: "2".into(),
                },
            ],
        });
        let current = view(env, &[], &[]);
        let changes = Changes {
            set: vec![("A".into(), "9".into()), ("C".into(), "3".into())],
            unset: vec!["B".into()],
            ..Changes::default()
        };
        let (update, changed) = apply(&current, changes).unwrap();
        assert_eq!(changed, ["variables"]);
        let Some(SecretBody::EnvSet(set)) = &update.body else {
            panic!("no env body")
        };
        let pairs: Vec<(&str, &str)> = set
            .vars
            .iter()
            .map(|v| (v.key.as_str(), v.value.as_str()))
            .collect();
        assert_eq!(pairs, [("A", "9"), ("C", "3")]);
    }

    #[test]
    fn options_for_another_kind_are_refused() {
        let current = view(login("me", "pw"), &[], &[]);
        let changes = Changes {
            unset: vec!["A".into()],
            ..Changes::default()
        };
        let err = apply(&current, changes).unwrap_err().to_string();
        assert!(
            err.contains("only work on env secrets; work/github is a login"),
            "{err}"
        );
    }
}
