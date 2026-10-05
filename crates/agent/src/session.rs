//! An unlocked vault held in memory: account keys plus one decrypted data key
//! and metadata per secret. Bodies are decrypted on demand only.

use std::collections::BTreeMap;

use secret_core::AccountKeys;
use secret_core::crypto::{CryptoRng, DataKey, Fingerprint, PublicKey};
use secret_core::vault::{Grant, SealedSecret, SecretId, SecretKind, SecretMeta, Url};

use crate::protocol::{AgentError, ListFilter, NewSecret, SecretSummary, SecretView, display_path};
use crate::store::{Store, StoredSecret};

pub struct Session {
    keys: AccountKeys,
    entries: BTreeMap<SecretId, Entry>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("public_key", self.keys.public_key())
            .field("secrets", &self.entries.len())
            .finish()
    }
}

struct Entry {
    stored: StoredSecret,
    key: DataKey,
    meta: SecretMeta,
}

impl Entry {
    fn open(stored: StoredSecret, keys: &AccountKeys) -> Result<Self, AgentError> {
        let grant = stored
            .grants
            .iter()
            .find(|grant| grant.covers(&stored.secret) && &grant.recipient == keys.public_key())
            .ok_or_else(|| AgentError::Internal {
                message: format!("no grant for {} on this account", stored.secret.id),
            })?;
        let key = grant.open(keys)?;
        let meta = stored.secret.open_meta(&key)?;
        Ok(Self { stored, key, meta })
    }

    fn summary(&self) -> SecretSummary {
        SecretSummary {
            id: self.stored.secret.id,
            revision: self.stored.secret.revision,
            meta: self.meta.clone(),
        }
    }
}

impl Session {
    /// Unlocks the account and decrypts the metadata of every readable secret.
    /// Returns the session and how many stored secrets could not be opened.
    pub fn unlock(store: &Store, password: &[u8]) -> Result<(Self, usize), AgentError> {
        let record = store.read_account()?;
        let keys = record.unlock(password)?;
        let mut entries = BTreeMap::new();
        let mut skipped = 0;
        for stored in store.load_all()? {
            match Entry::open(stored, &keys) {
                Ok(entry) => {
                    entries.insert(entry.stored.secret.id, entry);
                }
                Err(_) => skipped += 1,
            }
        }
        Ok((Self { keys, entries }, skipped))
    }

    pub fn public_key(&self) -> &PublicKey {
        self.keys.public_key()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.keys.fingerprint()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn list(&self, filter: &ListFilter) -> Vec<SecretSummary> {
        let mut out: Vec<SecretSummary> = self
            .entries
            .values()
            .filter(|entry| matches_filter(&entry.meta, filter))
            .map(Entry::summary)
            .collect();
        out.sort_by_cached_key(|summary| (summary.path(), summary.id));
        out
    }

    /// Resolves a user-supplied selector: a UUID, a full `folder/title` path, or
    /// a title that is unique across the vault.
    pub fn resolve(&self, selector: &str) -> Result<SecretId, AgentError> {
        if let Ok(id) = selector.parse::<SecretId>() {
            return if self.entries.contains_key(&id) {
                Ok(id)
            } else {
                Err(AgentError::NotFound {
                    selector: selector.to_owned(),
                })
            };
        }
        let by_path: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| display_path(&e.meta) == selector)
            .collect();
        if let Some(found) = unique(&by_path, selector)? {
            return Ok(found);
        }
        let by_title: Vec<&Entry> = self
            .entries
            .values()
            .filter(|e| e.meta.title == selector)
            .collect();
        if let Some(found) = unique(&by_title, selector)? {
            return Ok(found);
        }
        Err(AgentError::NotFound {
            selector: selector.to_owned(),
        })
    }

    /// Logins whose URL patterns cover `url`, most specific first.
    pub fn matches(&self, url: &str) -> Result<Vec<SecretSummary>, AgentError> {
        let target = Url::parse(url).map_err(|err| AgentError::Invalid {
            message: format!("invalid url {url:?}: {err}"),
        })?;
        let mut scored: Vec<(secret_core::vault::UrlMatch, SecretSummary)> = self
            .entries
            .values()
            .filter(|entry| entry.meta.kind == SecretKind::Login)
            .filter_map(|entry| {
                let patterns = entry.meta.urls.iter().map(String::as_str);
                secret_core::vault::best_url_match(patterns, &target)
                    .map(|score| (score, entry.summary()))
            })
            .collect();
        scored.sort_by(|(a, sa), (b, sb)| {
            b.cmp(a)
                .then_with(|| sa.path().cmp(&sb.path()))
                .then_with(|| sa.id.cmp(&sb.id))
        });
        Ok(scored.into_iter().map(|(_, summary)| summary).collect())
    }

    pub fn get(&self, selector: &str) -> Result<SecretView, AgentError> {
        let id = self.resolve(selector)?;
        let entry = &self.entries[&id];
        let body = entry.stored.secret.open_body(&entry.key)?;
        Ok(SecretView {
            id,
            revision: entry.stored.secret.revision,
            meta: entry.meta.clone(),
            body,
        })
    }

    /// Seals a new secret, grants it to this account, persists and caches it.
    pub fn add(
        &mut self,
        store: &Store,
        rng: &mut impl CryptoRng,
        now: u64,
        new: NewSecret,
    ) -> Result<SecretSummary, AgentError> {
        let NewSecret {
            title,
            folder,
            mut tags,
            urls,
            body,
        } = new;
        let title = validate_title(&title)?;
        tags.sort();
        tags.dedup();

        let mut id_bytes = [0u8; 16];
        rng.fill_bytes(&mut id_bytes);
        let id = SecretId::from_random_bytes(id_bytes);

        let meta = SecretMeta {
            title,
            kind: body.kind(),
            folder,
            tags,
            urls,
            created_at: now,
            updated_at: now,
        };
        let (sealed, key) = SealedSecret::seal(rng, id, 1, &meta, &body)?;
        let grant = Grant::seal(rng, &sealed, &key, *self.keys.public_key())?;
        let stored = StoredSecret {
            secret: sealed,
            grants: vec![grant],
        };
        store.save(&stored)?;

        let entry = Entry { stored, key, meta };
        let summary = entry.summary();
        self.entries.insert(id, entry);
        Ok(summary)
    }

    pub fn remove(&mut self, store: &Store, selector: &str) -> Result<SecretSummary, AgentError> {
        let id = self.resolve(selector)?;
        store.delete(id)?;
        let entry = self.entries.remove(&id).expect("resolved ids exist");
        Ok(entry.summary())
    }
}

fn unique(matches: &[&Entry], selector: &str) -> Result<Option<SecretId>, AgentError> {
    match matches {
        [] => Ok(None),
        [one] => Ok(Some(one.stored.secret.id)),
        many => Err(AgentError::Ambiguous {
            selector: selector.to_owned(),
            matches: many
                .iter()
                .map(|e| format!("{} ({})", display_path(&e.meta), e.stored.secret.id))
                .collect(),
        }),
    }
}

fn matches_filter(meta: &SecretMeta, filter: &ListFilter) -> bool {
    if let Some(folder) = &filter.folder {
        let ok = if filter.exact_folder {
            &meta.folder == folder
        } else {
            meta.folder.starts_with(folder)
        };
        if !ok {
            return false;
        }
    }
    if let Some(tag) = &filter.tag
        && !meta.tags.contains(tag)
    {
        return false;
    }
    if let Some(kind) = filter.kind
        && meta.kind != kind
    {
        return false;
    }
    true
}

fn validate_title(title: &str) -> Result<String, AgentError> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return Err(AgentError::Invalid {
            message: "title must not be empty".to_owned(),
        });
    }
    if trimmed.chars().any(char::is_control) {
        return Err(AgentError::Invalid {
            message: "title must not contain control characters".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use secret_core::AccountRecord;
    use secret_core::crypto::KdfParams;
    use secret_core::vault::{
        EnvSet, EnvVar, FolderPath, Login, Note, SecretBody, SecretKind, Tag,
    };

    fn setup() -> (tempfile::TempDir, Store, StdRng) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Paths::new(dir.path())).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        store.write_account(&record).unwrap();
        (dir, store, rng)
    }

    fn note(path: &str, text: &str, tags: &[&str]) -> NewSecret {
        let (folder, title) = path.rsplit_once('/').unwrap_or(("", path));
        NewSecret {
            title: title.into(),
            folder: FolderPath::parse(folder).unwrap(),
            tags: tags.iter().map(|t| Tag::new(t).unwrap()).collect(),
            urls: vec![],
            body: SecretBody::Note(Note { text: text.into() }),
        }
    }

    #[test]
    fn unlock_requires_the_right_password() {
        let (_dir, store, _) = setup();
        assert_eq!(
            Session::unlock(&store, b"nope").unwrap_err(),
            AgentError::WrongPassword
        );
        let (session, skipped) = Session::unlock(&store, b"pw").unwrap();
        assert!(session.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn add_list_get_remove_and_reload_from_disk() {
        let (_dir, store, mut rng) = setup();
        let (mut session, _) = Session::unlock(&store, b"pw").unwrap();

        let env = NewSecret {
            title: "dev-env".into(),
            folder: FolderPath::parse("projects/api").unwrap(),
            tags: vec![Tag::new("dev").unwrap(), Tag::new("dev").unwrap()],
            urls: vec![],
            body: SecretBody::EnvSet(EnvSet {
                vars: vec![EnvVar {
                    key: "DB_URL".into(),
                    value: "pg://x".into(),
                }],
            }),
        };
        let added = session.add(&store, &mut rng, 100, env).unwrap();
        assert_eq!(added.path(), "projects/api/dev-env");
        assert_eq!(added.meta.tags.len(), 1, "tags are deduplicated");
        assert_eq!(added.meta.created_at, 100);
        session
            .add(
                &store,
                &mut rng,
                101,
                note("personal/bank", "pin 1234", &["money"]),
            )
            .unwrap();

        let all = session.list(&ListFilter::default());
        assert_eq!(
            all.iter().map(SecretSummary::path).collect::<Vec<_>>(),
            ["personal/bank", "projects/api/dev-env"]
        );

        let under_projects = ListFilter {
            folder: Some(FolderPath::parse("projects").unwrap()),
            ..Default::default()
        };
        assert_eq!(session.list(&under_projects).len(), 1);
        let exact_projects = ListFilter {
            exact_folder: true,
            ..under_projects
        };
        assert_eq!(session.list(&exact_projects).len(), 0);
        let tagged = ListFilter {
            tag: Some(Tag::new("money").unwrap()),
            ..Default::default()
        };
        assert_eq!(session.list(&tagged)[0].path(), "personal/bank");
        let kinds = ListFilter {
            kind: Some(SecretKind::EnvSet),
            ..Default::default()
        };
        assert_eq!(session.list(&kinds)[0].path(), "projects/api/dev-env");

        let view = session.get("projects/api/dev-env").unwrap();
        assert_eq!(view.id, added.id);
        assert!(matches!(&view.body, SecretBody::EnvSet(set) if set.vars[0].key == "DB_URL"));

        // Reloading from disk gives the same vault.
        let (reloaded, skipped) = Session::unlock(&store, b"pw").unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(reloaded.len(), 2);
        assert_eq!(
            reloaded.get("bank").unwrap().body,
            SecretBody::Note(Note {
                text: "pin 1234".into()
            })
        );

        let removed = session.remove(&store, "bank").unwrap();
        assert_eq!(removed.path(), "personal/bank");
        assert_eq!(session.len(), 1);
        assert_eq!(Session::unlock(&store, b"pw").unwrap().0.len(), 1);
    }

    #[test]
    fn selector_resolution_rules() {
        let (_dir, store, mut rng) = setup();
        let (mut session, _) = Session::unlock(&store, b"pw").unwrap();
        let a = session
            .add(&store, &mut rng, 1, note("work/github", "a", &[]))
            .unwrap();
        let b = session
            .add(&store, &mut rng, 2, note("personal/github", "b", &[]))
            .unwrap();
        let c = session
            .add(&store, &mut rng, 3, note("root-note", "c", &[]))
            .unwrap();

        assert_eq!(session.resolve(&a.id.to_string()).unwrap(), a.id);
        assert_eq!(session.resolve("work/github").unwrap(), a.id);
        assert_eq!(session.resolve("personal/github").unwrap(), b.id);
        assert_eq!(session.resolve("root-note").unwrap(), c.id);

        match session.resolve("github").unwrap_err() {
            AgentError::Ambiguous { matches, .. } => assert_eq!(matches.len(), 2),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            session.resolve("nothing").unwrap_err(),
            AgentError::NotFound { .. }
        ));
        assert!(matches!(
            session
                .resolve(&SecretId::from_random_bytes([9; 16]).to_string())
                .unwrap_err(),
            AgentError::NotFound { .. }
        ));
    }

    #[test]
    fn matches_rank_logins_by_url_specificity() {
        let (_dir, store, mut rng) = setup();
        let (mut session, _) = Session::unlock(&store, b"pw").unwrap();
        let login = |title: &str, urls: &[&str]| NewSecret {
            title: title.into(),
            folder: FolderPath::parse("dev").unwrap(),
            tags: vec![],
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            body: SecretBody::Login(Login {
                username: "u".into(),
                password: "p".into(),
                totp: None,
                notes: String::new(),
            }),
        };
        session
            .add(&store, &mut rng, 1, login("wild", &["*.example.com"]))
            .unwrap();
        session
            .add(&store, &mut rng, 2, login("host", &["dev.example.com"]))
            .unwrap();
        session
            .add(
                &store,
                &mut rng,
                3,
                login("admin", &["https://dev.example.com/admin", "junk"]),
            )
            .unwrap();
        session
            .add(&store, &mut rng, 4, login("other", &["other.com"]))
            .unwrap();
        // A note with a matching URL is not a login and must be ignored.
        let mut n = note("dev/note", "x", &[]);
        n.urls = vec!["dev.example.com".into()];
        session.add(&store, &mut rng, 5, n).unwrap();

        let paths = |url: &str| {
            session
                .matches(url)
                .unwrap()
                .iter()
                .map(SecretSummary::path)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            paths("https://dev.example.com/admin/users"),
            ["dev/admin", "dev/host", "dev/wild"]
        );
        assert_eq!(paths("http://dev.example.com/"), ["dev/host", "dev/wild"]);
        assert_eq!(paths("https://nothing.net/"), Vec::<String>::new());
        assert!(matches!(
            session.matches("not a url").unwrap_err(),
            AgentError::Invalid { .. }
        ));
    }

    #[test]
    fn titles_are_validated() {
        let (_dir, store, mut rng) = setup();
        let (mut session, _) = Session::unlock(&store, b"pw").unwrap();
        assert!(matches!(
            session
                .add(&store, &mut rng, 1, note("  ", "x", &[]))
                .unwrap_err(),
            AgentError::Invalid { .. }
        ));
        let padded = session
            .add(&store, &mut rng, 1, note("  padded  ", "x", &[]))
            .unwrap();
        assert_eq!(padded.meta.title, "padded");
        let login = NewSecret {
            title: "site".into(),
            folder: FolderPath::root(),
            tags: vec![],
            urls: vec!["https://example.com".into()],
            body: SecretBody::Login(Login {
                username: "u".into(),
                password: "p".into(),
                totp: None,
                notes: String::new(),
            }),
        };
        assert_eq!(
            session.add(&store, &mut rng, 1, login).unwrap().meta.kind,
            SecretKind::Login
        );
    }
}
