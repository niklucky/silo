//! An unlocked vault held in memory: account keys plus one decrypted data key
//! and metadata per secret. Bodies are decrypted on demand only.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use silo_core::AccountKeys;
use silo_core::account::Identity;
use silo_core::crypto::{CryptoRng, DataKey, Fingerprint, PublicKey};
use silo_core::sync::Tombstone;
use silo_core::vault::{Grant, SealedSecret, SecretBody, SecretId, SecretKind, SecretMeta, Url};

use crate::protocol::{
    AgentError, ListFilter, NewSecret, SecretSummary, SecretUpdate, SecretView, display_path,
};
use crate::store::{Store, StoredSecret};

pub struct Session {
    keys: AccountKeys,
    entries: BTreeMap<SecretId, Entry>,
    trust: Trust,
}

/// Local pins are explicit, never populated from server responses. Ownership
/// bindings survive deletion/logout so a peer cannot take over an existing id.
#[derive(Default, Serialize, Deserialize)]
struct Trust {
    peers: BTreeMap<String, Identity>,
    owners: BTreeMap<SecretId, Identity>,
    #[serde(default)]
    local_only: BTreeSet<SecretId>,
}

pub fn revision_token(stored: &StoredSecret) -> String {
    let digest: String = stored
        .secret
        .digest()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{}:{}:{digest}", stored.secret.id, stored.secret.revision)
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
    local_only: bool,
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
        Ok(Self {
            stored,
            key,
            meta,
            local_only: false,
        })
    }

    fn view(&self) -> Result<SecretView, AgentError> {
        Ok(SecretView {
            local_only: self.local_only,
            id: self.stored.secret.id,
            revision: self.stored.secret.revision,
            meta: self.meta.clone(),
            body: self.stored.secret.open_body(&self.key)?,
        })
    }

    fn summary(&self) -> SecretSummary {
        SecretSummary {
            local_only: self.local_only,
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
        Self::open(store, record.unlock(password)?)
    }

    /// Like [`unlock`](Self::unlock) with keys the caller already has.
    pub fn open(store: &Store, keys: AccountKeys) -> Result<(Self, usize), AgentError> {
        let mut trust: Trust = store.read_trust()?.unwrap_or_default();
        let original_owner_count = trust.owners.len();
        let original_private_count = trust.local_only.len();
        let mut entries = BTreeMap::new();
        let mut skipped = 0;
        for stored in store.load_all()? {
            match Entry::open(stored, &keys) {
                Ok(mut entry) => {
                    let id = entry.stored.secret.id;
                    if store.is_local_only(id) {
                        trust.local_only.insert(id);
                    }
                    entry.local_only = trust.local_only.contains(&id);
                    // Bind pre-existing local secrets before they can be deleted.
                    // Unsigned entries are legacy local secrets; imported shared
                    // entries always have a persisted owner binding and signature.
                    trust
                        .owners
                        .entry(entry.stored.secret.id)
                        .or_insert(keys.identity());
                    entries.insert(entry.stored.secret.id, entry);
                }
                Err(_) => skipped += 1,
            }
        }
        if trust.owners.len() != original_owner_count
            || trust.local_only.len() != original_private_count
        {
            store.write_trust(&trust)?;
        }
        Ok((
            Self {
                keys,
                entries,
                trust,
            },
            skipped,
        ))
    }

    pub fn public_key(&self) -> &PublicKey {
        self.keys.public_key()
    }

    pub fn identity(&self) -> Identity {
        self.keys.identity()
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

    /// Logins whose URL patterns cover `url`, most specific first. With `site`,
    /// followed by the logins saved for other hosts of the same site.
    pub fn matches(&self, url: &str, site: bool) -> Result<Vec<SecretSummary>, AgentError> {
        let target = Url::parse(url).map_err(|err| AgentError::Invalid {
            message: format!("invalid url {url:?}: {err}"),
        })?;
        let logins = || {
            self.entries
                .values()
                .filter(|entry| entry.meta.kind == SecretKind::Login)
        };
        let mut scored: Vec<(silo_core::vault::UrlMatch, SecretSummary)> = logins()
            .filter_map(|entry| {
                let patterns = entry.meta.urls.iter().map(String::as_str);
                silo_core::vault::best_url_match(patterns, &target)
                    .map(|score| (score, entry.summary()))
            })
            .collect();
        scored.sort_by(|(a, sa), (b, sb)| {
            b.cmp(a)
                .then_with(|| sa.path().cmp(&sb.path()))
                .then_with(|| sa.id.cmp(&sb.id))
        });
        let mut out: Vec<SecretSummary> = scored.into_iter().map(|(_, summary)| summary).collect();
        if site {
            // Entries iterate in id order, so sort the rest by path like `list` does.
            let mut rest: Vec<SecretSummary> = logins()
                .filter(|entry| !out.iter().any(|m| m.id == entry.stored.secret.id))
                .filter(|entry| {
                    entry
                        .meta
                        .urls
                        .iter()
                        .any(|pattern| silo_core::vault::same_site(pattern, &target))
                })
                .map(Entry::summary)
                .collect();
            rest.sort_by_cached_key(|summary| (summary.path(), summary.id));
            out.extend(rest);
        }
        Ok(out)
    }

    pub fn get(&self, selector: &str) -> Result<SecretView, AgentError> {
        let id = self.resolve(selector)?;
        self.entries[&id].view()
    }

    /// Re-seals a secret as a new revision under a fresh data key, granted again
    /// to everyone who could read the current one. The current revision goes to
    /// the store's history first.
    pub fn update(
        &mut self,
        store: &Store,
        rng: &mut impl CryptoRng,
        now: u64,
        update: SecretUpdate,
    ) -> Result<SecretSummary, AgentError> {
        let id = self.resolve(&update.selector)?;
        self.require_owner(id)?;
        let entry = &self.entries[&id];
        let current = entry.stored.secret.revision;
        if let Some(expected) = update.revision
            && expected != current
        {
            return Err(AgentError::Stale {
                selector: update.selector,
                expected,
                current,
            });
        }
        let SecretUpdate {
            title,
            folder,
            tags,
            urls,
            basic_auth,
            body,
            ..
        } = update;
        let body = match body {
            Some(body) if body.kind() != entry.meta.kind => {
                return Err(AgentError::Invalid {
                    message: format!(
                        "{} holds a {:?}, not a {:?}",
                        display_path(&entry.meta),
                        entry.meta.kind,
                        body.kind()
                    ),
                });
            }
            Some(body) => body,
            None => entry.stored.secret.open_body(&entry.key)?,
        };
        let mut meta = entry.meta.clone();
        if let Some(title) = title {
            meta.title = validate_title(&title)?;
        }
        if let Some(folder) = folder {
            meta.folder = folder;
        }
        if let Some(mut tags) = tags {
            tags.sort();
            tags.dedup();
            meta.tags = tags;
        }
        if let Some(urls) = urls {
            meta.urls = urls;
        }
        if let Some(basic_auth) = basic_auth {
            meta.basic_auth = basic_auth;
            check_basic_auth(&meta)?;
        }
        meta.updated_at = now;

        let revision = current.checked_add(1).ok_or_else(|| AgentError::Internal {
            message: format!("{id} has run out of revisions"),
        })?;
        self.reseal(store, rng, id, revision, &meta, &body, true)?;
        Ok(self.entries[&id].summary())
    }

    /// Seals `meta` and `body` as `revision` of an existing secret under a
    /// fresh data key, granted again to everyone who could read the current
    /// revision, and makes it the current one. With `archive_current`, the
    /// replaced revision goes to history first; otherwise it is dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn reseal(
        &mut self,
        store: &Store,
        rng: &mut impl CryptoRng,
        id: SecretId,
        revision: u32,
        meta: &SecretMeta,
        body: &SecretBody,
        archive_current: bool,
    ) -> Result<StoredSecret, AgentError> {
        let entry = self.entry(id)?;
        let mut recipients = Vec::new();
        for grant in entry
            .stored
            .grants
            .iter()
            .filter(|g| g.covers(&entry.stored.secret))
        {
            if !recipients.contains(&grant.recipient) {
                recipients.push(grant.recipient);
            }
        }
        self.reseal_for(
            store,
            rng,
            id,
            revision,
            meta,
            body,
            archive_current,
            &recipients,
        )
    }

    /// Rebase content using the authoritative server recipient set. Offline
    /// edits must never resurrect a recipient revoked by another device.
    #[allow(clippy::too_many_arguments)]
    pub fn reseal_for(
        &mut self,
        store: &Store,
        rng: &mut impl CryptoRng,
        id: SecretId,
        revision: u32,
        meta: &SecretMeta,
        body: &SecretBody,
        archive_current: bool,
        recipients: &[PublicKey],
    ) -> Result<StoredSecret, AgentError> {
        self.require_owner(id)?;
        let entry = self.entry(id)?;
        let (sealed, key) = SealedSecret::seal(rng, &self.keys, id, revision, meta, body)?;
        let grants = recipients
            .iter()
            .map(|recipient| Grant::seal(rng, &self.keys, &sealed, &key, *recipient))
            .collect::<Result<Vec<_>, _>>()?;
        let stored = StoredSecret {
            secret: sealed,
            grants,
        };
        if archive_current {
            store.archive(&entry.stored)?;
        }
        store.save(&stored)?;
        self.entries.insert(
            id,
            Entry {
                stored: stored.clone(),
                key,
                meta: meta.clone(),
                local_only: self.is_local_only(id),
            },
        );
        Ok(stored)
    }

    /// Earlier revisions of a secret that this account can still open, newest first.
    pub fn history(&self, store: &Store, selector: &str) -> Result<Vec<SecretView>, AgentError> {
        let id = self.resolve(selector)?;
        let mut out = Vec::new();
        for stored in store.history(id)? {
            if let Ok(mut entry) = Entry::open(stored, &self.keys) {
                entry.local_only = self.is_local_only(id);
                out.push(entry.view()?);
            }
        }
        Ok(out)
    }

    /// Seals a new secret, grants it to this account, persists and caches it.
    pub fn add(
        &mut self,
        store: &Store,
        rng: &mut impl CryptoRng,
        now: u64,
        new: NewSecret,
    ) -> Result<SecretSummary, AgentError> {
        self.add_with_policy(store, rng, now, new, false)
    }

    pub fn add_local(
        &mut self,
        store: &Store,
        rng: &mut impl CryptoRng,
        now: u64,
        new: NewSecret,
    ) -> Result<SecretSummary, AgentError> {
        self.add_with_policy(store, rng, now, new, true)
    }

    fn add_with_policy(
        &mut self,
        store: &Store,
        rng: &mut impl CryptoRng,
        now: u64,
        new: NewSecret,
        local_only: bool,
    ) -> Result<SecretSummary, AgentError> {
        let NewSecret {
            title,
            folder,
            mut tags,
            urls,
            basic_auth,
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
            basic_auth,
            created_at: now,
            updated_at: now,
        };
        check_basic_auth(&meta)?;
        let (sealed, key) = SealedSecret::seal(rng, &self.keys, id, 1, &meta, &body)?;
        let grant = Grant::seal(rng, &self.keys, &sealed, &key, *self.keys.public_key())?;
        let stored = StoredSecret {
            secret: sealed,
            grants: vec![grant],
        };
        self.trust.owners.insert(id, self.identity());
        if local_only {
            self.trust.local_only.insert(id);
        }
        store.write_trust(&self.trust)?;
        if local_only {
            store.save_local(&stored)?;
        } else {
            store.save(&stored)?;
        }

        let entry = Entry {
            stored,
            key,
            meta,
            local_only,
        };
        let summary = entry.summary();
        self.entries.insert(id, entry);
        Ok(summary)
    }

    pub fn remove(&mut self, store: &Store, selector: &str) -> Result<SecretSummary, AgentError> {
        let id = self.resolve(selector)?;
        self.require_owner(id)?;
        store.delete(id)?;
        let entry = self.entries.remove(&id).expect("resolved ids exist");
        Ok(entry.summary())
    }

    // ---------- for sync ----------

    /// Every secret's id and current revision.
    pub fn revisions(&self) -> Vec<(SecretId, u32)> {
        self.entries
            .iter()
            .map(|(id, entry)| (*id, entry.stored.secret.revision))
            .collect()
    }

    pub fn stored(&self, id: SecretId) -> Option<&StoredSecret> {
        self.entries.get(&id).map(|entry| &entry.stored)
    }

    pub fn path_of(&self, id: SecretId) -> Option<String> {
        self.entries.get(&id).map(|entry| display_path(&entry.meta))
    }

    /// True if this account signed the revision and every grant on it.
    pub fn signed_by_me(&self, stored: &StoredSecret) -> bool {
        stored.verify(&self.keys.identity().signing_key).is_ok()
    }

    pub fn is_local_only(&self, id: SecretId) -> bool {
        self.trust.local_only.contains(&id)
    }

    pub fn is_syncable(&self, id: SecretId) -> bool {
        self.is_owned(id) && !self.is_local_only(id)
    }

    pub fn check_version(&self, selector: &str, expected: &str) -> Result<(), AgentError> {
        let id = self.resolve(selector)?;
        if revision_token(&self.entry(id)?.stored) != expected {
            return Err(AgentError::Invalid { message: "the file changed since this copy was read; export the current file to another path and merge, or use --force to replace it deliberately".into() });
        }
        Ok(())
    }

    pub fn is_owned(&self, id: SecretId) -> bool {
        self.owner(id) == self.identity()
    }

    pub fn owner(&self, id: SecretId) -> Identity {
        self.trust
            .owners
            .get(&id)
            .copied()
            .unwrap_or_else(|| self.identity())
    }

    pub fn require_owner(&self, id: SecretId) -> Result<(), AgentError> {
        if !self.is_owned(id) {
            return Err(AgentError::Invalid { message: "shared secrets are read-only; only their owner can change, share or delete them".into() });
        }
        Ok(())
    }

    /// Bind every revision to its original author, including across restarts.
    pub fn trusted_revision(&self, stored: &StoredSecret) -> bool {
        let id = stored.secret.id;
        if self.trust.owners.contains_key(&id) || self.entries.contains_key(&id) {
            return stored.verify(&self.owner(id).signing_key).is_ok();
        }
        self.signed_by_me(stored)
            || self
                .trust
                .peers
                .values()
                .any(|peer| stored.verify(&peer.signing_key).is_ok())
    }

    pub fn pin_peer(
        &mut self,
        store: &Store,
        server: &str,
        username: &str,
        identity: Identity,
        fingerprint: &str,
    ) -> Result<(), AgentError> {
        if identity.fingerprint().to_string() != fingerprint.trim() {
            return Err(AgentError::Invalid {
                message: "fingerprint does not match; compare with your teammate's `silo status`"
                    .into(),
            });
        }
        let key = format!("{server}|{username}");
        if self
            .trust
            .peers
            .get(&key)
            .is_some_and(|old| old != &identity)
        {
            return Err(AgentError::Invalid {
                message: "this peer's identity changed; the existing fingerprint pin was retained"
                    .into(),
            });
        }
        self.trust.peers.insert(key, identity);
        store.write_trust(&self.trust)?;
        Ok(())
    }

    pub fn peer(&self, server: &str, username: &str) -> Result<Identity, AgentError> {
        self.trust
            .peers
            .get(&format!("{server}|{username}"))
            .copied()
            .ok_or_else(|| AgentError::Invalid {
                message: format!(
                    "verify {username}'s fingerprint first with `silo connections verify`"
                ),
            })
    }

    pub fn prepare_share(
        &self,
        rng: &mut impl CryptoRng,
        now: u64,
        selector: &str,
        recipient: PublicKey,
        revoke: bool,
    ) -> Result<(u32, StoredSecret), AgentError> {
        let id = self.resolve(selector)?;
        self.require_owner(id)?;
        if self.is_local_only(id) {
            return Err(AgentError::Invalid {
                message: "local-only secrets cannot be shared".into(),
            });
        }
        if recipient == *self.public_key() {
            return Err(AgentError::Invalid {
                message: "cannot change the owner's grant".into(),
            });
        }
        let entry = self.entry(id)?;
        let mut recipients: Vec<_> = entry
            .stored
            .grants
            .iter()
            .map(|g| g.recipient)
            .filter(|r| *r != recipient)
            .collect();
        if !revoke {
            recipients.push(recipient);
        }
        let mut meta = entry.meta.clone();
        meta.updated_at = now;
        let base = entry.stored.secret.revision;
        let body = entry.stored.secret.open_body(&entry.key)?;
        Ok((
            base,
            self.prepare_revision(rng, id, base, &meta, &body, &recipients)?,
        ))
    }

    fn prepare_revision(
        &self,
        rng: &mut impl CryptoRng,
        id: SecretId,
        base: u32,
        meta: &SecretMeta,
        body: &SecretBody,
        recipients: &[PublicKey],
    ) -> Result<StoredSecret, AgentError> {
        let revision = base.checked_add(1).ok_or_else(|| AgentError::Invalid {
            message: "revision limit reached".into(),
        })?;
        let (secret, key) = SealedSecret::seal(rng, &self.keys, id, revision, meta, body)?;
        let grants = recipients
            .iter()
            .map(|recipient| Grant::seal(rng, &self.keys, &secret, &key, *recipient))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StoredSecret { secret, grants })
    }

    /// Decrypts a revision this account holds a grant for.
    pub fn open_parts(
        &self,
        stored: &StoredSecret,
    ) -> Result<(SecretMeta, SecretBody), AgentError> {
        let entry = Entry::open(stored.clone(), &self.keys)?;
        let body = entry.stored.secret.open_body(&entry.key)?;
        Ok((entry.meta, body))
    }

    /// Takes a revision from elsewhere as the current one. With
    /// `archive_current`, the replaced local revision goes to history.
    pub fn accept(
        &mut self,
        store: &Store,
        stored: StoredSecret,
        archive_current: bool,
    ) -> Result<(), AgentError> {
        if self.is_local_only(stored.secret.id) {
            return Err(AgentError::Invalid {
                message: "a remote revision cannot replace a local-only secret".into(),
            });
        }
        if !self.trusted_revision(&stored) {
            return Err(AgentError::Invalid {
                message: "revision is not signed by its trusted owner".into(),
            });
        }
        let id = stored.secret.id;
        if !self.trust.owners.contains_key(&id) {
            let owner = if self.signed_by_me(&stored) {
                self.identity()
            } else {
                *self
                    .trust
                    .peers
                    .values()
                    .find(|peer| stored.verify(&peer.signing_key).is_ok())
                    .expect("trusted above")
            };
            self.trust.owners.insert(id, owner);
            store.write_trust(&self.trust)?;
        }
        let entry = Entry::open(stored, &self.keys)?;
        let id = entry.stored.secret.id;
        if archive_current && let Some(current) = self.entries.get(&id) {
            store.archive(&current.stored)?;
        }
        store.save(&entry.stored)?;
        self.entries.insert(id, entry);
        Ok(())
    }

    /// Removes a secret by id, with its local history.
    pub fn remove_id(&mut self, store: &Store, id: SecretId) -> Result<(), AgentError> {
        if self.entries.remove(&id).is_some() {
            store.delete(id)?;
        }
        Ok(())
    }

    /// Signs a revision written before signing existed, and its grants, and
    /// stores it again: as the current revision, or in history.
    pub fn sign_if_needed(
        &mut self,
        store: &Store,
        mut stored: StoredSecret,
    ) -> Result<StoredSecret, AgentError> {
        self.require_owner(stored.secret.id)?;
        if self.signed_by_me(&stored) {
            return Ok(stored);
        }
        stored.secret.sign(&self.keys);
        for grant in &mut stored.grants {
            grant.sign(&self.keys, &stored.secret);
        }
        let id = stored.secret.id;
        match self.entries.get_mut(&id) {
            Some(entry) if entry.stored.secret.revision == stored.secret.revision => {
                store.save(&stored)?;
                entry.stored = stored.clone();
            }
            _ => store.archive(&stored)?,
        }
        Ok(stored)
    }

    pub fn tombstone(&self, id: SecretId, revision: u32, now: u64) -> Tombstone {
        Tombstone::seal(&self.keys, id, revision, now)
    }

    fn entry(&self, id: SecretId) -> Result<&Entry, AgentError> {
        self.entries.get(&id).ok_or_else(|| AgentError::NotFound {
            selector: id.to_string(),
        })
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

fn check_basic_auth(meta: &SecretMeta) -> Result<(), AgentError> {
    if meta.basic_auth && meta.kind != SecretKind::Login {
        return Err(AgentError::Invalid {
            message: format!(
                "{} is not a login, so it cannot answer Basic Auth",
                display_path(meta)
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Paths;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use silo_core::AccountRecord;
    use silo_core::crypto::KdfParams;
    use silo_core::vault::{EnvSet, EnvVar, FolderPath, Login, Note, SecretBody, SecretKind, Tag};

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
            basic_auth: false,
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
            basic_auth: false,
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
            basic_auth: false,
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
                .matches(url, false)
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
            session.matches("not a url", false).unwrap_err(),
            AgentError::Invalid { .. }
        ));
    }

    fn login(title: &str, username: &str, urls: &[&str]) -> NewSecret {
        NewSecret {
            title: title.into(),
            folder: FolderPath::parse("web").unwrap(),
            tags: vec![],
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            basic_auth: false,
            body: SecretBody::Login(Login {
                username: username.into(),
                password: "old".into(),
                totp: None,
                notes: "keep me".into(),
            }),
        }
    }

    #[test]
    fn site_matches_follow_direct_ones() {
        let (_dir, store, mut rng) = setup();
        let (mut session, _) = Session::unlock(&store, b"pw").unwrap();
        session
            .add(
                &store,
                &mut rng,
                1,
                login("prod", "nikita", &["https://cutstoryapp.com"]),
            )
            .unwrap();
        session
            .add(
                &store,
                &mut rng,
                2,
                login("admin", "nikita", &["admin.cutstoryapp.com"]),
            )
            .unwrap();
        session
            .add(
                &store,
                &mut rng,
                3,
                login("dev", "nikita", &["dev.cutstoryapp.com"]),
            )
            .unwrap();
        session
            .add(
                &store,
                &mut rng,
                4,
                login("other", "nikita", &["cutstoryapp.net"]),
            )
            .unwrap();
        let paths = |site| {
            session
                .matches("https://dev.cutstoryapp.com/signup", site)
                .unwrap()
                .iter()
                .map(SecretSummary::path)
                .collect::<Vec<_>>()
        };
        assert_eq!(paths(false), ["web/dev"]);
        assert_eq!(paths(true), ["web/dev", "web/admin", "web/prod"]);
    }

    #[test]
    fn basic_auth_is_for_logins_only() {
        let (_dir, store, mut rng) = setup();
        let (mut session, _) = Session::unlock(&store, b"pw").unwrap();
        let gate = NewSecret {
            basic_auth: true,
            ..login("gate", "admin", &["example.com"])
        };
        assert!(
            session
                .add(&store, &mut rng, 1, gate)
                .unwrap()
                .meta
                .basic_auth
        );
        let not_a_login = NewSecret {
            basic_auth: true,
            ..note("notes/n", "x", &[])
        };
        assert!(matches!(
            session.add(&store, &mut rng, 2, not_a_login),
            Err(AgentError::Invalid { .. })
        ));

        session
            .add(&store, &mut rng, 3, note("notes/n", "x", &[]))
            .unwrap();
        let mark = |selector: &str, basic_auth| SecretUpdate {
            selector: selector.into(),
            revision: None,
            title: None,
            folder: None,
            tags: None,
            urls: None,
            basic_auth: Some(basic_auth),
            body: None,
        };
        assert!(matches!(
            session.update(&store, &mut rng, 4, mark("notes/n", true)),
            Err(AgentError::Invalid { .. })
        ));
        let cleared = session
            .update(&store, &mut rng, 5, mark("web/gate", false))
            .unwrap();
        assert!(!cleared.meta.basic_auth);

        // It survives sealing: a fresh unlock reads it back from disk.
        session
            .update(&store, &mut rng, 6, mark("web/gate", true))
            .unwrap();
        let (reloaded, _) = Session::unlock(&store, b"pw").unwrap();
        assert!(reloaded.get("web/gate").unwrap().meta.basic_auth);
    }

    #[test]
    fn update_makes_a_new_revision_and_keeps_the_old_one() {
        let (_dir, store, mut rng) = setup();
        let (mut session, _) = Session::unlock(&store, b"pw").unwrap();
        let added = session
            .add(
                &store,
                &mut rng,
                10,
                login("prod", "nikita", &["cutstoryapp.com"]),
            )
            .unwrap();
        let change = |revision, password: &str| SecretUpdate {
            selector: "web/prod".into(),
            revision,
            title: None,
            folder: None,
            tags: None,
            urls: Some(vec![
                "cutstoryapp.com".into(),
                "https://dev.cutstoryapp.com".into(),
            ]),
            basic_auth: None,
            body: Some(SecretBody::Login(Login {
                username: "nikita".into(),
                password: password.into(),
                totp: None,
                notes: "keep me".into(),
            })),
        };
        let updated = session
            .update(&store, &mut rng, 20, change(Some(1), "new"))
            .unwrap();
        // Both revisions and their grants carry this account's signature.
        let signer = session.identity().signing_key;
        let current = store.load_all().unwrap().remove(0);
        let replaced = store.history(added.id).unwrap().remove(0);
        for stored in [&current, &replaced] {
            assert_eq!(stored.secret.verify(&signer), Ok(()));
            assert_eq!(stored.grants[0].verify(&stored.secret, &signer), Ok(()));
        }
        assert_eq!((current.secret.revision, replaced.secret.revision), (2, 1));
        assert_eq!(updated.id, added.id);
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.meta.created_at, 10);
        assert_eq!(updated.meta.updated_at, 20);
        assert_eq!(updated.meta.title, "prod");
        assert_eq!(
            session
                .matches("https://dev.cutstoryapp.com/", false)
                .unwrap()[0]
                .id,
            added.id
        );

        // Based on a revision that is no longer current: refused, nothing written.
        assert_eq!(
            session
                .update(&store, &mut rng, 30, change(Some(1), "lost"))
                .unwrap_err(),
            AgentError::Stale {
                selector: "web/prod".into(),
                expected: 1,
                current: 2
            }
        );

        // Survives a reload; the replaced revision is still readable.
        let (reloaded, skipped) = Session::unlock(&store, b"pw").unwrap();
        assert_eq!(skipped, 0);
        let view = reloaded.get("web/prod").unwrap();
        assert_eq!(view.revision, 2);
        assert!(matches!(&view.body, SecretBody::Login(l) if l.password == "new"));
        let history = reloaded.history(&store, "web/prod").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].revision, 1);
        assert!(matches!(&history[0].body, SecretBody::Login(l) if l.password == "old"));

        // A body of another kind is refused.
        let mut wrong = change(None, "x");
        wrong.body = Some(SecretBody::Note(Note { text: "x".into() }));
        assert!(matches!(
            session.update(&store, &mut rng, 40, wrong).unwrap_err(),
            AgentError::Invalid { .. }
        ));

        // Only the title, without a revision check: the body is carried over.
        let rename = SecretUpdate {
            selector: "web/prod".into(),
            revision: None,
            title: Some("cutstory".into()),
            folder: None,
            tags: None,
            urls: None,
            basic_auth: None,
            body: None,
        };
        let renamed = session.update(&store, &mut rng, 50, rename).unwrap();
        assert_eq!(renamed.revision, 3);
        assert!(
            matches!(&session.get("web/cutstory").unwrap().body, SecretBody::Login(l) if l.password == "new")
        );
        assert_eq!(session.history(&store, "web/cutstory").unwrap().len(), 2);

        session.remove(&store, "web/cutstory").unwrap();
        assert!(store.history(added.id).unwrap().is_empty());
    }

    #[test]
    fn verified_peers_cannot_replace_another_owners_document_even_after_restart() {
        let (_dir, store, mut rng) = setup();
        let (mut session, _) = Session::unlock(&store, b"pw").unwrap();
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (_, bob) = AccountRecord::create(&mut rng, b"bob", kdf).unwrap();
        let kdf = KdfParams::new(&mut rng, 256, 1, 1);
        let (_, carol) = AccountRecord::create(&mut rng, b"carol", kdf).unwrap();
        for (name, peer) in [("bob", &bob), ("carol", &carol)] {
            session
                .pin_peer(
                    &store,
                    "https://example.test",
                    name,
                    peer.identity(),
                    &peer.fingerprint().to_string(),
                )
                .unwrap();
        }
        // A server swapping either public key cannot replace a saved pin.
        assert!(
            session
                .pin_peer(
                    &store,
                    "https://example.test",
                    "bob",
                    carol.identity(),
                    &carol.fingerprint().to_string()
                )
                .is_err()
        );
        let id = SecretId::from_random_bytes([12; 16]);
        let new = note("api/env", "original", &[]);
        let meta = SecretMeta {
            title: new.title,
            folder: new.folder,
            kind: SecretKind::Note,
            tags: vec![],
            urls: vec![],
            basic_auth: false,
            created_at: 1,
            updated_at: 1,
        };
        let (secret, key) = SealedSecret::seal(&mut rng, &bob, id, 1, &meta, &new.body).unwrap();
        let grant = Grant::seal(&mut rng, &bob, &secret, &key, *session.public_key()).unwrap();
        session
            .accept(
                &store,
                StoredSecret {
                    secret,
                    grants: vec![grant],
                },
                false,
            )
            .unwrap();
        let (secret, key) = SealedSecret::seal(&mut rng, &carol, id, 2, &meta, &new.body).unwrap();
        let grant = Grant::seal(&mut rng, &carol, &secret, &key, *session.public_key()).unwrap();
        let forged = StoredSecret {
            secret,
            grants: vec![grant],
        };
        assert!(!session.trusted_revision(&forged));
        assert!(session.accept(&store, forged.clone(), true).is_err());
        session.remove_id(&store, id).unwrap();
        let (mut reloaded, _) = Session::unlock(&store, b"pw").unwrap();
        assert!(!reloaded.trusted_revision(&forged));
        assert!(reloaded.accept(&store, forged, false).is_err());
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
            basic_auth: false,
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
