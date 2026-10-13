//! One sync run: pull everything new, then push local changes in rounds.
//!
//! Conflicts never lose an edit. When a secret changed both here and on the
//! server, the newer edit (by its `updated_at`) becomes the current revision
//! and the other one stays in history, here and on the server:
//!
//! ```text
//! server:  … R            (theirs)
//! yours newer:   R → R+1 = yours
//! theirs newer:  R → R+1 = yours → R+2 = theirs again
//! ```
//!
//! An edit also wins over a deletion, whichever side made which.

use serde::{Deserialize, Serialize};
use silo_core::crypto::CryptoRng;
use silo_core::sync::{
    Change, HistoryQuery, HistoryRequest, PushItem, PushRequest, PushResult, Tombstone,
};
use silo_core::vault::{SecretId, StoredSecret};

use super::SyncError;
use super::http::HttpClient;
use super::state::{Rejection, SyncState};
use crate::session::Session;
use crate::store::Store;

/// Items per push request; large file secrets make batches big.
pub const PUSH_BATCH: usize = 100;
/// Each round pushes at most one revision per secret, so a secret with a
/// chain of local revisions needs a round for each.
const MAX_ROUNDS: usize = 8;

/// What one run did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    /// Secrets added or changed from the server.
    pub pulled: usize,
    /// Secrets deleted because they were deleted elsewhere.
    pub removed: usize,
    /// Revisions and deletions the server accepted.
    pub pushed: usize,
    /// One line per conflict, saying which side won.
    pub conflicts: Vec<String>,
    /// One line per change the server refused.
    pub rejected: Vec<String>,
    /// Changes from the server that were not signed by this account, or could
    /// not be opened. Ignored.
    pub skipped: usize,
}

/// A run in progress: what it did so far, and the revisions it skipped over
/// that should go into local history.
#[derive(Default)]
struct Progress {
    report: SyncReport,
    gaps: Vec<HistoryQuery>,
}

impl Progress {
    /// Revisions between `known` and `received` went by on the server without
    /// this device seeing them.
    fn gap(&mut self, id: SecretId, known: Option<u32>, received: u32) {
        if let Some(known) = known
            && received > known.saturating_add(1)
        {
            self.gaps.push(HistoryQuery {
                secret_id: id,
                after: known,
                before: received,
            });
        }
    }
}

/// Everything a run touches, borrowed under the agent's lock.
pub struct Vault<'a> {
    pub store: &'a Store,
    pub session: &'a mut Session,
    pub state: &'a mut SyncState,
}

impl Vault<'_> {
    pub fn save(&self) -> Result<(), SyncError> {
        Ok(self.store.write_sync(self.state)?)
    }
}

/// Lends the vault to the engine for one step at a time, so the agent's lock
/// is never held during network calls.
pub trait VaultAccess {
    /// Fails with [`SyncError::Locked`] or [`SyncError::NotConfigured`].
    fn with_vault<R>(
        &self,
        f: impl FnOnce(&mut Vault<'_>) -> Result<R, SyncError>,
    ) -> Result<R, SyncError>;
}

/// Runs one sync and records its outcome in the sync state.
pub fn run(access: &impl VaultAccess, now: &dyn Fn() -> u64) -> Result<SyncReport, SyncError> {
    let client =
        access.with_vault(|v| Ok(HttpClient::new(&v.state.server)?.with_token(&v.state.token)))?;
    let result = run_with(access, &client);
    let error = result.as_ref().err().map(ToString::to_string);
    let recorded = access.with_vault(|v| {
        if error.is_none() {
            v.state.last_sync = Some(now());
        }
        v.state.last_error = error;
        v.save()
    });
    let report = result?;
    recorded?;
    Ok(report)
}

fn run_with(access: &impl VaultAccess, client: &HttpClient) -> Result<SyncReport, SyncError> {
    let mut progress = Progress::default();
    let mut rng = rand::rng();

    loop {
        let since = access.with_vault(|v| Ok(v.state.cursor))?;
        let reply = client.changes(since)?;
        let more = access.with_vault(|v| {
            let more = if reply.cursor < since {
                // The server has less than we pulled: it was restored from an
                // older backup. Start over; anything it lacks is pushed again.
                v.state.cursor = 0;
                v.state.known.clear();
                v.state.deleted_remotely.clear();
                true
            } else {
                for change in reply.changes {
                    apply_change(v, &mut rng, change, &mut progress)?;
                }
                v.state.cursor = reply.cursor;
                v.state.account_version = reply.account_version;
                reply.more
            };
            v.save()?;
            Ok(more)
        })?;
        if !more {
            break;
        }
    }

    for _ in 0..MAX_ROUNDS {
        let items = access.with_vault(plan_push)?;
        if items.is_empty() {
            break;
        }
        for chunk in items.chunks(PUSH_BATCH) {
            let reply = client.push(&PushRequest {
                items: chunk.to_vec(),
            })?;
            if reply.results.len() != chunk.len() {
                return Err(SyncError::Protocol(format!(
                    "{} results for {} items",
                    reply.results.len(),
                    chunk.len()
                )));
            }
            access.with_vault(|v| {
                for (item, result) in chunk.iter().zip(reply.results) {
                    apply_result(v, &mut rng, item, result, &mut progress)?;
                }
                v.save()
            })?;
        }
    }
    fill_gaps(access, client, std::mem::take(&mut progress.gaps));
    Ok(progress.report)
}

/// Fetches the revisions a run skipped over and keeps them in history.
/// Best effort: history is a convenience, so failures are ignored.
fn fill_gaps(access: &impl VaultAccess, client: &HttpClient, gaps: Vec<HistoryQuery>) {
    for chunk in gaps.chunks(200) {
        let Ok(reply) = client.history(&HistoryRequest {
            items: chunk.to_vec(),
        }) else {
            return;
        };
        let _ = access.with_vault(|v| {
            for stored in reply.revisions {
                let id = stored.secret.id;
                if v.session.stored(id).is_some()
                    && !v.store.has_archived(id, stored.secret.revision)
                    && v.session.signed_by_me(&stored)
                    && v.session.open_parts(&stored).is_ok()
                {
                    v.store.archive(&stored)?;
                }
            }
            Ok(())
        });
    }
}

/// Brings one change from the server into the local vault.
fn apply_change(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    change: Change,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    match change {
        Change::Put { entry, .. } => apply_put(v, rng, entry, progress),
        Change::Delete { tombstone, .. } => apply_delete(v, tombstone, progress),
    }
}

fn apply_put(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    remote: StoredSecret,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = remote.secret.id;
    let revision = remote.secret.revision;
    // Only what this account wrote counts; anyone holding its public key, the
    // server included, could have sealed the rest.
    if !v.session.signed_by_me(&remote) || v.session.open_parts(&remote).is_err() {
        progress.report.skipped += 1;
        return Ok(());
    }
    let known = v.state.known.get(&id).copied();

    if let Some(deleted) = v.state.deletes.get(&id) {
        if revision > deleted.revision {
            // Edited elsewhere after the revision deleted here: the edit wins.
            v.state.deletes.remove(&id);
            v.session.accept(v.store, remote, false)?;
            v.state.known.insert(id, revision);
            progress.report.pulled += 1;
            progress.report.conflicts.push(format!(
                "{}: deleted here but changed on another device; kept their version",
                path(v, id)
            ));
        }
        return Ok(());
    }
    v.state.deleted_remotely.remove(&id);

    let Some(local) = v.session.stored(id) else {
        v.session.accept(v.store, remote, false)?;
        v.state.known.insert(id, revision);
        progress.report.pulled += 1;
        return Ok(());
    };
    if local.secret.digest() == remote.secret.digest() {
        v.state.known.insert(id, revision);
        return Ok(());
    }
    if known.is_some_and(|k| revision <= k) {
        // Older than what this device has already seen: a server rolling a
        // secret back. Ignore it.
        progress.report.skipped += 1;
        return Ok(());
    }
    if known == Some(local.secret.revision) {
        progress.gap(id, known, revision);
        v.session.accept(v.store, remote, true)?;
        v.state.known.insert(id, revision);
        progress.report.pulled += 1;
        return Ok(());
    }
    resolve_conflict(v, rng, remote, progress)
}

/// The secret changed here and on the server. Both versions end up in history
/// on top of the server's revision, the newer edit last.
fn resolve_conflict(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    remote: StoredSecret,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = remote.secret.id;
    let base = remote.secret.revision;
    let next = base
        .checked_add(1)
        .filter(|n| n.checked_add(1).is_some())
        .ok_or_else(|| SyncError::Protocol(format!("{id} has run out of revisions")))?;
    let (theirs_meta, theirs_body) = v.session.open_parts(&remote)?;
    let local = v
        .session
        .stored(id)
        .cloned()
        .ok_or_else(|| SyncError::Protocol(format!("{id} vanished during sync")))?;
    let (mine_meta, mine_body) = v.session.open_parts(&local)?;

    progress.gap(id, v.state.known.get(&id).copied(), base);
    v.store.archive(&remote)?;
    v.session
        .reseal(v.store, rng, id, next, &mine_meta, &mine_body, false)?;
    let outcome = if mine_meta.updated_at > theirs_meta.updated_at {
        "kept yours, theirs is in history"
    } else {
        v.session
            .reseal(v.store, rng, id, next + 1, &theirs_meta, &theirs_body, true)?;
        "kept theirs, yours is in history"
    };
    v.state.known.insert(id, base);
    progress.report.conflicts.push(format!(
        "{}: changed here and on another device; {outcome}",
        path(v, id)
    ));
    Ok(())
}

fn apply_delete(
    v: &mut Vault<'_>,
    tombstone: Tombstone,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = tombstone.secret_id;
    if tombstone.verify(&v.session.identity().signing_key).is_err() {
        progress.report.skipped += 1;
        return Ok(());
    }
    v.state.deletes.remove(&id);
    v.state.deleted_remotely.remove(&id);
    let known = v.state.known.get(&id).copied();
    if known.is_some_and(|k| tombstone.revision < k) {
        progress.report.skipped += 1;
        return Ok(());
    }
    match v.session.stored(id).map(|s| s.secret.revision) {
        None => {
            v.state.known.remove(&id);
        }
        Some(local) if known == Some(local) || (known.is_none() && local <= tombstone.revision) => {
            v.session.remove_id(v.store, id)?;
            v.state.known.remove(&id);
            progress.report.removed += 1;
        }
        Some(_) => {
            // Changed here since: the edit wins and goes back up as a restore.
            v.state.deleted_remotely.insert(id, tombstone.revision);
            v.state.known.insert(id, tombstone.revision);
            progress.report.conflicts.push(format!(
                "{}: deleted on another device but changed here; kept yours",
                path(v, id)
            ));
        }
    }
    Ok(())
}

/// The next push: every pending deletion, and for each changed secret the
/// oldest revision the server does not have yet.
fn plan_push(v: &mut Vault<'_>) -> Result<Vec<PushItem>, SyncError> {
    let mut items: Vec<PushItem> = v
        .state
        .deletes
        .values()
        .map(|tombstone| PushItem::Delete {
            tombstone: tombstone.clone(),
        })
        .collect();
    for (id, current) in v.session.revisions() {
        let known = v.state.known.get(&id).copied();
        if known == Some(current)
            || known.is_some_and(|k| current < k)
            || v.state
                .rejected
                .get(&id)
                .is_some_and(|r| r.revision == current)
        {
            continue;
        }
        let next = match known {
            // Revisions made here since the last one the server has, oldest first.
            Some(k) => v
                .store
                .history(id)?
                .into_iter()
                .filter(|h| h.secret.revision > k && h.secret.revision < current)
                .min_by_key(|h| h.secret.revision),
            // Never synced: only the current revision.
            None => None,
        };
        let next = match next {
            Some(next) => next,
            None => v
                .session
                .stored(id)
                .cloned()
                .expect("listed ids are stored"),
        };
        let entry = v.session.sign_if_needed(v.store, next)?;
        items.push(PushItem::Put {
            base_revision: known.unwrap_or(0),
            entry,
            restore: v.state.deleted_remotely.contains_key(&id),
        });
    }
    Ok(items)
}

fn apply_result(
    v: &mut Vault<'_>,
    rng: &mut impl CryptoRng,
    item: &PushItem,
    result: PushResult,
    progress: &mut Progress,
) -> Result<(), SyncError> {
    let id = item.secret_id();
    match (item, result) {
        (PushItem::Put { entry, .. }, PushResult::Ok { .. }) => {
            v.state.known.insert(id, entry.secret.revision);
            v.state.deleted_remotely.remove(&id);
            v.state.rejected.remove(&id);
            progress.report.pushed += 1;
        }
        (PushItem::Delete { .. }, PushResult::Ok { .. }) => {
            v.state.deletes.remove(&id);
            v.state.known.remove(&id);
            progress.report.pushed += 1;
        }
        (_, PushResult::Conflict { current }) => apply_change(v, rng, *current, progress)?,
        (PushItem::Put { entry, .. }, PushResult::Rejected { message }) => {
            let revision = v
                .session
                .stored(id)
                .map_or(entry.secret.revision, |s| s.secret.revision);
            progress
                .report
                .rejected
                .push(format!("{}: {message}", path(v, id)));
            v.state.rejected.insert(id, Rejection { revision, message });
        }
        (PushItem::Delete { .. }, PushResult::Rejected { message }) => {
            v.state.deletes.remove(&id);
            v.state.known.remove(&id);
            progress
                .report
                .rejected
                .push(format!("deletion of {id}: {message}"));
        }
    }
    Ok(())
}

fn path(v: &Vault<'_>, id: SecretId) -> String {
    v.session.path_of(id).unwrap_or_else(|| id.to_string())
}
