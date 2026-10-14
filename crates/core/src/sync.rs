//! Sync protocol between hosts and the server.
//!
//! The server stores opaque encrypted revisions, their grants and signed
//! tombstones, and never sees plaintext or keys. Clients push revisions on top
//! of the one they last saw and pull changes since a cursor. This module holds
//! the wire types (JSON over HTTPS, under `/v1`) and the signed objects only
//! sync needs; transport is supplied by the host.
//!
//! ```text
//! GET    /v1/server                     → ServerInfo               (no auth)
//! GET    /v1/prelogin/{username}        → PreloginReply            (no auth)
//! POST   /v1/register   RegisterRequest → SessionReply             (no auth, invite)
//! POST   /v1/login      LoginRequest    → SessionReply             (no auth)
//! POST   /v1/logout                     → 204                      revokes this device
//! GET    /v1/account                    → AccountReply
//! GET    /v1/devices                    → DevicesReply
//! DELETE /v1/devices/{id}               → 204
//! GET    /v1/connections                → ConnectionsReply
//! PUT    /v1/connections/{username}     → ConnectionInfo           request, or accept theirs
//! DELETE /v1/connections/{username}     → 204                      cancel, decline or remove
//! GET    /v1/changes?since=N&limit=M    → ChangesReply
//! POST   /v1/push       PushRequest     → PushReply
//! POST   /v1/history    HistoryRequest  → HistoryReply             revisions between two
//! ```
//!
//! Everything but the first four needs `Authorization: Bearer <device token>`.
//! Errors come back as [`ErrorReply`] with a matching HTTP status.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::account::{AccountKeys, AccountRecord, Identity};
use crate::crypto::bytes;
use crate::crypto::{AuthKey, KdfParams, PublicKey, SecretKey, Signature, SigningPublicKey};
use crate::error::{Error, Result};
use crate::vault::{SecretId, StoredSecret};

/// Current format of [`Tombstone`].
pub const TOMBSTONE_FORMAT: u8 = 1;

pub const USERNAME_MAX_LEN: usize = 32;

const TOMBSTONE_SIGNATURE_DOMAIN: &[u8] = b"silo/v1/sig/tombstone";
const REGISTER_SIGNATURE_DOMAIN: &[u8] = b"silo/v1/sig/register";
const REGISTER_KEY_PROOF_INFO: &[u8] = b"silo/v1/register-key-proof";

/// Checks a username and returns it lowercased: 1 to 32 characters from
/// `a-z`, `0-9`, `.`, `_`, `-`, starting with a letter or digit.
pub fn normalize_username(name: &str) -> Result<String> {
    let name = name.trim().to_ascii_lowercase();
    let invalid = |why| Err(Error::InvalidUsername(name.clone(), why));
    if name.is_empty() {
        return invalid("empty");
    }
    if name.len() > USERNAME_MAX_LEN {
        return invalid("longer than 32 characters");
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return invalid("must start with a letter or digit");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return invalid("only letters, digits, '.', '_' and '-' are allowed");
    }
    Ok(name)
}

/// Shows the server that whoever registers `username` holds both secret keys
/// of `identity`, so nobody can claim someone else's public keys:
///
/// - `signature`: the Ed25519 key signs the username and both public keys.
/// - `key_proof`: a MAC under the X25519 shared secret between the account
///   key and the server's static key ([`ServerInfo::public_key`]). Only the
///   holder of the account's X25519 secret, or the server, can compute it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationProof {
    pub signature: Signature,
    #[serde(
        serialize_with = "bytes::serialize",
        deserialize_with = "bytes::deserialize_array"
    )]
    pub key_proof: [u8; 32],
}

/// Proves `keys` for registering `username` on the server whose static key is
/// `server`. Use the name as [`normalize_username`] returns it; the server
/// checks that.
pub fn prove_registration(
    keys: &AccountKeys,
    username: &str,
    server: &PublicKey,
) -> Result<RegistrationProof> {
    let identity = keys.identity();
    let digest = registration_digest(username, &identity);
    let shared = keys
        .secret_key()
        .diffie_hellman(server)
        .ok_or(Error::BadSignature)?;
    Ok(RegistrationProof {
        signature: keys.signing_key().sign(&digest),
        key_proof: key_proof(&shared, &identity.public_key, server, &digest),
    })
}

/// The server's static X25519 key, used only to check the
/// [`RegistrationProof::key_proof`] of new accounts.
pub struct ServerKey(SecretKey);

impl ServerKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretKey::from_bytes(Zeroizing::new(bytes)))
    }

    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// Fails with [`Error::BadSignature`] unless the proof shows possession of
    /// both secret keys behind `identity`.
    pub fn verify_registration(
        &self,
        identity: &Identity,
        username: &str,
        proof: &RegistrationProof,
    ) -> Result<()> {
        let digest = registration_digest(username, identity);
        proof.signature.verify(&identity.signing_key, &digest)?;
        let shared = self
            .0
            .diffie_hellman(&identity.public_key)
            .ok_or(Error::BadSignature)?;
        let expected = key_proof(&shared, &identity.public_key, &self.public_key(), &digest);
        let diff = expected
            .iter()
            .zip(&proof.key_proof)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff == 0 {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}

impl core::fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ServerKey({:?})", self.public_key())
    }
}

fn registration_digest(username: &str, identity: &Identity) -> [u8; 32] {
    Sha256::new()
        .chain_update(REGISTER_SIGNATURE_DOMAIN)
        .chain_update((username.len() as u64).to_be_bytes())
        .chain_update(username.as_bytes())
        .chain_update(identity.public_key.as_bytes())
        .chain_update(identity.signing_key.as_bytes())
        .finalize()
        .into()
}

/// HKDF over the shared secret, salted with both public keys, expanded with
/// the registration digest: a MAC only the two key holders can compute.
fn key_proof(
    shared: &[u8; 32],
    account: &PublicKey,
    server: &PublicKey,
    digest: &[u8; 32],
) -> [u8; 32] {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(account.as_bytes());
    salt[32..].copy_from_slice(server.as_bytes());
    let mut info = Vec::with_capacity(REGISTER_KEY_PROOF_INFO.len() + 32);
    info.extend_from_slice(REGISTER_KEY_PROOF_INFO);
    info.extend_from_slice(digest);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(&info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// A signed record that a secret was deleted at `revision`. The server keeps
/// it in place of the secret so other devices learn of the deletion, and so a
/// server cannot make a secret disappear without the owner's signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    pub format: u8,
    pub secret_id: SecretId,
    /// The revision that was deleted.
    pub revision: u32,
    pub deleted_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl Tombstone {
    pub fn seal(author: &AccountKeys, secret_id: SecretId, revision: u32, deleted_at: u64) -> Self {
        let mut tombstone = Self {
            format: TOMBSTONE_FORMAT,
            secret_id,
            revision,
            deleted_at,
            signature: None,
        };
        tombstone.signature = Some(author.signing_key().sign(&tombstone.digest()));
        tombstone
    }

    /// Errors as [`SealedSecret::verify`](crate::vault::SealedSecret::verify).
    pub fn verify(&self, signer: &SigningPublicKey) -> Result<()> {
        if self.format != TOMBSTONE_FORMAT {
            return Err(Error::UnsupportedFormat(self.format));
        }
        self.signature
            .as_ref()
            .ok_or(Error::Unsigned)?
            .verify(signer, &self.digest())
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(TOMBSTONE_SIGNATURE_DOMAIN)
            .chain_update([self.format])
            .chain_update(self.secret_id.as_bytes())
            .chain_update(self.revision.to_be_bytes())
            .chain_update(self.deleted_at.to_be_bytes())
            .finalize()
            .into()
    }
}

// ---------- accounts and devices ----------

/// What a client needs to know about the server before registering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    /// The server's static X25519 key for [`prove_registration`].
    pub public_key: PublicKey,
    pub version: String,
}

/// How to hash the password for `username`. Unknown usernames get made-up
/// parameters that stay the same between requests, so this does not reveal
/// which accounts exist. Check them with [`KdfParams::check_minimum`] first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreloginReply {
    pub kdf: KdfParams,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub invite: String,
    pub username: String,
    pub account: AccountRecord,
    pub identity: Identity,
    /// [`prove_registration`] for `username` and `identity`.
    pub proof: RegistrationProof,
    pub auth_key: AuthKey,
    pub device_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub auth_key: AuthKey,
    pub device_name: String,
}

/// A new device session. `token` goes into `Authorization: Bearer` from now on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReply {
    pub device_id: String,
    pub token: String,
    #[serde(flatten)]
    pub account: AccountReply,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountReply {
    pub username: String,
    pub account: AccountRecord,
    pub identity: Identity,
    /// Goes up when the account record changes (a new password).
    pub account_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub created_at: u64,
    pub last_seen_at: u64,
    /// The device making this request.
    pub current: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicesReply {
    pub devices: Vec<DeviceInfo>,
}

// ---------- connections ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// You asked; they have not accepted yet.
    Outgoing,
    /// They asked; accept with `PUT /v1/connections/{username}`.
    Incoming,
    Connected,
}

/// Another account you are connected to or about to be. Its identity is
/// shown only once both sides agreed; compare its fingerprint out of band
/// before sharing anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub username: String,
    pub state: ConnectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionsReply {
    pub connections: Vec<ConnectionInfo>,
}

// ---------- push and pull ----------

/// One change a device sends. Accepted only on top of the server's current
/// revision of that secret (`0` for a new one), and only from its owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PushItem {
    /// A new revision, newer than `base_revision`, with all of its grants.
    ///
    /// A deleted secret keeps its last revision as the current one, so
    /// `base_revision` alone cannot tell an edit made before the deletion
    /// from a deliberate restore. `restore` says which: without it, a put on
    /// a deleted secret is a conflict; with it, a put on a live one is.
    Put {
        base_revision: u32,
        entry: StoredSecret,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        restore: bool,
    },
    /// Deletes the revision named in the tombstone.
    Delete { tombstone: Tombstone },
}

impl PushItem {
    pub fn secret_id(&self) -> SecretId {
        match self {
            Self::Put { entry, .. } => entry.secret.id,
            Self::Delete { tombstone } => tombstone.secret_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    pub items: Vec<PushItem>,
}

/// The outcome of one [`PushItem`], in the same position as in the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PushResult {
    Ok {
        seq: u64,
    },
    /// The server has moved on; `current` is what it holds now.
    Conflict {
        current: Box<Change>,
    },
    /// Malformed, badly signed, or not the pusher's to change. Sending it
    /// again will not help.
    Rejected {
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushReply {
    pub results: Vec<PushResult>,
}

/// The current state of one secret the device can read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    Put { seq: u64, entry: StoredSecret },
    Delete { seq: u64, tombstone: Tombstone },
}

impl Change {
    pub fn seq(&self) -> u64 {
        match self {
            Self::Put { seq, .. } | Self::Delete { seq, .. } => *seq,
        }
    }

    pub fn secret_id(&self) -> SecretId {
        match self {
            Self::Put { entry, .. } => entry.secret.id,
            Self::Delete { tombstone, .. } => tombstone.secret_id,
        }
    }

    pub fn revision(&self) -> u32 {
        match self {
            Self::Put { entry, .. } => entry.secret.revision,
            Self::Delete { tombstone, .. } => tombstone.revision,
        }
    }
}

/// Earlier revisions of one secret: those after `after` and before `before`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryQuery {
    pub secret_id: SecretId,
    pub after: u32,
    pub before: u32,
}

/// Pull hands out only the current revision of each secret. A device that
/// had revision 3 and receives 6 asks for 4 and 5 here, so its history has
/// every version, including the ones a conflict on another device left behind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryRequest {
    pub items: Vec<HistoryQuery>,
}

/// The revisions asked for that the account holds a grant for, oldest first
/// per secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryReply {
    pub revisions: Vec<StoredSecret>,
}

/// Changes after the requested cursor, oldest first. Ask again with
/// `since=cursor` while `more` is true.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesReply {
    pub changes: Vec<Change>,
    pub cursor: u64,
    pub more: bool,
    pub account_version: u32,
}

// ---------- errors ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    Forbidden,
    NotFound,
    Invalid,
    InviteInvalid,
    UsernameTaken,
    IdentityTaken,
    RateLimited,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorReply {
    pub error: ErrorBody,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use crate::vault::{Note, SealedSecret, SecretBody, SecretKind, SecretMeta};

    fn account(rng: &mut rand_chacha::ChaCha20Rng) -> AccountKeys {
        let kdf = testing::weak_kdf(rng);
        AccountRecord::create(rng, b"pw", kdf).unwrap().1
    }

    #[test]
    fn usernames() {
        assert_eq!(normalize_username(" Nikita ").unwrap(), "nikita");
        assert_eq!(normalize_username("a.b_c-9").unwrap(), "a.b_c-9");
        for bad in ["", "-x", ".x", "a b", "ä", "a/b", &"x".repeat(33)] {
            assert!(normalize_username(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn registration_proof_needs_both_secret_keys() {
        let mut rng = testing::rng(40);
        let alice = account(&mut rng);
        let mallory = account(&mut rng);
        let server = ServerKey::from_bytes([5; 32]);
        let server_pk = server.public_key();
        let proof = prove_registration(&alice, "alice", &server_pk).unwrap();

        assert_eq!(
            server.verify_registration(&alice.identity(), "alice", &proof),
            Ok(())
        );
        assert_eq!(
            server.verify_registration(&alice.identity(), "alice2", &proof),
            Err(Error::BadSignature)
        );
        // Mallory cannot sign as Alice.
        let theirs = prove_registration(&mallory, "mallory", &server_pk).unwrap();
        assert_eq!(
            server.verify_registration(&alice.identity(), "mallory", &theirs),
            Err(Error::BadSignature)
        );
        // Nor claim Alice's public encryption key next to her own signing key:
        // the signature checks out, the key proof does not.
        let claimed = Identity {
            public_key: *alice.public_key(),
            signing_key: mallory.identity().signing_key,
        };
        let mut forged = prove_registration(&mallory, "mallory", &server_pk).unwrap();
        forged.signature = mallory
            .signing_key()
            .sign(&registration_digest("mallory", &claimed));
        assert_eq!(
            server.verify_registration(&claimed, "mallory", &forged),
            Err(Error::BadSignature)
        );
        // A proof made for another server does not carry over.
        let elsewhere = ServerKey::from_bytes([6; 32]);
        assert_eq!(
            elsewhere.verify_registration(&alice.identity(), "alice", &proof),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn tombstones_are_signed() {
        let mut rng = testing::rng(41);
        let alice = account(&mut rng);
        let bob = account(&mut rng);
        let id = SecretId::from_random_bytes([9; 16]);
        let tombstone = Tombstone::seal(&alice, id, 3, 100);
        let signer = alice.identity().signing_key;

        assert_eq!(tombstone.verify(&signer), Ok(()));
        assert_eq!(
            tombstone.verify(&bob.identity().signing_key),
            Err(Error::BadSignature)
        );
        let mut older = tombstone.clone();
        older.revision = 2;
        assert_eq!(older.verify(&signer), Err(Error::BadSignature));
        let mut unsigned = tombstone.clone();
        unsigned.signature = None;
        assert_eq!(unsigned.verify(&signer), Err(Error::Unsigned));
    }

    #[test]
    fn wire_shapes() {
        let mut rng = testing::rng(42);
        let alice = account(&mut rng);
        let meta = SecretMeta {
            title: "n".into(),
            kind: SecretKind::Note,
            folder: Default::default(),
            tags: vec![],
            urls: vec![],
            basic_auth: false,
            created_at: 0,
            updated_at: 0,
        };
        let body = SecretBody::Note(Note { text: "x".into() });
        let id = SecretId::from_random_bytes([1; 16]);
        let (secret, _) = SealedSecret::seal(&mut rng, &alice, id, 1, &meta, &body).unwrap();
        let entry = StoredSecret {
            secret,
            grants: vec![],
        };

        let item = PushItem::Put {
            base_revision: 0,
            entry: entry.clone(),
            restore: false,
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["op"], "put");
        assert_eq!(json["base_revision"], 0);
        assert!(json.get("restore").is_none());
        assert_eq!(serde_json::from_value::<PushItem>(json).unwrap(), item);

        let result = PushResult::Conflict {
            current: Box::new(Change::Delete {
                seq: 7,
                tombstone: Tombstone::seal(&alice, id, 1, 5),
            }),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "conflict");
        assert_eq!(json["current"]["kind"], "delete");
        assert_eq!(json["current"]["seq"], 7);
        assert_eq!(serde_json::from_value::<PushResult>(json).unwrap(), result);

        let auth = AuthKey::from_bytes([1; 32]);
        let json = serde_json::to_string(&auth).unwrap();
        assert_eq!(json, "\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"");
        let back: AuthKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_bytes(), auth.as_bytes());
    }
}
