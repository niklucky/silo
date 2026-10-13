use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{SecretBody, SecretId, SecretMeta};
use crate::account::AccountKeys;
use crate::crypto::{
    self, Ciphertext, CryptoRng, DataKey, PublicKey, Signature, SigningPublicKey, WrappedKey,
};
use crate::error::{Error, Result};

/// Current format of [`SealedSecret`] and [`Grant`].
pub const SECRET_FORMAT: u8 = 1;

const META_DOMAIN: &[u8] = b"secret/v1/meta";
const BODY_DOMAIN: &[u8] = b"secret/v1/body";
const GRANT_DOMAIN: &[u8] = b"secret/v1/grant";
const REVISION_SIGNATURE_DOMAIN: &[u8] = b"silo/v1/sig/revision";
const GRANT_SIGNATURE_DOMAIN: &[u8] = b"silo/v1/sig/grant";

/// One encrypted revision of a secret. This is what the server stores.
///
/// `id` and `revision` are plaintext so the server can version and address
/// blobs; everything else is inside `meta` and `body`, both under one data key.
///
/// `signature` is the author's, over everything else. Revisions written
/// before signing existed have none; [`sign`](Self::sign) adds it later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    pub format: u8,
    pub id: SecretId,
    pub revision: u32,
    pub meta: Ciphertext,
    pub body: Ciphertext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl SealedSecret {
    /// Encrypts `meta` and `body` under a fresh data key and signs the result
    /// as `author`.
    ///
    /// Every revision gets a new key, so revoking a grant and publishing a new
    /// revision leaves the revoked party unable to read anything newer.
    pub fn seal(
        rng: &mut impl CryptoRng,
        author: &AccountKeys,
        id: SecretId,
        revision: u32,
        meta: &SecretMeta,
        body: &SecretBody,
    ) -> Result<(Self, DataKey)> {
        if meta.kind != body.kind() {
            return Err(Error::KindMismatch {
                meta: meta.kind,
                body: body.kind(),
            });
        }
        let key = DataKey::generate(rng);
        let meta_ct = crypto::seal(
            key.as_bytes(),
            rng,
            &aad(META_DOMAIN, id, revision),
            &encode(meta)?,
        )?;
        let body_ct = crypto::seal(
            key.as_bytes(),
            rng,
            &aad(BODY_DOMAIN, id, revision),
            &encode(body)?,
        )?;
        let mut sealed = Self {
            format: SECRET_FORMAT,
            id,
            revision,
            meta: meta_ct,
            body: body_ct,
            signature: None,
        };
        sealed.sign(author);
        Ok((sealed, key))
    }

    /// Signs (or signs again) this revision as `author`. The ciphertext stays
    /// as it is, so revisions from before signing can be signed in place.
    pub fn sign(&mut self, author: &AccountKeys) {
        self.signature = Some(author.signing_key().sign(&self.digest()));
    }

    /// Checks that `signer` signed exactly this revision.
    ///
    /// Fails with [`Error::Unsigned`] if it carries no signature and
    /// [`Error::BadSignature`] if anything, the signer included, differs.
    pub fn verify(&self, signer: &SigningPublicKey) -> Result<()> {
        self.signature
            .as_ref()
            .ok_or(Error::Unsigned)?
            .verify(signer, &self.digest())
    }

    /// SHA-256 over every field except the signature.
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(REVISION_SIGNATURE_DOMAIN);
        hash.update([self.format]);
        hash.update(self.id.as_bytes());
        hash.update(self.revision.to_be_bytes());
        hash_ciphertext(&mut hash, &self.meta);
        hash_ciphertext(&mut hash, &self.body);
        hash.finalize().into()
    }

    /// Decrypts the listing metadata. Cheap; do this for every secret on unlock.
    pub fn open_meta(&self, key: &DataKey) -> Result<SecretMeta> {
        self.check_format()?;
        let plain = crypto::open(
            key.as_bytes(),
            &aad(META_DOMAIN, self.id, self.revision),
            &self.meta,
        )?;
        decode(&plain)
    }

    /// Decrypts the payload. Do this on demand only.
    pub fn open_body(&self, key: &DataKey) -> Result<SecretBody> {
        self.check_format()?;
        let plain = crypto::open(
            key.as_bytes(),
            &aad(BODY_DOMAIN, self.id, self.revision),
            &self.body,
        )?;
        decode(&plain)
    }

    fn check_format(&self) -> Result<()> {
        if self.format == SECRET_FORMAT {
            Ok(())
        } else {
            Err(Error::UnsupportedFormat(self.format))
        }
    }
}

/// Permission for one account to read one revision of one secret.
///
/// The owner holds a grant to themself like anyone else; there is no special
/// owner path. "Shared with whom" is the set of grants for a secret id.
///
/// `signature` is the granter's, over the grant and the digest of the
/// revision it opens, so a grant cannot be moved to another revision with the
/// same id and number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub format: u8,
    pub secret_id: SecretId,
    pub revision: u32,
    pub recipient: PublicKey,
    pub key: WrappedKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

impl Grant {
    /// Wraps `key` for `recipient`, bound to this secret revision, and signs
    /// the grant as `author`.
    pub fn seal(
        rng: &mut impl CryptoRng,
        author: &AccountKeys,
        secret: &SealedSecret,
        key: &DataKey,
        recipient: PublicKey,
    ) -> Result<Self> {
        let wrapped = WrappedKey::seal(
            rng,
            key,
            &recipient,
            &grant_aad(secret.id, secret.revision, &recipient),
        )?;
        let mut grant = Self {
            format: SECRET_FORMAT,
            secret_id: secret.id,
            revision: secret.revision,
            recipient,
            key: wrapped,
            signature: None,
        };
        grant.sign(author, secret);
        Ok(grant)
    }

    /// Signs (or signs again) this grant for `secret` as `author`.
    pub fn sign(&mut self, author: &AccountKeys, secret: &SealedSecret) {
        self.signature = Some(author.signing_key().sign(&self.digest(secret)));
    }

    /// Checks that `signer` signed this grant for exactly this revision.
    /// Errors as [`SealedSecret::verify`].
    pub fn verify(&self, secret: &SealedSecret, signer: &SigningPublicKey) -> Result<()> {
        self.signature
            .as_ref()
            .ok_or(Error::Unsigned)?
            .verify(signer, &self.digest(secret))
    }

    fn digest(&self, secret: &SealedSecret) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(GRANT_SIGNATURE_DOMAIN);
        hash.update([self.format]);
        hash.update(secret.digest());
        hash.update(self.secret_id.as_bytes());
        hash.update(self.revision.to_be_bytes());
        hash.update(self.recipient.as_bytes());
        hash.update(self.key.ephemeral.as_bytes());
        hash_ciphertext(&mut hash, &self.key.ciphertext);
        hash.finalize().into()
    }

    /// Recovers the data key. Fails with [`Error::NotRecipient`] if the grant is
    /// addressed to someone else, or [`Error::Decrypt`] if it was tampered with.
    pub fn open(&self, keys: &AccountKeys) -> Result<DataKey> {
        if self.format != SECRET_FORMAT {
            return Err(Error::UnsupportedFormat(self.format));
        }
        if &self.recipient != keys.public_key() {
            return Err(Error::NotRecipient);
        }
        self.key.open(
            keys.secret_key(),
            &grant_aad(self.secret_id, self.revision, &self.recipient),
        )
    }

    /// True if this grant unlocks the given sealed revision.
    pub fn covers(&self, secret: &SealedSecret) -> bool {
        self.secret_id == secret.id && self.revision == secret.revision
    }
}

/// One revision of a secret together with every grant on it: what a store
/// keeps per secret and what sync moves between hosts and the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSecret {
    pub secret: SealedSecret,
    pub grants: Vec<Grant>,
}

impl StoredSecret {
    /// Checks that `signer` signed the revision and every grant, and that each
    /// grant belongs to this revision.
    pub fn verify(&self, signer: &SigningPublicKey) -> Result<()> {
        self.secret.verify(signer)?;
        for grant in &self.grants {
            if !grant.covers(&self.secret) {
                return Err(Error::BadSignature);
            }
            grant.verify(&self.secret, signer)?;
        }
        Ok(())
    }
}

fn aad(domain: &[u8], id: SecretId, revision: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + 16 + 4);
    aad.extend_from_slice(domain);
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

fn grant_aad(id: SecretId, revision: u32, recipient: &PublicKey) -> Vec<u8> {
    let mut aad = aad(GRANT_DOMAIN, id, revision);
    aad.extend_from_slice(recipient.as_bytes());
    aad
}

fn hash_ciphertext(hash: &mut Sha256, ct: &Ciphertext) {
    hash.update(ct.nonce.as_bytes());
    hash.update((ct.data.len() as u64).to_be_bytes());
    hash.update(&ct.data);
}

fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    ciborium::into_writer(value, &mut *out).map_err(|err| Error::Encode(err.to_string()))?;
    Ok(out)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|err| Error::Decode(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountRecord;
    use crate::crypto::KdfParams;
    use crate::testing;
    use crate::vault::{EnvSet, EnvVar, FolderPath, Login, SecretKind, Tag};

    fn account(rng: &mut rand_chacha::ChaCha20Rng, pw: &[u8]) -> AccountKeys {
        let kdf: KdfParams = testing::weak_kdf(rng);
        AccountRecord::create(rng, pw, kdf).unwrap().1
    }

    fn env_secret() -> (SecretMeta, SecretBody) {
        let meta = SecretMeta {
            title: "api dev env".into(),
            kind: SecretKind::EnvSet,
            folder: FolderPath::parse("projects/api").unwrap(),
            tags: vec![Tag::new("dev").unwrap()],
            urls: vec![],
            basic_auth: false,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        };
        let body = SecretBody::EnvSet(EnvSet {
            vars: vec![
                EnvVar {
                    key: "DB_URL".into(),
                    value: "postgres://localhost/api".into(),
                },
                EnvVar {
                    key: "API_KEY".into(),
                    value: "sk-test".into(),
                },
            ],
        });
        (meta, body)
    }

    #[test]
    fn seal_and_open_both_parts() {
        let mut rng = testing::rng(30);
        let author = account(&mut rng, b"author");
        let (meta, body) = env_secret();
        let id = SecretId::from_random_bytes([1; 16]);
        let (sealed, key) = SealedSecret::seal(&mut rng, &author, id, 1, &meta, &body).unwrap();

        assert_eq!(sealed.open_meta(&key).unwrap(), meta);
        assert_eq!(sealed.open_body(&key).unwrap(), body);

        let other = DataKey::generate(&mut rng);
        assert_eq!(sealed.open_meta(&other).unwrap_err(), Error::Decrypt);
        assert_eq!(sealed.open_body(&other).unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn kind_mismatch_is_rejected() {
        let mut rng = testing::rng(31);
        let author = account(&mut rng, b"author");
        let (mut meta, body) = env_secret();
        meta.kind = SecretKind::Login;
        let err = SealedSecret::seal(
            &mut rng,
            &author,
            SecretId::from_random_bytes([2; 16]),
            1,
            &meta,
            &body,
        )
        .unwrap_err();
        assert_eq!(
            err,
            Error::KindMismatch {
                meta: SecretKind::Login,
                body: SecretKind::EnvSet
            }
        );
    }

    #[test]
    fn ciphertexts_are_bound_to_id_revision_and_part() {
        let mut rng = testing::rng(32);
        let author = account(&mut rng, b"author");
        let (meta, body) = env_secret();
        let id = SecretId::from_random_bytes([3; 16]);
        let (sealed, key) = SealedSecret::seal(&mut rng, &author, id, 1, &meta, &body).unwrap();

        let mut moved = sealed.clone();
        moved.revision = 2;
        assert_eq!(moved.open_meta(&key).unwrap_err(), Error::Decrypt);

        let mut renamed = sealed.clone();
        renamed.id = SecretId::from_random_bytes([4; 16]);
        assert_eq!(renamed.open_body(&key).unwrap_err(), Error::Decrypt);

        let mut swapped = sealed.clone();
        core::mem::swap(&mut swapped.meta, &mut swapped.body);
        assert_eq!(swapped.open_meta(&key).unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn sharing_flow_grant_open_revoke_by_new_revision() {
        let mut rng = testing::rng(33);
        let alice = account(&mut rng, b"alice");
        let bob = account(&mut rng, b"bob");
        let carol = account(&mut rng, b"carol");

        let (meta, body) = env_secret();
        let id = SecretId::from_random_bytes([5; 16]);
        let (rev1, key1) = SealedSecret::seal(&mut rng, &alice, id, 1, &meta, &body).unwrap();

        let alice_grant = Grant::seal(&mut rng, &alice, &rev1, &key1, *alice.public_key()).unwrap();
        let bob_grant = Grant::seal(&mut rng, &alice, &rev1, &key1, *bob.public_key()).unwrap();
        assert!(alice_grant.covers(&rev1) && bob_grant.covers(&rev1));

        // Both grantees read the same plaintext.
        assert_eq!(
            rev1.open_body(&alice_grant.open(&alice).unwrap()).unwrap(),
            body
        );
        assert_eq!(
            rev1.open_body(&bob_grant.open(&bob).unwrap()).unwrap(),
            body
        );

        // Someone else cannot use Bob's grant, and Bob cannot use Alice's.
        assert_eq!(bob_grant.open(&carol).unwrap_err(), Error::NotRecipient);
        assert_eq!(alice_grant.open(&bob).unwrap_err(), Error::NotRecipient);

        // Re-pointing a grant at another recipient breaks the AAD binding.
        let mut forged = bob_grant.clone();
        forged.recipient = *carol.public_key();
        assert_eq!(forged.open(&carol).unwrap_err(), Error::Decrypt);

        // Alice updates DB_URL and publishes revision 2 without re-granting Bob.
        let mut body2 = body.clone();
        if let SecretBody::EnvSet(env) = &mut body2 {
            env.vars[0].value = "postgres://db.internal/api".into();
        }
        let (rev2, key2) = SealedSecret::seal(&mut rng, &alice, id, 2, &meta, &body2).unwrap();
        let alice_grant2 =
            Grant::seal(&mut rng, &alice, &rev2, &key2, *alice.public_key()).unwrap();

        assert_eq!(
            rev2.open_body(&alice_grant2.open(&alice).unwrap()).unwrap(),
            body2
        );
        // Bob's old key opens nothing in revision 2, and his old grant does not cover it.
        assert!(!bob_grant.covers(&rev2));
        assert_eq!(
            rev2.open_body(&bob_grant.open(&bob).unwrap()).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn login_secret_json_roundtrip_of_sealed_forms() {
        let mut rng = testing::rng(34);
        let alice = account(&mut rng, b"alice");
        let meta = SecretMeta {
            title: "staging admin".into(),
            kind: SecretKind::Login,
            folder: FolderPath::parse("work/staging").unwrap(),
            tags: vec![],
            urls: vec!["https://staging.example.com".into()],
            basic_auth: false,
            created_at: 1,
            updated_at: 2,
        };
        let body = SecretBody::Login(Login {
            username: "admin".into(),
            password: "s3cret".into(),
            totp: None,
            notes: String::new(),
        });
        let id = SecretId::from_random_bytes([6; 16]);
        let (sealed, key) = SealedSecret::seal(&mut rng, &alice, id, 1, &meta, &body).unwrap();
        let grant = Grant::seal(&mut rng, &alice, &sealed, &key, *alice.public_key()).unwrap();

        let sealed_json = serde_json::to_string(&sealed).unwrap();
        let grant_json = serde_json::to_string(&grant).unwrap();
        assert!(!sealed_json.contains("s3cret") && !sealed_json.contains("staging admin"));

        let sealed_back: SealedSecret = serde_json::from_str(&sealed_json).unwrap();
        let grant_back: Grant = serde_json::from_str(&grant_json).unwrap();
        let key_back = grant_back.open(&alice).unwrap();
        assert_eq!(sealed_back.open_meta(&key_back).unwrap(), meta);
        assert_eq!(sealed_back.open_body(&key_back).unwrap(), body);
    }

    #[test]
    fn revisions_and_grants_are_signed_by_their_author() {
        let mut rng = testing::rng(35);
        let alice = account(&mut rng, b"alice");
        let bob = account(&mut rng, b"bob");
        let (meta, body) = env_secret();
        let id = SecretId::from_random_bytes([7; 16]);
        let (sealed, key) = SealedSecret::seal(&mut rng, &alice, id, 1, &meta, &body).unwrap();
        let grant = Grant::seal(&mut rng, &alice, &sealed, &key, *bob.public_key()).unwrap();
        let alice_id = alice.identity().signing_key;
        let bob_id = bob.identity().signing_key;

        assert_eq!(sealed.verify(&alice_id), Ok(()));
        assert_eq!(grant.verify(&sealed, &alice_id), Ok(()));
        assert_eq!(sealed.verify(&bob_id), Err(Error::BadSignature));
        assert_eq!(grant.verify(&sealed, &bob_id), Err(Error::BadSignature));

        // Anyone holding Alice's public key, a server included, can seal a
        // revision for her, but it does not carry her signature.
        let (forged, forged_key) = SealedSecret::seal(&mut rng, &bob, id, 2, &meta, &body).unwrap();
        let forged_grant =
            Grant::seal(&mut rng, &bob, &forged, &forged_key, *alice.public_key()).unwrap();
        assert_eq!(forged.verify(&alice_id), Err(Error::BadSignature));
        assert_eq!(
            forged_grant.verify(&forged, &alice_id),
            Err(Error::BadSignature)
        );

        // Changing any signed field breaks the signature.
        let mut moved = sealed.clone();
        moved.revision = 2;
        assert_eq!(moved.verify(&alice_id), Err(Error::BadSignature));
        let mut swapped = sealed.clone();
        core::mem::swap(&mut swapped.meta, &mut swapped.body);
        assert_eq!(swapped.verify(&alice_id), Err(Error::BadSignature));
        let mut repointed = grant.clone();
        repointed.recipient = *alice.public_key();
        assert_eq!(
            repointed.verify(&sealed, &alice_id),
            Err(Error::BadSignature)
        );

        // A grant is tied to the exact revision, not just its id and number.
        let (twin, _) = SealedSecret::seal(&mut rng, &alice, id, 1, &meta, &body).unwrap();
        assert_eq!(grant.verify(&twin, &alice_id), Err(Error::BadSignature));
    }

    #[test]
    fn unsigned_revisions_load_and_can_be_signed_later() {
        let mut rng = testing::rng(36);
        let alice = account(&mut rng, b"alice");
        let (meta, body) = env_secret();
        let id = SecretId::from_random_bytes([8; 16]);
        let (signed, key) = SealedSecret::seal(&mut rng, &alice, id, 1, &meta, &body).unwrap();
        let grant = Grant::seal(&mut rng, &alice, &signed, &key, *alice.public_key()).unwrap();

        // What a vault written before signing looks like on disk.
        let mut old_secret = serde_json::to_value(&signed).unwrap();
        old_secret.as_object_mut().unwrap().remove("signature");
        let mut old_grant = serde_json::to_value(&grant).unwrap();
        old_grant.as_object_mut().unwrap().remove("signature");
        let mut sealed: SealedSecret = serde_json::from_value(old_secret).unwrap();
        let mut grant: Grant = serde_json::from_value(old_grant).unwrap();
        assert_eq!(sealed.signature, None);
        assert!(
            !serde_json::to_string(&sealed)
                .unwrap()
                .contains("signature")
        );

        let alice_id = alice.identity().signing_key;
        assert_eq!(sealed.verify(&alice_id), Err(Error::Unsigned));
        assert_eq!(grant.verify(&sealed, &alice_id), Err(Error::Unsigned));
        // Still readable.
        assert_eq!(
            sealed.open_body(&grant.open(&alice).unwrap()).unwrap(),
            body
        );

        sealed.sign(&alice);
        grant.sign(&alice, &sealed);
        assert_eq!(sealed.verify(&alice_id), Ok(()));
        assert_eq!(grant.verify(&sealed, &alice_id), Ok(()));
        assert_eq!(sealed.digest(), signed.digest());
    }
}
