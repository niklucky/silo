//! Account creation, unlock and password change.
//!
//! An [`AccountRecord`] is the stored, non-secret half: KDF parameters, the
//! public key, and the secret key wrapped under a key derived from the password.
//! Unlocking yields [`AccountKeys`], which stay in memory only.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{
    self, Ciphertext, CryptoRng, Fingerprint, KdfParams, MasterKey, PublicKey, SecretKey,
    SigningKey, SigningPublicKey,
};
use crate::error::{Error, Result};

/// Current on-disk / on-wire format of [`AccountRecord`].
pub const ACCOUNT_FORMAT: u8 = 1;
/// Current on-disk / on-wire format of [`UnlockSlot`].
pub const UNLOCK_SLOT_FORMAT: u8 = 1;

const ACCOUNT_WRAP_INFO: &[u8] = b"secret/v1/account-key-wrap";
const ACCOUNT_AAD_DOMAIN: &[u8] = b"secret/v1/account";
const IDENTITY_FINGERPRINT_DOMAIN: &[u8] = b"silo/v1/identity";
const UNLOCK_SLOT_WRAP_INFO: &[u8] = b"silo/v1/unlock-slot-wrap";
const UNLOCK_SLOT_AAD_DOMAIN: &[u8] = b"silo/v1/unlock-slot";

/// Stored description of an account. Contains no secrets; safe on disk and server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub format: u8,
    pub kdf: KdfParams,
    pub public_key: PublicKey,
    pub wrapped_secret_key: Ciphertext,
}

/// Secondary wrapping of an account's secret key under a 32-byte key supplied
/// by an external unlock mechanism (such as OS biometrics/keychain or a
/// WebAuthn PRF credential).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockSlot {
    pub format: u8,
    pub public_key: PublicKey,
    pub wrapped_secret_key: Ciphertext,
}

/// The public half of an account: what others need to share with it (the
/// X25519 key) and to check what it wrote (the Ed25519 key).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identity {
    pub public_key: PublicKey,
    pub signing_key: SigningPublicKey,
}

impl Identity {
    /// What people compare out of band before trusting each other. Covers
    /// both keys, so a server cannot swap either one unnoticed.
    pub fn fingerprint(&self) -> Fingerprint {
        let digest = Sha256::new()
            .chain_update(IDENTITY_FINGERPRINT_DOMAIN)
            .chain_update(self.public_key.as_bytes())
            .chain_update(self.signing_key.as_bytes())
            .finalize();
        Fingerprint::from_digest(digest.into())
    }
}

/// Unlocked account keys. Zeroed on drop; never serialized.
pub struct AccountKeys {
    secret_key: SecretKey,
    public_key: PublicKey,
    signing_key: SigningKey,
}

impl AccountKeys {
    fn new(secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key();
        let signing_key = SigningKey::derive(&secret_key);
        Self {
            secret_key,
            public_key,
            signing_key,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn identity(&self) -> Identity {
        Identity {
            public_key: self.public_key,
            signing_key: self.signing_key.public_key(),
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.identity().fingerprint()
    }

    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Wraps this account's secret key into an [`UnlockSlot`] under an external
    /// 32-byte key bound to `context` (for example `b"os-biometric"` or
    /// `b"webauthn-prf"`).
    pub fn seal_slot(
        &self,
        rng: &mut impl CryptoRng,
        wrapping_key: &[u8; crypto::KEY_LEN],
        context: &[u8],
    ) -> Result<UnlockSlot> {
        let wrap_key = slot_wrap_key(wrapping_key, context);
        let wrapped_secret_key = crypto::seal(
            &wrap_key,
            rng,
            &slot_aad(&self.public_key, context),
            self.secret_key.to_bytes().as_ref(),
        )?;
        Ok(UnlockSlot {
            format: UNLOCK_SLOT_FORMAT,
            public_key: self.public_key,
            wrapped_secret_key,
        })
    }
}

impl UnlockSlot {
    /// Unwraps the account keys with `wrapping_key`, checking that the slot
    /// matches both `expected_public_key` and `context`.
    pub fn open(
        &self,
        wrapping_key: &[u8; crypto::KEY_LEN],
        expected_public_key: &PublicKey,
        context: &[u8],
    ) -> Result<AccountKeys> {
        if self.format != UNLOCK_SLOT_FORMAT {
            return Err(Error::UnsupportedFormat(self.format));
        }
        if self.public_key != *expected_public_key {
            return Err(Error::Unlock);
        }
        let wrap_key = slot_wrap_key(wrapping_key, context);
        let plain = crypto::open(
            &wrap_key,
            &slot_aad(&self.public_key, context),
            &self.wrapped_secret_key,
        )
        .map_err(|_| Error::Unlock)?;
        let mut bytes = Zeroizing::new([0u8; crypto::KEY_LEN]);
        if plain.len() != bytes.len() {
            return Err(Error::Unlock);
        }
        bytes.copy_from_slice(&plain);
        let keys = AccountKeys::new(SecretKey::from_bytes(bytes));
        if keys.public_key != *expected_public_key {
            return Err(Error::Unlock);
        }
        Ok(keys)
    }
}

impl core::fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountKeys")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl AccountRecord {
    /// Creates a new account: random keypair, secret key wrapped under `password`.
    pub fn create(
        rng: &mut impl CryptoRng,
        password: &[u8],
        kdf: KdfParams,
    ) -> Result<(Self, AccountKeys)> {
        let keys = AccountKeys::new(SecretKey::generate(rng));
        let record = Self::wrap(rng, password, kdf, &keys.secret_key, keys.public_key)?;
        Ok((record, keys))
    }

    /// Derives the wrapping key from `password` and unwraps the secret key.
    ///
    /// A wrong password and a corrupted record are indistinguishable by design.
    pub fn unlock(&self, password: &[u8]) -> Result<AccountKeys> {
        if self.format != ACCOUNT_FORMAT {
            return Err(Error::UnsupportedFormat(self.format));
        }
        self.unlock_with(&self.kdf.derive(password)?)
    }

    /// Unwraps the secret key with a master key the caller already derived
    /// from this record's KDF parameters, for example while logging in to a
    /// sync server, which needs the same master key for its login key.
    pub fn unlock_with(&self, master: &MasterKey) -> Result<AccountKeys> {
        if self.format != ACCOUNT_FORMAT {
            return Err(Error::UnsupportedFormat(self.format));
        }
        let wrap_key = master.subkey(ACCOUNT_WRAP_INFO);
        let plain = crypto::open(&wrap_key, &aad(&self.public_key), &self.wrapped_secret_key)
            .map_err(|_| Error::Unlock)?;
        let mut bytes = Zeroizing::new([0u8; crypto::KEY_LEN]);
        if plain.len() != bytes.len() {
            return Err(Error::Unlock);
        }
        bytes.copy_from_slice(&plain);
        let keys = AccountKeys::new(SecretKey::from_bytes(bytes));
        if keys.public_key != self.public_key {
            return Err(Error::Unlock);
        }
        Ok(keys)
    }

    /// Re-wraps the same keypair under a new password and fresh KDF parameters.
    /// Nothing else in the vault changes.
    pub fn change_password(
        &self,
        rng: &mut impl CryptoRng,
        old_password: &[u8],
        new_password: &[u8],
        kdf: KdfParams,
    ) -> Result<Self> {
        let keys = self.unlock(old_password)?;
        Self::wrap(rng, new_password, kdf, &keys.secret_key, keys.public_key)
    }

    fn wrap(
        rng: &mut impl CryptoRng,
        password: &[u8],
        kdf: KdfParams,
        secret_key: &SecretKey,
        public_key: PublicKey,
    ) -> Result<Self> {
        let wrap_key = kdf.derive(password)?.subkey(ACCOUNT_WRAP_INFO);
        let wrapped_secret_key = crypto::seal(
            &wrap_key,
            rng,
            &aad(&public_key),
            secret_key.to_bytes().as_ref(),
        )?;
        Ok(Self {
            format: ACCOUNT_FORMAT,
            kdf,
            public_key,
            wrapped_secret_key,
        })
    }
}

fn aad(public_key: &PublicKey) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ACCOUNT_AAD_DOMAIN.len() + 1 + 32);
    aad.extend_from_slice(ACCOUNT_AAD_DOMAIN);
    aad.push(ACCOUNT_FORMAT);
    aad.extend_from_slice(public_key.as_bytes());
    aad
}

fn slot_wrap_key(
    wrapping_key: &[u8; crypto::KEY_LEN],
    context: &[u8],
) -> Zeroizing<[u8; crypto::KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, wrapping_key);
    let mut info = Vec::with_capacity(UNLOCK_SLOT_WRAP_INFO.len() + 1 + context.len());
    info.extend_from_slice(UNLOCK_SLOT_WRAP_INFO);
    info.push(0);
    info.extend_from_slice(context);
    let mut out = Zeroizing::new([0u8; crypto::KEY_LEN]);
    hk.expand(&info, out.as_mut())
        .expect("32 bytes is always a valid HKDF-SHA256 length");
    out
}

fn slot_aad(public_key: &PublicKey, context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(UNLOCK_SLOT_AAD_DOMAIN.len() + 1 + 32 + 1 + context.len());
    aad.extend_from_slice(UNLOCK_SLOT_AAD_DOMAIN);
    aad.push(UNLOCK_SLOT_FORMAT);
    aad.extend_from_slice(public_key.as_bytes());
    aad.push(0);
    aad.extend_from_slice(context);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn create_then_unlock() {
        let mut rng = testing::rng(20);
        let kdf = testing::weak_kdf(&mut rng);
        let (record, keys) = AccountRecord::create(&mut rng, b"correct horse", kdf).unwrap();

        let unlocked = record.unlock(b"correct horse").unwrap();
        assert_eq!(unlocked.public_key(), keys.public_key());
        assert_eq!(unlocked.fingerprint(), keys.fingerprint());
        assert_eq!(record.unlock(b"wrong").unwrap_err(), Error::Unlock);
    }

    #[test]
    fn unlock_with_a_master_key_and_identity() {
        let mut rng = testing::rng(24);
        let kdf = testing::weak_kdf(&mut rng);
        let (record, keys) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();

        let master = record.kdf.derive(b"pw").unwrap();
        let unlocked = record.unlock_with(&master).unwrap();
        assert_eq!(unlocked.identity(), keys.identity());
        assert_eq!(unlocked.identity().public_key, record.public_key);

        let wrong = record.kdf.derive(b"nope").unwrap();
        assert_eq!(record.unlock_with(&wrong).unwrap_err(), Error::Unlock);

        // The fingerprint covers both keys.
        let mut other = keys.identity();
        other.signing_key = SigningPublicKey::from_bytes([7; 32]);
        assert_ne!(other.fingerprint(), keys.fingerprint());
        assert_ne!(keys.fingerprint(), record.public_key.fingerprint());
    }

    #[test]
    fn tampered_record_fails_to_unlock() {
        let mut rng = testing::rng(21);
        let kdf = testing::weak_kdf(&mut rng);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();

        let mut swapped_pk = record.clone();
        swapped_pk.public_key = PublicKey::from_bytes([9; 32]);
        assert_eq!(swapped_pk.unlock(b"pw").unwrap_err(), Error::Unlock);

        let mut future = record.clone();
        future.format = 2;
        assert_eq!(
            future.unlock(b"pw").unwrap_err(),
            Error::UnsupportedFormat(2)
        );
    }

    #[test]
    fn change_password_keeps_the_keypair() {
        let mut rng = testing::rng(22);
        let kdf = testing::weak_kdf(&mut rng);
        let (record, _) = AccountRecord::create(&mut rng, b"old", kdf).unwrap();

        let new_kdf = testing::weak_kdf(&mut rng);
        let changed = record
            .change_password(&mut rng, b"old", b"new", new_kdf)
            .unwrap();
        assert_eq!(changed.public_key, record.public_key);
        assert_ne!(changed.kdf.salt, record.kdf.salt);
        assert!(changed.unlock(b"new").is_ok());
        assert_eq!(changed.unlock(b"old").unwrap_err(), Error::Unlock);
        assert_eq!(
            record
                .change_password(&mut rng, b"bad", b"x", changed.kdf.clone())
                .unwrap_err(),
            Error::Unlock
        );
    }

    #[test]
    fn record_json_roundtrip() {
        let mut rng = testing::rng(23);
        let kdf = testing::weak_kdf(&mut rng);
        let (record, _) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        let json = serde_json::to_string_pretty(&record).unwrap();
        let back: AccountRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert!(back.unlock(b"pw").is_ok());
    }

    #[test]
    fn unlock_slot_roundtrip_and_context_binding() {
        let mut rng = testing::rng(25);
        let kdf = testing::weak_kdf(&mut rng);
        let (record, keys) = AccountRecord::create(&mut rng, b"pw", kdf).unwrap();
        let wrapping_key = [42u8; crypto::KEY_LEN];

        let slot = keys
            .seal_slot(&mut rng, &wrapping_key, b"os-biometric")
            .unwrap();
        let json = serde_json::to_string(&slot).unwrap();
        let slot: UnlockSlot = serde_json::from_str(&json).unwrap();

        let opened = slot
            .open(&wrapping_key, &record.public_key, b"os-biometric")
            .unwrap();
        assert_eq!(opened.identity(), keys.identity());

        // Wrong wrapping key, context, or account public key must fail.
        let wrong_key = [7u8; crypto::KEY_LEN];
        assert_eq!(
            slot.open(&wrong_key, &record.public_key, b"os-biometric")
                .unwrap_err(),
            Error::Unlock
        );
        assert_eq!(
            slot.open(&wrapping_key, &record.public_key, b"webauthn-prf")
                .unwrap_err(),
            Error::Unlock
        );
        assert_eq!(
            slot.open(
                &wrapping_key,
                &PublicKey::from_bytes([9; 32]),
                b"os-biometric"
            )
            .unwrap_err(),
            Error::Unlock
        );

        let mut future = slot.clone();
        future.format = 2;
        assert_eq!(
            future
                .open(&wrapping_key, &record.public_key, b"os-biometric")
                .unwrap_err(),
            Error::UnsupportedFormat(2)
        );
    }
}
