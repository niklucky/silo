//! Account creation, unlock and password change.
//!
//! An [`AccountRecord`] is the stored, non-secret half: KDF parameters, the
//! public key, and the secret key wrapped under a key derived from the password.
//! Unlocking yields [`AccountKeys`], which stay in memory only.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, Ciphertext, CryptoRng, Fingerprint, KdfParams, PublicKey, SecretKey};
use crate::error::{Error, Result};

/// Current on-disk / on-wire format of [`AccountRecord`].
pub const ACCOUNT_FORMAT: u8 = 1;

const ACCOUNT_WRAP_INFO: &[u8] = b"secret/v1/account-key-wrap";
const ACCOUNT_AAD_DOMAIN: &[u8] = b"secret/v1/account";

/// Stored description of an account. Contains no secrets; safe on disk and server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub format: u8,
    pub kdf: KdfParams,
    pub public_key: PublicKey,
    pub wrapped_secret_key: Ciphertext,
}

/// Unlocked account keys. Zeroed on drop; never serialized.
pub struct AccountKeys {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl AccountKeys {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key.fingerprint()
    }

    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.secret_key
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
        let secret_key = SecretKey::generate(rng);
        let public_key = secret_key.public_key();
        let record = Self::wrap(rng, password, kdf, &secret_key, public_key)?;
        Ok((
            record,
            AccountKeys {
                secret_key,
                public_key,
            },
        ))
    }

    /// Derives the wrapping key from `password` and unwraps the secret key.
    ///
    /// A wrong password and a corrupted record are indistinguishable by design.
    pub fn unlock(&self, password: &[u8]) -> Result<AccountKeys> {
        if self.format != ACCOUNT_FORMAT {
            return Err(Error::UnsupportedFormat(self.format));
        }
        let wrap_key = self.kdf.derive(password)?.subkey(ACCOUNT_WRAP_INFO);
        let plain = crypto::open(&wrap_key, &aad(&self.public_key), &self.wrapped_secret_key)
            .map_err(|_| Error::Unlock)?;
        let mut bytes = Zeroizing::new([0u8; crypto::KEY_LEN]);
        if plain.len() != bytes.len() {
            return Err(Error::Unlock);
        }
        bytes.copy_from_slice(&plain);
        let secret_key = SecretKey::from_bytes(bytes);
        if secret_key.public_key() != self.public_key {
            return Err(Error::Unlock);
        }
        Ok(AccountKeys {
            secret_key,
            public_key: self.public_key,
        })
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
}
