use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::bytes;
use crate::crypto::CryptoRng;
use crate::error::{Error, Result};

pub const MASTER_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

/// Password hashing algorithm. Only Argon2id exists today; the field is here so
/// the record format can carry a successor without a version bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlgorithm {
    Argon2id,
}

/// Argon2id parameters plus salt. Stored in plaintext next to the account record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    #[serde(
        serialize_with = "bytes::serialize",
        deserialize_with = "bytes::deserialize_array"
    )]
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// 64 MiB, 3 passes, 1 lane. Comparable to Bitwarden's default; roughly a
    /// second in WebAssembly, well under on native.
    pub const RECOMMENDED_MEMORY_KIB: u32 = 64 * 1024;
    pub const RECOMMENDED_ITERATIONS: u32 = 3;
    pub const RECOMMENDED_PARALLELISM: u32 = 1;

    /// Recommended parameters with a fresh random salt.
    pub fn recommended(rng: &mut impl CryptoRng) -> Self {
        Self::new(
            rng,
            Self::RECOMMENDED_MEMORY_KIB,
            Self::RECOMMENDED_ITERATIONS,
            Self::RECOMMENDED_PARALLELISM,
        )
    }

    /// Custom parameters with a fresh random salt. Argon2 requires
    /// `memory_kib >= 8 * parallelism` and `iterations >= 1`; violations surface
    /// as [`Error::Kdf`] on [`derive`](Self::derive).
    pub fn new(
        rng: &mut impl CryptoRng,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Self {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib,
            iterations,
            parallelism,
            salt,
        }
    }

    /// Stretches a password into the master key. Deliberately slow.
    pub fn derive(&self, password: &[u8]) -> Result<MasterKey> {
        let KdfAlgorithm::Argon2id = self.algorithm;
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(MASTER_KEY_LEN),
        )
        .map_err(|err| Error::Kdf(err.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
        argon
            .hash_password_into(password, &self.salt, key.as_mut())
            .map_err(|err| Error::Kdf(err.to_string()))?;
        Ok(MasterKey(key))
    }
}

/// Output of the password KDF. Never stored; only used to derive wrapping keys.
pub struct MasterKey(Zeroizing<[u8; MASTER_KEY_LEN]>);

impl MasterKey {
    /// Derives a purpose-bound subkey with HKDF-SHA256.
    pub(crate) fn subkey(&self, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, self.0.as_ref())
            .expand(info, out.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }
}

impl core::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn same_inputs_same_key_different_salt_different_key() {
        let mut rng = testing::rng(3);
        let a = testing::weak_kdf(&mut rng);
        let b = testing::weak_kdf(&mut rng);
        assert_ne!(a.salt, b.salt);

        let k1 = a.derive(b"hunter2").unwrap();
        let k2 = a.derive(b"hunter2").unwrap();
        let k3 = b.derive(b"hunter2").unwrap();
        let k4 = a.derive(b"hunter3").unwrap();
        assert_eq!(k1.0, k2.0);
        assert_ne!(k1.0, k3.0);
        assert_ne!(k1.0, k4.0);
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let mut rng = testing::rng(4);
        let key = testing::weak_kdf(&mut rng).derive(b"pw").unwrap();
        assert_ne!(key.subkey(b"a"), key.subkey(b"b"));
        assert_eq!(key.subkey(b"a"), key.subkey(b"a"));
    }

    #[test]
    fn invalid_params_are_reported() {
        let mut rng = testing::rng(5);
        let params = KdfParams::new(&mut rng, 4, 1, 1);
        assert!(matches!(params.derive(b"pw"), Err(Error::Kdf(_))));
    }

    #[test]
    fn params_json_roundtrip() {
        let mut rng = testing::rng(6);
        let params = testing::weak_kdf(&mut rng);
        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains(r#""algorithm":"argon2id""#));
        assert_eq!(serde_json::from_str::<KdfParams>(&json).unwrap(), params);
    }
}
