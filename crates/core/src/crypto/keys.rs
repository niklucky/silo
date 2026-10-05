use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use super::bytes;
use crate::crypto::CryptoRng;

pub const KEY_LEN: usize = 32;
const FINGERPRINT_DOMAIN: &[u8] = b"secret/v1/fingerprint";

/// Symmetric key protecting one secret revision. Never leaves memory unwrapped.
pub struct DataKey(Zeroizing<[u8; KEY_LEN]>);

impl DataKey {
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    pub(crate) fn from_bytes(bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(..)")
    }
}

/// X25519 public key of an account. Safe to publish; identifies a grantee.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Hash of the key for humans to compare out of band when accepting a share.
    pub fn fingerprint(&self) -> Fingerprint {
        let digest = Sha256::new()
            .chain_update(FINGERPRINT_DOMAIN)
            .chain_update(self.0)
            .finalize();
        Fingerprint(digest.into())
    }

    pub(crate) fn to_dalek(self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        bytes::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        bytes::deserialize_array(deserializer).map(Self)
    }
}

/// X25519 secret key of an account. Lives in memory only while unlocked.
pub struct SecretKey(StaticSecret);

impl SecretKey {
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rng.fill_bytes(bytes.as_mut());
        Self(StaticSecret::from(*bytes))
    }

    pub(crate) fn from_bytes(bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self(StaticSecret::from(*bytes))
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0).to_bytes())
    }

    /// X25519 shared secret, or `None` if the peer key is a low-order point.
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self.0.diffie_hellman(&peer.to_dalek());
        shared
            .was_contributory()
            .then(|| Zeroizing::new(shared.to_bytes()))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// SHA-256 of a public key. Displayed as eight groups of four hex digits
/// (the first 128 bits), which is enough to read aloud or compare visually.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// All 256 bits as lowercase hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, pair) in self.0[..16].chunks(2).enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{:02x}{:02x}", pair[0], pair[1])?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn keypair_roundtrips_through_bytes() {
        let mut rng = testing::rng(7);
        let sk = SecretKey::generate(&mut rng);
        let restored = SecretKey::from_bytes(sk.to_bytes());
        assert_eq!(sk.public_key(), restored.public_key());
    }

    #[test]
    fn diffie_hellman_agrees_and_rejects_low_order_points() {
        let mut rng = testing::rng(8);
        let alice = SecretKey::generate(&mut rng);
        let bob = SecretKey::generate(&mut rng);
        let ab = alice.diffie_hellman(&bob.public_key()).unwrap();
        let ba = bob.diffie_hellman(&alice.public_key()).unwrap();
        assert_eq!(ab, ba);
        assert!(
            alice
                .diffie_hellman(&PublicKey::from_bytes([0; KEY_LEN]))
                .is_none()
        );
    }

    #[test]
    fn fingerprint_format() {
        let pk = PublicKey::from_bytes([42; KEY_LEN]);
        let shown = pk.fingerprint().to_string();
        assert_eq!(shown.len(), 8 * 4 + 7, "{shown}");
        assert_eq!(shown.split(' ').count(), 8);
        assert_eq!(pk.fingerprint().to_hex().len(), 64);
        assert_ne!(
            pk.fingerprint(),
            PublicKey::from_bytes([43; KEY_LEN]).fingerprint()
        );
    }

    #[test]
    fn public_key_json_is_base64() {
        let pk = PublicKey::from_bytes([1; KEY_LEN]);
        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(json, "\"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"");
        assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), pk);
    }
}
