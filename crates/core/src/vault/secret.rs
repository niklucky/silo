use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{FolderPath, Tag};

/// Stable identifier of a secret across revisions, devices and accounts.
///
/// A random UUID (version 4). Visible to the server; carries no information.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(Uuid);

impl SecretId {
    /// Builds an id from 16 random bytes supplied by the host's RNG.
    pub fn from_random_bytes(bytes: [u8; 16]) -> Self {
        Self(uuid::Builder::from_random_bytes(bytes).into_uuid())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for SecretId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Self)
    }
}

/// What a secret holds. Stored in the metadata so hosts can filter without
/// decrypting bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Login,
    Card,
    EnvSet,
    File,
    Note,
}

/// Everything needed to list, search and match a secret without its body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    pub title: String,
    pub kind: SecretKind,
    pub folder: FolderPath,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
    /// Origins or URL patterns this secret applies to (logins, Basic Auth).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// A login that answers HTTP Basic Auth on its URLs: tried first there,
    /// offered last in sign-in forms. Logins only.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub basic_auth: bool,
    /// Unix seconds, supplied by the host.
    pub created_at: u64,
    /// Unix seconds, supplied by the host.
    pub updated_at: u64,
}

/// The sensitive payload of a secret. Zeroed when dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "snake_case")]
pub enum SecretBody {
    Login(Login),
    Card(Card),
    EnvSet(EnvSet),
    File(File),
    Note(Note),
}

impl SecretBody {
    pub fn kind(&self) -> SecretKind {
        match self {
            Self::Login(_) => SecretKind::Login,
            Self::Card(_) => SecretKind::Card,
            Self::EnvSet(_) => SecretKind::EnvSet,
            Self::File(_) => SecretKind::File,
            Self::Note(_) => SecretKind::Note,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Login {
    pub username: String,
    pub password: String,
    /// TOTP seed or `otpauth://` URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Card {
    pub holder: String,
    pub number: String,
    pub expiry_month: u8,
    pub expiry_year: u16,
    pub cvv: String,
    #[serde(default)]
    pub notes: String,
}

/// An ordered set of environment variables, e.g. the dev config of one project.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EnvSet {
    pub vars: Vec<EnvVar>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct File {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(
        serialize_with = "crate::crypto::bytes::serialize",
        deserialize_with = "crate::crypto::bytes::deserialize_vec"
    )]
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Note {
    pub text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_id_is_uuid_v4_and_roundtrips_as_string() {
        let id = SecretId::from_random_bytes([7; 16]);
        assert_eq!(id.as_uuid().get_version_num(), 4);
        let text = id.to_string();
        assert_eq!(text.len(), 36);
        assert_eq!(text.parse::<SecretId>().unwrap(), id);
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{text}\""));
    }

    #[test]
    fn body_kind_matches_variant() {
        let body = SecretBody::EnvSet(EnvSet {
            vars: vec![EnvVar {
                key: "DB_URL".into(),
                value: "postgres://x".into(),
            }],
        });
        assert_eq!(body.kind(), SecretKind::EnvSet);
        assert_eq!(
            serde_json::to_string(&SecretKind::EnvSet).unwrap(),
            "\"env_set\""
        );
    }

    #[test]
    fn file_bytes_are_compact_in_cbor_and_base64_in_json() {
        let body = SecretBody::File(File {
            name: "id_ed25519".into(),
            mime: None,
            data: vec![0xAB; 1000],
        });
        let mut cbor = Vec::new();
        ciborium::into_writer(&body, &mut cbor).unwrap();
        // A CBOR byte string, not an array of 1000 integers.
        assert!(cbor.len() < 1100, "cbor was {} bytes", cbor.len());
        let back: SecretBody = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(back, body);

        // And base64 in JSON, which is what travels over the agent protocol.
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("\"data\":\"q6urq6"), "{json}");
        assert_eq!(serde_json::from_str::<SecretBody>(&json).unwrap(), body);
    }
}
