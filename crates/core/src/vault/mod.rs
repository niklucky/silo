//! Vault model: secrets, nested folders and tags.
//!
//! A secret is split in two encrypted parts under one data key:
//!
//! - [`SecretMeta`]: title, kind, folder, tags, URLs, timestamps. Decrypted for
//!   every secret on unlock so hosts can list, search and match URLs.
//! - [`SecretBody`]: the sensitive payload. Decrypted on demand only, so a host
//!   never has to hold every password in memory at once.
//!
//! Both parts travel inside a [`SealedSecret`]; access to the data key is
//! expressed as a [`Grant`] per recipient.

mod path;
mod sealed;
mod secret;
mod urls;

pub use path::{FolderPath, Tag};
pub use sealed::{Grant, SealedSecret, StoredSecret};
pub use secret::{
    Card, EnvSet, EnvVar, File, Login, Note, SecretBody, SecretId, SecretKind, SecretMeta,
};
pub use url::Url;
pub use urls::{UrlMatch, best_url_match, registrable_domain, same_site, site_of, url_match};
