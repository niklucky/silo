//! Vault model: secrets, nested folders and tags.
//!
//! Planned shape, to be implemented in the next step:
//!
//! - Secret kinds: website login, bank card, environment variable set, secret file.
//! - Every secret lives in exactly one nested folder path (`projects/wallet`) and
//!   carries zero or more tags.
//! - Metadata (title, folder, tags, URL) is encrypted alongside the payload; all
//!   search and URL matching happens client-side after unlock.
