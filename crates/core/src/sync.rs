//! Sync protocol between hosts and the server.
//!
//! Planned shape, to be implemented in the next step:
//!
//! - The server stores opaque encrypted blobs, version numbers and grants. It never
//!   sees plaintext or keys.
//! - Clients push new versions and pull changes since a cursor.
//! - Grants reference a secret and a grantee public key; "shared with whom" is a
//!   query over this table.
//!
//! This module defines the wire types only. Transport is supplied by the host.
