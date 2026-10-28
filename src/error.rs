//! Failures that recovery classifies. Recovery inspects these by type, never
//! by message text, because messages can carry storage-controlled strings.

use std::io;

use thiserror::Error;

/// A required storage object is missing or could not be read.
#[derive(Debug, Error)]
#[error("{storage} object {id} is unavailable")]
pub struct ObjectUnavailable {
    pub storage: &'static str,
    pub id: String,
    #[source]
    pub source: Option<io::Error>,
}

/// Storage holds no HEAD at all.
#[derive(Debug, Error)]
#[error("encrypted repository has no storage HEAD")]
pub struct MissingStorageHead;

/// A format version or transition this implementation does not support.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct Unsupported(pub String);

/// No generation-key envelope opens for this device.
#[derive(Debug, Error)]
#[error(
    "device is not an active reader of the current generation (revoked, never added, or envelope malformed)"
)]
pub struct NotActiveReader;

/// The local key file and the manifest name different repository roots.
#[derive(Debug, Error)]
#[error("key file belongs to a different repository")]
pub struct ForeignRepository;

/// A fixed recovery budget ran out; recovery fails closed.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct BudgetExhausted(pub String);
