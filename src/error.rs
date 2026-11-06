//! The error type.
//!
//! One error type for the whole crate. Every variant carries a stable code
//! (`NEX-1001` and up) and a message that says what to do. Absence is never an
//! error: lookups return `Option`. No variant ever holds a secret: no token,
//! password, hash, digest, or key reaches an error or its message.

use std::{error::Error as StdError, fmt};

/// A specialised [`Result`](std::result::Result) whose error is [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong in nex-db.
///
/// The type is `#[non_exhaustive]`: later versions add variants without a
/// major version bump, so a `match` needs a wildcard arm.
///
/// ```
/// let err = nex_db::Error::AlreadyExists { what: "path" };
/// assert_eq!(err.code(), "NEX-1001");
/// assert!(err.to_string().contains("choose another"));
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// A unique value is taken: an identifier (`what = "identifier"`) or a
    /// route path (`what = "path"`). Choose another; for a sign-up, answer as
    /// if it succeeded so the response does not reveal which accounts exist.
    AlreadyExists {
        /// Which unique value is taken.
        what: &'static str,
    },
    /// The commit lost to concurrent commits on every retry. Retry later.
    Conflict,
    /// A bounded resource is full (for example the password-hashing slots).
    /// Back off and retry.
    Busy {
        /// The resource that is full.
        what: &'static str,
    },
    /// A value fails its rule. Fix the input.
    Invalid {
        /// The input that was refused.
        field: &'static str,
        /// Why it was refused.
        reason: &'static str,
    },
    /// A key the database needs cannot be read. The database stays closed.
    /// Restore the key file, or restore the database from a backup.
    KeyUnavailable,
    /// Another process owns the database directory. Stop that process, or
    /// open a different directory.
    Locked,
    /// Stored data failed a check. The database stays closed. Restore it from
    /// a backup.
    Corrupt {
        /// What failed the check.
        what: &'static str,
        /// The log sequence number or byte offset where it was found, when
        /// known.
        at: u64,
    },
    /// The operating system refused an operation, or a write could not be
    /// made durable. After a failed write the database refuses further
    /// commits; reads continue. Check the disk, then restart the process:
    /// recovery decides what is durable.
    Storage {
        /// What the database was doing.
        what: &'static str,
        /// The underlying error.
        source: Box<dyn StdError + Send + Sync + 'static>,
    },
    /// A [`Database::read`](crate::Database::read) ran longer than the
    /// snapshot age limit (60 seconds). Read again.
    SnapshotTooOld,
}

impl Error {
    /// The stable code of this error, for logs and support.
    ///
    /// ```
    /// assert_eq!(nex_db::Error::Conflict.code(), "NEX-1002");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Error::AlreadyExists { .. } => "NEX-1001",
            Error::Conflict => "NEX-1002",
            Error::Busy { .. } => "NEX-1003",
            Error::Invalid { .. } => "NEX-1004",
            Error::KeyUnavailable => "NEX-1005",
            Error::Locked => "NEX-1006",
            Error::Corrupt { .. } => "NEX-1007",
            Error::Storage { .. } => "NEX-1008",
            Error::SnapshotTooOld => "NEX-1009",
        }
    }

    pub(crate) fn storage(
        what: &'static str,
        source: impl Into<Box<dyn StdError + Send + Sync + 'static>>,
    ) -> Self {
        Error::Storage {
            what,
            source: source.into(),
        }
    }

    pub(crate) const fn invalid(field: &'static str, reason: &'static str) -> Self {
        Error::Invalid { field, reason }
    }

    pub(crate) const fn corrupt(what: &'static str, at: u64) -> Self {
        Error::Corrupt { what, at }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Error::AlreadyExists { what } => {
                write!(f, "{code}: the {what} is taken; choose another")
            }
            Error::Conflict => write!(
                f,
                "{code}: the commit conflicted with concurrent commits on every retry; retry later"
            ),
            Error::Busy { what } => write!(f, "{code}: {what} is full; back off and retry"),
            Error::Invalid { field, reason } => {
                write!(f, "{code}: invalid {field}: {reason}")
            }
            Error::KeyUnavailable => write!(
                f,
                "{code}: a database key cannot be read; the database stays closed. Restore the \
                 key file or restore the database from a backup"
            ),
            Error::Locked => write!(
                f,
                "{code}: another process owns the database directory; stop it or open another \
                 directory"
            ),
            Error::Corrupt { what, at } => write!(
                f,
                "{code}: {what} failed a check at {at}; the database stays closed. Restore it \
                 from a backup"
            ),
            Error::Storage { what, source } => write!(
                f,
                "{code}: storage failed while {what}: {source}. Check the disk, then restart the \
                 process"
            ),
            Error::SnapshotTooOld => write!(
                f,
                "{code}: the read ran past the snapshot age limit; read again"
            ),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Storage { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<wal_db::WalError> for Error {
    fn from(err: wal_db::WalError) -> Self {
        match err {
            wal_db::WalError::Corruption { offset, .. } => Error::corrupt("the commit log", offset),
            other => Error::storage("writing the commit log", other),
        }
    }
}

#[cfg(any(feature = "auth", feature = "content"))]
impl From<lsm_db::Error> for Error {
    fn from(err: lsm_db::Error) -> Self {
        Error::storage("using an engine store", err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_every_variant_is_unique() {
        let all = [
            Error::AlreadyExists { what: "path" },
            Error::Conflict,
            Error::Busy { what: "x" },
            Error::invalid("f", "r"),
            Error::KeyUnavailable,
            Error::Locked,
            Error::corrupt("x", 0),
            Error::storage("x", "y"),
            Error::SnapshotTooOld,
        ];
        let mut codes: Vec<&str> = all.iter().map(Error::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn test_display_storage_includes_source_and_code() {
        let err = Error::storage("syncing", "disk gone");
        let text = err.to_string();
        assert!(text.starts_with("NEX-1008"));
        assert!(text.contains("disk gone"));
        assert!(err.source().is_some());
    }

    #[test]
    fn test_from_wal_corruption_maps_to_corrupt() {
        let err: Error = wal_db::WalError::Corruption {
            offset: 7,
            reason: "x",
        }
        .into();
        assert!(matches!(err, Error::Corrupt { at: 7, .. }));
    }
}
