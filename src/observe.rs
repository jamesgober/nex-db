//! Health and observers: how the database reports on itself.
//!
//! An [`Observer`] set with [`Builder::observer`](crate::Builder::observer)
//! hears about every commit, every error a call returns, and every security
//! event; with none set, nothing is called. Security events carry ids and
//! kinds only, never an identifier, token, or hash.

use std::{fmt, time::Duration};

use crate::{error::Error, feed::Position, ids::AccountId};

/// The database's health.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Serving reads and writes.
    Ready,
    /// Replaying its log; nothing is served yet.
    Recovering,
    /// Serving reads only, after a failed write: restart the process to
    /// recover.
    ReadOnly {
        /// Why writes stopped.
        reason: &'static str,
    },
}

/// A commit that landed, as [`Observer::on_commit`] sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitInfo {
    pub(crate) position: Position,
    pub(crate) attempts: u32,
    pub(crate) took: Duration,
}

impl CommitInfo {
    /// The commit's position in the change feed.
    #[must_use]
    pub const fn position(&self) -> Position {
        self.position
    }

    /// How many times the transaction ran (more than 1 after a conflict).
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// From the first attempt to the commit being visible.
    #[must_use]
    pub const fn took(&self) -> Duration {
        self.took
    }
}

/// Something an operator or intrusion detection should know about.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent {
    /// A sign-in failed: a wrong password for `account`, or (`None`) an
    /// identifier no account has.
    SignInFailed {
        /// The account, when the identifier named one.
        account: Option<AccountId>,
    },
    /// Repeated failures locked `account` out.
    LockedOut {
        /// The account.
        account: AccountId,
    },
    /// A sign-in was refused because the account's standing blocks it.
    SignInBlocked,
    /// A revoked session's token was presented again.
    RevokedSessionPresented,
    /// A canary path was resolved ([`ContentTx::add_canary`](crate::ContentTx::add_canary)):
    /// most likely a scanner. The path is the one the application just
    /// resolved on this thread.
    CanaryRequested,
}

/// Receives commits, errors, and security events. Every method has an
/// empty default. Calls happen on the thread that made the database call,
/// so they should be quick (hand work to another thread).
pub trait Observer: Send + Sync + 'static {
    /// A commit landed.
    fn on_commit(&self, _commit: &CommitInfo) {}

    /// A call returned `error`.
    fn on_error(&self, _error: &Error) {}

    /// A security event happened.
    fn on_security_event(&self, _event: &SecurityEvent) {}
}

/// The observer, or none.
#[derive(Clone, Default)]
pub(crate) struct Observers(pub(crate) Option<std::sync::Arc<dyn Observer>>);

impl fmt::Debug for Observers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "Some(observer)"
        } else {
            "None"
        })
    }
}

impl Observers {
    pub(crate) fn commit(&self, commit: &CommitInfo) {
        if let Some(o) = &self.0 {
            o.on_commit(commit);
        }
    }

    pub(crate) fn error(&self, error: &Error) {
        if let Some(o) = &self.0 {
            o.on_error(error);
        }
    }

    #[cfg_attr(not(feature = "auth"), allow(dead_code))]
    pub(crate) fn security(&self, event: SecurityEvent) {
        if let Some(o) = &self.0 {
            o.on_security_event(&event);
        }
    }
}
