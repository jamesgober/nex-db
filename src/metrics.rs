//! An observer that reports into metrics-lib (feature `metrics`).
//!
//! Every metric is registered when the [`Recorder`] is made, so recording a
//! commit, an error, or a security event is a few atomic adds with no lookup.

use std::sync::Arc;

use metrics_lib::{Counter, LabelSet, Registry, Timer};

use crate::{
    error::Error,
    observe::{CommitInfo, Observer, SecurityEvent},
};

/// Commits that landed.
const COMMITS: &str = "nex_db_commits_total";
/// Closure runs beyond the first, from conflicts.
const RETRIES: &str = "nex_db_commit_retries_total";
/// Time a commit took, from its first attempt until durable and visible.
const COMMIT_TIME: &str = "nex_db_commit_seconds";
/// Errors returned, by code.
const ERRORS: &str = "nex_db_errors_total";
/// Security events, by kind.
const SECURITY: &str = "nex_db_security_events_total";

/// Every error code, in the order of [`Error::code`]'s numbers.
const CODES: [&str; 12] = [
    "NEX-1001", "NEX-1002", "NEX-1003", "NEX-1004", "NEX-1005", "NEX-1006", "NEX-1007", "NEX-1008",
    "NEX-1009", "NEX-1010", "NEX-1011", "NEX-1012",
];

/// Security event kinds, as labels.
const KINDS: [&str; 5] = [
    "sign_in_failed",
    "locked_out",
    "sign_in_blocked",
    "revoked_session_presented",
    "canary_requested",
];

/// Reports a database's commits, errors, and security events into a
/// metrics-lib [`Registry`], for [`Builder::observer`](crate::Builder::observer):
///
/// | Metric | Kind | Labels |
/// |---|---|---|
/// | `nex_db_commits_total` | counter | |
/// | `nex_db_commit_retries_total` | counter | |
/// | `nex_db_commit_seconds` | timer | |
/// | `nex_db_errors_total` | counter | `code` (`NEX-1001` and up) |
/// | `nex_db_security_events_total` | counter | `kind` |
///
/// Labels carry codes and kinds only, never an account or identifier.
///
/// ```no_run
/// # fn main() -> nex_db::Result<()> {
/// use std::sync::Arc;
/// let registry = Arc::new(metrics_lib::Registry::new());
/// let db = nex_db::Database::builder("data/site")
///     .observer(nex_db::metrics::Recorder::new(&registry))
///     .open()?;
/// # let _ = db;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Recorder {
    commits: Arc<Counter>,
    retries: Arc<Counter>,
    commit_time: Arc<Timer>,
    errors: Vec<Arc<Counter>>,
    security: Vec<Arc<Counter>>,
}

impl Recorder {
    /// A recorder reporting into `registry`.
    #[must_use]
    pub fn new(registry: &Registry) -> Recorder {
        let labelled = |name: &'static str, key: &'static str, value: &'static str| {
            registry.counter_with(name, &LabelSet::from([(key, value)]))
        };
        Recorder {
            commits: registry.counter(COMMITS),
            retries: registry.counter(RETRIES),
            commit_time: registry.timer(COMMIT_TIME),
            errors: CODES.iter().map(|c| labelled(ERRORS, "code", c)).collect(),
            security: KINDS
                .iter()
                .map(|k| labelled(SECURITY, "kind", k))
                .collect(),
        }
    }
}

impl Observer for Recorder {
    fn on_commit(&self, commit: &CommitInfo) {
        self.commits.inc();
        self.retries
            .add(u64::from(commit.attempts().saturating_sub(1)));
        self.commit_time.record(commit.took());
    }

    fn on_error(&self, error: &Error) {
        let number: usize = error
            .code()
            .strip_prefix("NEX-")
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        if let Some(counter) = number.checked_sub(1001).and_then(|i| self.errors.get(i)) {
            counter.inc();
        }
    }

    fn on_security_event(&self, event: &SecurityEvent) {
        let kind = match event {
            SecurityEvent::SignInFailed { .. } => 0,
            SecurityEvent::LockedOut { .. } => 1,
            SecurityEvent::SignInBlocked => 2,
            SecurityEvent::RevokedSessionPresented => 3,
            SecurityEvent::CanaryRequested => 4,
        };
        if let Some(counter) = self.security.get(kind) {
            counter.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{feed::Position, ids::AccountId};

    #[test]
    fn test_recorder_counts_commits_errors_and_events() {
        let registry = Registry::new();
        let recorder = Recorder::new(&registry);
        recorder.on_commit(&CommitInfo {
            position: Position(1),
            attempts: 3,
            took: std::time::Duration::from_millis(2),
        });
        recorder.on_error(&Error::Conflict);
        recorder.on_security_event(&SecurityEvent::LockedOut {
            account: AccountId::from_bytes([1; 16]),
        });
        assert_eq!(registry.counter(COMMITS).get(), 1);
        assert_eq!(registry.counter(RETRIES).get(), 2);
        let conflict = LabelSet::from([("code", "NEX-1002")]);
        assert_eq!(registry.counter_with(ERRORS, &conflict).get(), 1);
        let locked = LabelSet::from([("kind", "locked_out")]);
        assert_eq!(registry.counter_with(SECURITY, &locked).get(), 1);
        assert_eq!(registry.timer(COMMIT_TIME).count(), 1);
    }
}
