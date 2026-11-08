//! A realm's policy: lock-out, session limits, and how accounts start.

use std::time::Duration;

use crate::{
    core::codec::{Reader, Writer},
    error::{Error, Result},
};

/// Format of an encoded policy (a realm's catalog definition).
const FORMAT: u8 = 1;

const MAX_SESSION_MS: u64 = 400 * 24 * 60 * 60 * 1000;

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A realm's policy, for [`Database::define_realm`](crate::Database::define_realm)
/// and [`Database::set_realm_policy`](crate::Database::set_realm_policy).
///
/// ```
/// use std::time::Duration;
/// use nex_db::RealmPolicy;
/// let staff = RealmPolicy::new()
///     .lockout(5, Duration::from_secs(600), Duration::from_secs(3600))
///     .max_session(Duration::from_secs(8 * 3600))
///     .max_idle(Duration::from_secs(1800))
///     .pending_verification();
/// # let _ = staff;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct RealmPolicy {
    pub(crate) lockout_failures: u32,
    pub(crate) lockout_window_ms: u64,
    pub(crate) lockout_ms: u64,
    pub(crate) max_session_ms: u64,
    /// 0 for none.
    pub(crate) max_idle_ms: u64,
    pub(crate) pending_verification: bool,
}

impl Default for RealmPolicy {
    fn default() -> Self {
        RealmPolicy::new()
    }
}

impl RealmPolicy {
    /// The default policy: ten failed sign-ins within fifteen minutes lock
    /// an account out for fifteen minutes; sessions last at most 400 days
    /// with no idle limit; new accounts start [`Active`](crate::Standing::Active).
    pub const fn new() -> RealmPolicy {
        RealmPolicy {
            lockout_failures: 10,
            lockout_window_ms: 15 * 60 * 1000,
            lockout_ms: 15 * 60 * 1000,
            max_session_ms: MAX_SESSION_MS,
            max_idle_ms: 0,
            pending_verification: false,
        }
    }

    /// `failures` failed sign-ins within `window` lock an account out for
    /// `duration` (`failures` at least 1, both times at least a second).
    pub fn lockout(mut self, failures: u32, window: Duration, duration: Duration) -> RealmPolicy {
        self.lockout_failures = failures.max(1);
        self.lockout_window_ms = ms(window).max(1000);
        self.lockout_ms = ms(duration).max(1000);
        self
    }

    /// The longest a session lasts (at most 400 days): a longer one asked
    /// for is cut to it.
    pub fn max_session(mut self, limit: Duration) -> RealmPolicy {
        self.max_session_ms = ms(limit).clamp(1000, MAX_SESSION_MS);
        self
    }

    /// The longest a session may go unused: a session asked for with no
    /// idle limit, or a longer one, gets this one.
    pub fn max_idle(mut self, limit: Duration) -> RealmPolicy {
        self.max_idle_ms = ms(limit).max(1000);
        self
    }

    /// New accounts start [`PendingVerification`](crate::Standing::PendingVerification).
    pub fn pending_verification(mut self) -> RealmPolicy {
        self.pending_verification = true;
        self
    }

    /// The session lifetime and idle limit a session asked for with `ttl_ms`
    /// and `idle_ms` (0 for none) gets in this realm.
    pub(crate) fn limit(&self, ttl_ms: u64, idle_ms: u64) -> (u64, u64) {
        let idle = match (idle_ms, self.max_idle_ms) {
            (0, max) => max,
            (asked, 0) => asked,
            (asked, max) => asked.min(max),
        };
        (ttl_ms.min(self.max_session_ms), idle)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(38);
        let mut w = Writer::new(&mut out);
        w.u8(FORMAT);
        w.u32(self.lockout_failures);
        w.u64(self.lockout_window_ms);
        w.u64(self.lockout_ms);
        w.u64(self.max_session_ms);
        w.u64(self.max_idle_ms);
        w.u8(u8::from(self.pending_verification));
        out
    }

    /// The policy a realm definition holds; the default for an empty one.
    pub(crate) fn decode(bytes: &[u8]) -> Result<RealmPolicy> {
        if bytes.is_empty() {
            return Ok(RealmPolicy::new());
        }
        let bad = || Error::invalid("realm definition", "not a realm policy");
        let mut r = Reader::new(bytes, "a realm policy", 0);
        if r.u8().map_err(|_| bad())? != FORMAT {
            return Err(bad());
        }
        let policy = RealmPolicy {
            lockout_failures: r.u32().map_err(|_| bad())?,
            lockout_window_ms: r.u64().map_err(|_| bad())?,
            lockout_ms: r.u64().map_err(|_| bad())?,
            max_session_ms: r.u64().map_err(|_| bad())?,
            max_idle_ms: r.u64().map_err(|_| bad())?,
            pending_verification: match r.u8().map_err(|_| bad())? {
                0 => false,
                1 => true,
                _ => return Err(bad()),
            },
        };
        r.finish().map_err(|_| bad())?;
        if policy.lockout_failures == 0 || policy.max_session_ms > MAX_SESSION_MS {
            return Err(bad());
        }
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_round_trips_and_limits_sessions() {
        let policy = RealmPolicy::new()
            .lockout(3, Duration::from_secs(60), Duration::from_secs(120))
            .max_session(Duration::from_secs(3600))
            .max_idle(Duration::from_secs(600))
            .pending_verification();
        assert_eq!(RealmPolicy::decode(&policy.encode()).unwrap(), policy);
        assert_eq!(RealmPolicy::decode(&[]).unwrap(), RealmPolicy::new());
        assert!(RealmPolicy::decode(&[9]).is_err());
        assert_eq!(policy.limit(10_000_000, 0), (3_600_000, 600_000));
        assert_eq!(policy.limit(1000, 60_000), (1000, 60_000));
        assert_eq!(RealmPolicy::new().limit(5, 0), (5, 0));
    }
}
