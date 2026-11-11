//! The change feed: committed changes, in order, for keeping caches
//! current.
//!
//! Engines report what each commit changed while they apply it; the core
//! keeps the changes of the last [`FEED_COMMITS`] commits that changed
//! anything. A reader asks for every change after a [`Position`] and gets
//! [`Error::FeedBehind`] when that is older than what is kept (or than the
//! last open): it then drops what it built from the feed and starts again
//! from [`Database::position`](crate::Database::position). Auth changes name
//! ids only, never a token, digest, identifier, or hash.

use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, PoisonError},
    time::{Duration, Instant},
};

use crate::{
    Database,
    core::record::Seq,
    error::{Error, Result},
    ids::{AccountId, EntityId},
};

/// Commits kept, counting only those that changed something the feed
/// reports.
pub(crate) const FEED_COMMITS: usize = 65_536;

/// A point in the commit order: a feed resumes after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position(pub(crate) Seq);

impl Position {
    /// The position as a number, to store and give back to
    /// [`Position::from_u64`].
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// A position from [`get`](Self::get).
    #[must_use]
    pub const fn from_u64(position: u64) -> Position {
        Position(position)
    }
}

/// One change a commit made.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// An entity's draft, status, or published revision changed. `revision`
    /// is the published one (0 when nothing is).
    EntityChanged {
        /// The entity.
        entity: EntityId,
        /// Its published revision after the commit.
        revision: u32,
    },
    /// A route was set or removed.
    RouteChanged {
        /// The site.
        site: String,
        /// The path.
        path: String,
    },
    /// An account was created.
    AccountCreated {
        /// The account.
        account: AccountId,
    },
    /// A session ended (`revoke`, `rotate`), or every session of an account
    /// (`revoke_all`, a password change, a blocking standing). `None` when
    /// the session's account is not known.
    SessionRevoked {
        /// The account, when known.
        account: Option<AccountId>,
    },
    /// An account's standing changed.
    StandingChanged {
        /// The account.
        account: AccountId,
    },
    /// An account's roles, identifiers, or password changed.
    AccountChanged {
        /// The account.
        account: AccountId,
    },
    /// An account was erased.
    AccountErased {
        /// The account.
        account: AccountId,
    },
}

#[derive(Debug, Default)]
struct Ring {
    commits: VecDeque<(Seq, Arc<[Change]>)>,
    /// Changes at or below this are not kept.
    kept_after: Seq,
    /// The newest commit pushed (with or without changes).
    last: Seq,
}

/// The core's window of recent changes.
#[derive(Debug, Default)]
pub(crate) struct FeedLog {
    ring: Mutex<Ring>,
    added: Condvar,
}

impl FeedLog {
    /// A feed whose first commit will follow `last`.
    #[cfg(test)]
    pub(crate) fn starting_after(last: Seq) -> FeedLog {
        FeedLog {
            ring: Mutex::new(Ring {
                commits: VecDeque::new(),
                kept_after: last,
                last,
            }),
            added: Condvar::new(),
        }
    }

    /// After recovery: the feed starts after `last`.
    pub(crate) fn reset(&self, last: Seq) {
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        ring.commits.clear();
        ring.kept_after = last;
        ring.last = last;
    }

    /// Record what commit `seq` changed. Called in commit order.
    pub(crate) fn push(&self, seq: Seq, changes: Vec<Change>) {
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        ring.last = ring.last.max(seq);
        if !changes.is_empty() {
            if ring.commits.len() >= FEED_COMMITS {
                if let Some((dropped, _)) = ring.commits.pop_front() {
                    ring.kept_after = dropped;
                }
            }
            ring.commits.push_back((seq, changes.into()));
        }
        drop(ring);
        self.added.notify_all();
    }

    /// Append to `out` every change after `after`, waiting up to `timeout`
    /// for one when there is none yet.
    fn read(
        &self,
        after: Seq,
        timeout: Option<Duration>,
        out: &mut VecDeque<(Position, Change)>,
    ) -> Result<()> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut ring = self.ring.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if after < ring.kept_after {
                return Err(Error::FeedBehind {
                    oldest: ring.kept_after,
                });
            }
            let start = ring.commits.partition_point(|(seq, _)| *seq <= after);
            if start < ring.commits.len() {
                for (seq, changes) in ring.commits.range(start..) {
                    out.extend(changes.iter().map(|c| (Position(*seq), c.clone())));
                }
                return Ok(());
            }
            let wait = match deadline {
                None => None,
                Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                    Some(left) if !left.is_zero() => Some(left),
                    _ => return Ok(()),
                },
            };
            ring = match wait {
                None => self
                    .added
                    .wait(ring)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(left) => {
                    self.added
                        .wait_timeout(ring, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
    }

    /// The newest commit the feed has seen.
    #[cfg(test)]
    pub(crate) fn last(&self) -> Seq {
        self.ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last
    }
}

/// Committed changes after a position, from
/// [`Database::feed`](crate::Database::feed).
///
/// ```no_run
/// # fn main() -> nex_db::Result<()> {
/// use std::time::Duration;
/// use nex_db::Change;
///
/// let db = nex_db::open("data/site")?;
/// let mut feed = db.feed(db.position())?;
/// while let Some((_position, change)) = feed.next_timeout(Duration::from_secs(1))? {
///     if let Change::EntityChanged { entity, .. } = change {
///         // drop cached pages built from `entity`
///         # let _ = entity;
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// As an [`Iterator`] it blocks until the next change: use
/// [`next_timeout`](Self::next_timeout) on a thread that must stop. Resume
/// later from the position of the last commit whose changes were all
/// handled.
#[derive(Debug)]
pub struct Feed<'db> {
    db: &'db Database,
    after: Seq,
    pending: VecDeque<(Position, Change)>,
}

impl<'db> Feed<'db> {
    pub(crate) fn new(db: &'db Database, after: Position) -> Result<Feed<'db>> {
        let mut feed = Feed {
            db,
            after: after.0,
            pending: VecDeque::new(),
        };
        // Refuse a position the feed no longer covers at once.
        feed.fill(Some(Duration::ZERO))?;
        Ok(feed)
    }

    fn fill(&mut self, timeout: Option<Duration>) -> Result<()> {
        if self.pending.is_empty() {
            self.db
                .feed_log()
                .read(self.after, timeout, &mut self.pending)?;
            if let Some((position, _)) = self.pending.back() {
                self.after = position.0;
            }
        }
        Ok(())
    }

    /// The next change, waiting up to `timeout` for one; `None` when none
    /// came.
    ///
    /// # Errors
    ///
    /// [`Error::FeedBehind`] when the feed no longer covers its position.
    pub fn next_timeout(&mut self, timeout: Duration) -> Result<Option<(Position, Change)>> {
        self.fill(Some(timeout))?;
        Ok(self.pending.pop_front())
    }

    /// The next change if one is there now.
    ///
    /// # Errors
    ///
    /// As [`next_timeout`](Self::next_timeout).
    pub fn try_next(&mut self) -> Result<Option<(Position, Change)>> {
        self.next_timeout(Duration::ZERO)
    }
}

impl Iterator for Feed<'_> {
    type Item = Result<(Position, Change)>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.fill(None) {
            Ok(()) => self.pending.pop_front().map(Ok),
            Err(err) => Some(Err(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn created(n: u8) -> Change {
        Change::AccountCreated {
            account: AccountId::from_bytes([n; 16]),
        }
    }

    #[test]
    fn test_read_returns_changes_after_a_position_in_order() {
        let log = FeedLog::starting_after(10);
        log.push(11, vec![created(1), created(2)]);
        log.push(12, Vec::new());
        log.push(13, vec![created(3)]);
        let mut out = VecDeque::new();
        log.read(10, Some(Duration::ZERO), &mut out).unwrap();
        let seqs: Vec<u64> = out.iter().map(|(p, _)| p.get()).collect();
        assert_eq!(seqs, [11, 11, 13]);
        out.clear();
        log.read(11, Some(Duration::ZERO), &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(log.last(), 13);
        assert!(matches!(
            log.read(9, Some(Duration::ZERO), &mut out),
            Err(Error::FeedBehind { oldest: 10 })
        ));
    }

    #[test]
    fn test_a_full_ring_drops_the_oldest_and_says_so() {
        let log = FeedLog::starting_after(0);
        for seq in 1..=(FEED_COMMITS as u64 + 2) {
            log.push(seq, vec![created(1)]);
        }
        let mut out = VecDeque::new();
        assert!(matches!(
            log.read(1, Some(Duration::ZERO), &mut out),
            Err(Error::FeedBehind { oldest: 2 })
        ));
        log.read(2, Some(Duration::ZERO), &mut out).unwrap();
        assert_eq!(out.len(), FEED_COMMITS);
    }

    #[test]
    fn test_read_waits_for_a_change() {
        let log = Arc::new(FeedLog::starting_after(0));
        let writer = {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                log.push(1, vec![created(7)]);
            })
        };
        let mut out = VecDeque::new();
        log.read(0, Some(Duration::from_secs(10)), &mut out)
            .unwrap();
        assert_eq!(out.len(), 1);
        writer.join().unwrap();
        out.clear();
        log.read(1, Some(Duration::from_millis(10)), &mut out)
            .unwrap();
        assert!(out.is_empty());
    }
}
