//! The core: commit log, record format, catalog, conflict tables, files.

pub(crate) mod catalog;
pub(crate) mod codec;
pub(crate) mod conflict;
pub(crate) mod fs;
pub(crate) mod keys;
pub(crate) mod log;
pub(crate) mod pipeline;
pub(crate) mod record;

/// Milliseconds since the Unix epoch, or 0 if the clock is before it.
#[cfg(any(feature = "auth", feature = "content"))]
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
