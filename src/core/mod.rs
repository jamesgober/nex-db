//! The core: commit log, record format, catalog, conflict tables, files.

pub(crate) mod catalog;
pub(crate) mod codec;
pub(crate) mod conflict;
pub(crate) mod fs;
pub(crate) mod keys;
pub(crate) mod log;
pub(crate) mod pipeline;
pub(crate) mod record;
pub(crate) mod turn;
pub(crate) mod versions;

/// The latest time nex-db turns a stored millisecond count into: the end of
/// the year 9999, which every platform's `SystemTime` can hold. Larger
/// counts (only damaged data holds them) are clamped, so reading a time
/// never panics.
#[cfg(any(feature = "auth", feature = "content"))]
const MAX_TIME_MS: u64 = 253_402_300_799_999;

/// The time `ms` milliseconds after the Unix epoch, clamped to
/// [`MAX_TIME_MS`].
#[cfg(any(feature = "auth", feature = "content"))]
pub(crate) fn time_of(ms: u64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms.min(MAX_TIME_MS))
}

/// Milliseconds since the Unix epoch, or 0 if the clock is before it.
#[cfg(any(feature = "auth", feature = "content"))]
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(all(test, any(feature = "auth", feature = "content")))]
mod tests {
    #[test]
    fn test_time_of_huge_count_is_clamped_not_a_panic() {
        assert_eq!(super::time_of(u64::MAX), super::time_of(super::MAX_TIME_MS));
    }
}
