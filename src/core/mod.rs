//! The core: commit log, record format, catalog, conflict tables, files.

pub(crate) mod catalog;
pub(crate) mod codec;
pub(crate) mod conflict;
pub(crate) mod fs;
pub(crate) mod keys;
pub(crate) mod log;
pub(crate) mod pipeline;
pub(crate) mod record;
pub(crate) mod ship;
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

/// The store keys that start with `prefix`, as the range a store scan takes:
/// from the prefix up to, not including, the prefix with its last byte below
/// `0xFF` raised by one. A prefix of only `0xFF` bytes has no such end, so its
/// range is open-ended instead of empty.
#[cfg(any(feature = "auth", feature = "content"))]
pub(crate) fn prefix_range(prefix: &[u8]) -> (std::ops::Bound<Vec<u8>>, std::ops::Bound<Vec<u8>>) {
    use std::ops::Bound;
    let end = match prefix.iter().rposition(|&b| b < u8::MAX) {
        Some(last) => {
            let mut end = prefix[..=last].to_vec();
            end[last] = prefix[last] + 1;
            Bound::Excluded(end)
        }
        None => Bound::Unbounded,
    };
    (Bound::Included(prefix.to_vec()), end)
}

/// Milliseconds since the Unix epoch, or 0 if the clock is before it.
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

    #[test]
    fn test_prefix_range_bounds_a_prefix_scan() {
        use std::ops::{Bound, RangeBounds};
        let range = |p: &[u8]| super::prefix_range(p);
        assert_eq!(range(&[1, 2]).1, Bound::Excluded(vec![1, 3]));
        assert_eq!(range(&[1, 0xFF]).1, Bound::Excluded(vec![2]));
        // A prefix of only 0xFF bytes: open-ended, not an empty range.
        assert_eq!(range(&[0xFF]).1, Bound::Unbounded);
        assert_eq!(range(&[0xFF, 0xFF]).1, Bound::Unbounded);
        let all_ff = range(&[0xFF]);
        assert!(all_ff.contains(&vec![0xFF, 0xFF, 0x01]));
        assert!(!all_ff.contains(&vec![0xFE]));
        let r = range(&[1, 2]);
        assert!(r.contains(&vec![1, 2]) && r.contains(&vec![1, 2, 0xFF]));
        assert!(!r.contains(&vec![1, 3]) && !r.contains(&vec![1, 1, 0xFF]));
    }
}
