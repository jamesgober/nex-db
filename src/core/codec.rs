//! Hand-written fixed-width little-endian encoding.
//!
//! Every byte format nex-db writes (log records, engine sections, stored
//! records, the catalog checkpoint) is built with [`Writer`] and read back with
//! [`Reader`]. No serialization framework is involved, so a frozen format
//! cannot drift with a dependency. A reader never trusts a length: every read
//! is checked against the bytes that remain, and a short or malformed input is
//! [`Error::Corrupt`].

// Builds with one engine use only part of the codec.
#![cfg_attr(not(all(feature = "auth", feature = "content")), allow(dead_code))]

use crate::error::{Error, Result};

/// Appends fixed-width values to a byte buffer.
pub(crate) struct Writer<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        Writer { out }
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u128(&mut self, v: u128) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn i64(&mut self, v: i64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) {
        self.out.extend_from_slice(v);
    }

    /// A byte string with a `u16` length prefix. The caller has checked the
    /// length against its limit; a longer value is a bug and is refused.
    pub(crate) fn str16(&mut self, v: &str) -> Result<()> {
        let len = u16::try_from(v.len()).map_err(|_| Error::invalid("value", "too long"))?;
        self.u16(len);
        self.bytes(v.as_bytes());
        Ok(())
    }

    /// A byte string with a `u16` length prefix.
    pub(crate) fn bytes16(&mut self, v: &[u8]) -> Result<()> {
        let len = u16::try_from(v.len()).map_err(|_| Error::invalid("value", "too long"))?;
        self.u16(len);
        self.bytes(v);
        Ok(())
    }

    /// A byte string with a `u32` length prefix.
    pub(crate) fn bytes32(&mut self, v: &[u8]) -> Result<()> {
        let len = u32::try_from(v.len()).map_err(|_| Error::invalid("value", "too long"))?;
        self.u32(len);
        self.bytes(v);
        Ok(())
    }

    /// The current length of the buffer, for back-patching a length field.
    pub(crate) fn position(&self) -> usize {
        self.out.len()
    }

    /// Overwrite four bytes at `at` with `v`.
    pub(crate) fn patch_u32(&mut self, at: usize, v: u32) -> Result<()> {
        let slot = self
            .out
            .get_mut(at..at + 4)
            .ok_or(Error::invalid("record", "length field out of range"))?;
        slot.copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
}

/// Reads fixed-width values from a byte slice, checking every length.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Reported in [`Error::Corrupt`] when the input is malformed.
    what: &'static str,
    /// Reported as the location in [`Error::Corrupt`].
    at: u64,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], what: &'static str, at: u64) -> Self {
        Reader {
            buf,
            pos: 0,
            what,
            at,
        }
    }

    fn corrupt(&self) -> Error {
        Error::corrupt(self.what, self.at)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.corrupt())?;
        let slice = self.buf.get(self.pos..end).ok_or_else(|| self.corrupt())?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(crate) fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.array()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.array()
    }

    pub(crate) fn str16(&mut self) -> Result<&'a str> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes).map_err(|_| self.corrupt())
    }

    pub(crate) fn bytes16(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    pub(crate) fn bytes32(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| self.corrupt())?;
        self.take(len)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Fail unless every byte was consumed: trailing bytes mean the input is
    /// not what its writer produced.
    pub(crate) fn finish(&self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(self.corrupt())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_every_width_matches() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        w.u8(1);
        w.u16(2);
        w.u32(3);
        w.u64(4);
        w.u128(5);
        w.i64(-6);
        w.str16("seven").unwrap();
        w.bytes32(b"eight").unwrap();
        w.bytes16(b"nine").unwrap();
        w.bytes(&[9; 4]);

        let mut r = Reader::new(&buf, "test", 0);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 2);
        assert_eq!(r.u32().unwrap(), 3);
        assert_eq!(r.u64().unwrap(), 4);
        assert_eq!(r.u128().unwrap(), 5);
        assert_eq!(r.i64().unwrap(), -6);
        assert_eq!(r.str16().unwrap(), "seven");
        assert_eq!(r.bytes32().unwrap(), b"eight");
        assert_eq!(r.bytes16().unwrap(), b"nine");
        assert_eq!(r.fixed::<4>().unwrap(), [9; 4]);
        r.finish().unwrap();
    }

    #[test]
    fn test_reader_short_input_is_corrupt() {
        let mut r = Reader::new(&[1, 2], "short", 9);
        assert!(matches!(
            r.u32(),
            Err(Error::Corrupt {
                what: "short",
                at: 9
            })
        ));
    }

    #[test]
    fn test_reader_length_past_end_is_corrupt() {
        let mut buf = Vec::new();
        Writer::new(&mut buf).u32(u32::MAX);
        let mut r = Reader::new(&buf, "len", 0);
        assert!(r.bytes32().is_err());
    }

    #[test]
    fn test_reader_invalid_utf8_is_corrupt() {
        let buf = [2u8, 0, 0xff, 0xfe];
        assert!(Reader::new(&buf, "utf8", 0).str16().is_err());
    }

    #[test]
    fn test_finish_trailing_bytes_is_corrupt() {
        let buf = [1u8, 2];
        let mut r = Reader::new(&buf, "trail", 0);
        let _ = r.u8().unwrap();
        assert!(r.finish().is_err());
    }

    #[test]
    fn test_patch_u32_overwrites_in_place() {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf);
        let at = w.position();
        w.u32(0);
        w.patch_u32(at, 0xdead_beef).unwrap();
        assert_eq!(buf, 0xdead_beef_u32.to_le_bytes());
    }
}
