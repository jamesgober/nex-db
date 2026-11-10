//! The commit log record.
//!
//! wal-db frames every record with a length and a CRC32C. Inside that frame a
//! nex-db record is a header followed by one section per collection the
//! commit touched (an engine has one section per collection of it):
//!
//! ```text
//! header   format u16 | seq u64 | kind u8 | class u8 | engines u128 | sections u16
//!          | time ms u64 (format 2)
//! section  engine u16 | flags u8 | format u16 | collection u32 | length u32 | body
//! ```
//!
//! All integers are little endian. `engines` is a bit mask of the engine ids
//! in the record, so a reader can tell which engines a record touches without
//! walking its sections. The section body is defined by its engine; the core
//! never interprets it.

use super::codec::{Reader, Writer};
use crate::{
    engine::EngineId,
    error::{Error, Result},
};

/// A commit sequence number. Strictly increasing, never reused; the first
/// commit is 1, and 0 means "nothing".
pub(crate) type Seq = u64;

/// The record format this version writes: 2 adds the commit time.
pub(crate) const RECORD_FORMAT: u16 = 2;
/// The format before, without the time; read only.
const RECORD_FORMAT_1: u16 = 1;

/// Size of the record header in bytes.
#[cfg(test)]
pub(crate) const HEADER_LEN: usize = 2 + 8 + 1 + 1 + 16 + 2 + 8;

/// Size of a section header in bytes.
#[cfg(test)]
pub(crate) const SECTION_HEADER_LEN: usize = 2 + 1 + 2 + 4 + 4;

/// What a record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    /// An ordinary commit of one or more engines.
    Commit = 1,
    /// A change to the catalog (engine 0).
    Catalog = 5,
}

impl Kind {
    fn from_u8(v: u8, at: Seq) -> Result<Self> {
        match v {
            1 => Ok(Kind::Commit),
            5 => Ok(Kind::Catalog),
            _ => Err(Error::corrupt("a log record kind", at)),
        }
    }
}

/// How a record is written. In this version every class is synced before the
/// commit returns; the class is recorded so later versions can order and ship
/// records by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Class {
    /// Ordinary durable commit.
    Durable = 1,
    /// Revocations and other changes that must take effect first.
    Priority = 2,
}

impl Class {
    fn from_u8(v: u8, at: Seq) -> Result<Self> {
        match v {
            1 => Ok(Class::Durable),
            2 => Ok(Class::Priority),
            _ => Err(Error::corrupt("a log record class", at)),
        }
    }
}

/// Section flag: the body is encrypted by its engine; the rest of the
/// database moves the bytes without reading them.
pub(crate) const SEALED: u8 = 1;

/// One engine's part of a record, borrowed from the record bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Section<'a> {
    pub(crate) engine: EngineId,
    pub(crate) flags: u8,
    pub(crate) format: u16,
    pub(crate) collection: u32,
    pub(crate) body: &'a [u8],
}

/// A decoded record. Sections borrow the record bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordView<'a> {
    pub(crate) seq: Seq,
    pub(crate) kind: Kind,
    pub(crate) class: Class,
    /// When the commit was sequenced, in Unix milliseconds; 0 for a format 1
    /// record.
    pub(crate) time_ms: u64,
    pub(crate) sections: Vec<Section<'a>>,
}

/// The bit of `engine` in a record's engine mask.
fn engine_bit(engine: EngineId, at: Seq) -> Result<u128> {
    1u128
        .checked_shl(u32::from(engine.0))
        .filter(|_| engine.0 < 128)
        .ok_or_else(|| Error::corrupt("a log record engine id", at))
}

/// Builds one record: the header, then each section in turn.
pub(crate) struct RecordWriter {
    buf: Vec<u8>,
    seq: Seq,
    expected_sections: u16,
    written_sections: u16,
    /// The (engine, collection) of each section begun.
    written: Vec<(EngineId, u32)>,
    mask: u128,
    open_section: Option<usize>,
}

impl RecordWriter {
    /// Start a record of `sections` sections touching the engines in
    /// `engines`, committed at `time_ms`.
    pub(crate) fn new(
        seq: Seq,
        kind: Kind,
        class: Class,
        engines: &[EngineId],
        time_ms: u64,
        mut buf: Vec<u8>,
    ) -> Result<Self> {
        buf.clear();
        let mut mask = 0u128;
        for engine in engines {
            mask |= engine_bit(*engine, seq)?;
        }
        let sections = u16::try_from(engines.len())
            .map_err(|_| Error::invalid("record", "too many sections"))?;
        let mut w = Writer::new(&mut buf);
        w.u16(RECORD_FORMAT);
        w.u64(seq);
        w.u8(kind as u8);
        w.u8(class as u8);
        w.u128(mask);
        w.u16(sections);
        w.u64(time_ms);
        Ok(RecordWriter {
            buf,
            seq,
            expected_sections: sections,
            written_sections: 0,
            written: Vec::new(),
            mask,
            open_section: None,
        })
    }

    /// Begin a section and return the buffer its body is appended to. Call
    /// [`end_section`](Self::end_section) after writing the body.
    pub(crate) fn begin_section(
        &mut self,
        engine: EngineId,
        flags: u8,
        format: u16,
        collection: u32,
    ) -> Result<&mut Vec<u8>> {
        if self.open_section.is_some() || self.written_sections >= self.expected_sections {
            return Err(Error::invalid("record", "section out of order"));
        }
        if self.mask & engine_bit(engine, self.seq)? == 0 {
            return Err(Error::invalid("record", "section for an undeclared engine"));
        }
        if self.written.contains(&(engine, collection)) {
            return Err(Error::invalid("record", "a collection appears twice"));
        }
        self.written.push((engine, collection));
        let mut w = Writer::new(&mut self.buf);
        w.u16(engine.0);
        w.u8(flags);
        w.u16(format);
        w.u32(collection);
        let length_at = w.position();
        w.u32(0);
        self.open_section = Some(length_at);
        Ok(&mut self.buf)
    }

    /// Close the open section, filling in its length.
    pub(crate) fn end_section(&mut self) -> Result<()> {
        let length_at = self
            .open_section
            .take()
            .ok_or(Error::invalid("record", "no open section"))?;
        let body_len = self.buf.len() - (length_at + 4);
        let len =
            u32::try_from(body_len).map_err(|_| Error::invalid("record", "section too long"))?;
        Writer::new(&mut self.buf).patch_u32(length_at, len)?;
        self.written_sections += 1;
        Ok(())
    }

    /// The finished record bytes.
    pub(crate) fn finish(self) -> Result<Vec<u8>> {
        if self.open_section.is_some() || self.written_sections != self.expected_sections {
            return Err(Error::invalid("record", "sections missing"));
        }
        Ok(self.buf)
    }
}

/// Decode a record. `at` locates it in errors (its log offset).
pub(crate) fn decode(bytes: &[u8], at: u64) -> Result<RecordView<'_>> {
    let mut r = Reader::new(bytes, "a log record", at);
    let format = r.u16()?;
    if format != RECORD_FORMAT && format != RECORD_FORMAT_1 {
        return Err(Error::corrupt("a log record format", at));
    }
    let seq = r.u64()?;
    let kind = Kind::from_u8(r.u8()?, seq)?;
    let class = Class::from_u8(r.u8()?, seq)?;
    let mask = r.u128()?;
    let count = r.u16()?;
    let time_ms = if format == RECORD_FORMAT { r.u64()? } else { 0 };
    let mut seen = 0u128;
    let mut sections: Vec<Section<'_>> = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let engine = EngineId(r.u16()?);
        seen |= engine_bit(engine, seq)?;
        let flags = r.u8()?;
        let format = r.u16()?;
        let collection = r.u32()?;
        if sections
            .iter()
            .any(|s| s.engine == engine && s.collection == collection)
        {
            return Err(Error::corrupt("a log record (collection twice)", seq));
        }
        let body = r.bytes32()?;
        sections.push(Section {
            engine,
            flags,
            format,
            collection,
            body,
        });
    }
    r.finish()?;
    if seen != mask {
        return Err(Error::corrupt("a log record (engine mask)", seq));
    }
    Ok(RecordView {
        seq,
        kind,
        class,
        time_ms,
        sections,
    })
}

/// Runs this module's decoders on `data`, for fuzzing and tests. Errors are
/// expected; a panic, a hang, or an allocation the input asked for is a bug.
#[cfg(any(fuzzing, test))]
pub(crate) fn fuzz(data: &[u8]) {
    let _ = decode(data, 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut w = RecordWriter::new(
            42,
            Kind::Commit,
            Class::Durable,
            &[EngineId(1), EngineId(2)],
            7,
            Vec::new(),
        )
        .unwrap();
        w.begin_section(EngineId(1), SEALED, 1, 10)
            .unwrap()
            .extend_from_slice(b"auth");
        w.end_section().unwrap();
        w.begin_section(EngineId(2), 0, 3, 20)
            .unwrap()
            .extend_from_slice(b"content!");
        w.end_section().unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn test_decode_written_record_round_trips() {
        let bytes = sample();
        assert_eq!(
            bytes.len(),
            HEADER_LEN + 2 * SECTION_HEADER_LEN + b"auth".len() + b"content!".len()
        );
        let view = decode(&bytes, 0).unwrap();
        assert_eq!(view.seq, 42);
        assert_eq!(view.kind, Kind::Commit);
        assert_eq!(view.class, Class::Durable);
        assert_eq!(view.time_ms, 7);
        assert_eq!(view.sections.len(), 2);
        assert_eq!(view.sections[0].engine, EngineId(1));
        assert_eq!(view.sections[0].collection, 10);
        assert_eq!(view.sections[0].flags, SEALED);
        assert_eq!(view.sections[0].body, b"auth");
        assert_eq!(view.sections[1].format, 3);
        assert_eq!(view.sections[1].body, b"content!");
    }

    #[test]
    fn test_decode_every_truncation_is_corrupt() {
        let bytes = sample();
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len], 0).is_err(), "prefix of {len} bytes");
        }
    }

    #[test]
    fn test_decode_trailing_byte_is_corrupt() {
        let mut bytes = sample();
        bytes.push(0);
        assert!(decode(&bytes, 0).is_err());
    }

    #[test]
    fn test_decode_wrong_mask_is_corrupt() {
        let mut bytes = sample();
        // The mask starts after format, seq, kind and class.
        bytes[12] ^= 0b1000;
        assert!(decode(&bytes, 0).is_err());
    }

    #[test]
    fn test_decode_unknown_format_is_corrupt() {
        let mut bytes = sample();
        bytes[0] = 9;
        assert!(decode(&bytes, 0).is_err());
    }

    #[test]
    fn test_writer_undeclared_engine_is_refused() {
        let mut w = RecordWriter::new(
            1,
            Kind::Commit,
            Class::Durable,
            &[EngineId(1)],
            0,
            Vec::new(),
        )
        .unwrap();
        assert!(w.begin_section(EngineId(2), 0, 1, 0).is_err());
    }

    #[test]
    fn test_writer_missing_section_is_refused() {
        let w = RecordWriter::new(
            1,
            Kind::Commit,
            Class::Durable,
            &[EngineId(1)],
            0,
            Vec::new(),
        )
        .unwrap();
        assert!(w.finish().is_err());
    }

    #[test]
    fn test_writer_engine_id_128_is_refused() {
        assert!(
            RecordWriter::new(
                1,
                Kind::Commit,
                Class::Durable,
                &[EngineId(128)],
                0,
                Vec::new()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod format_one {
    use super::*;

    #[test]
    fn test_a_format_1_record_reads_without_a_time() {
        let mut w = RecordWriter::new(
            3,
            Kind::Commit,
            Class::Priority,
            &[EngineId(1)],
            9,
            Vec::new(),
        )
        .unwrap();
        w.begin_section(EngineId(1), 0, 1, 0)
            .unwrap()
            .extend_from_slice(b"x");
        w.end_section().unwrap();
        let mut bytes = w.finish().unwrap();
        // Format 1: the same header without the time.
        let header = 2 + 8 + 1 + 1 + 16 + 2;
        let _ = bytes.drain(header..header + 8);
        bytes[..2].copy_from_slice(&RECORD_FORMAT_1.to_le_bytes());
        let view = decode(&bytes, 0).unwrap();
        assert_eq!(
            (view.seq, view.time_ms, view.class),
            (3, 0, Class::Priority)
        );
        assert_eq!(view.sections[0].body, b"x");
    }
}
