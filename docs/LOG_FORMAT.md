<h1 align="center">
        <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>nex-db</b><br>
    <sub><sup>LOG FORMAT</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./README.md" title="Documentation"><b>DOCS</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>LOG FORMAT</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="./FILE_FORMATS.md" title="File formats"><b>FILE FORMATS</b></a>
    </sup>
</div>
<br>

The commit log holds every commit, in order. It is the database's source of
truth: every engine's files can be rebuilt from it, and opening a database
replays it. This document describes the bytes of a log record.

**Status:** draft. The format may change before 1.0; every change raises a
format number, and a database written in a format this build does not read
refuses to open. From 1.0 the format is frozen for the 1.x line: later 1.x
versions read every 1.0 log.

All integers are little endian. Lengths are in bytes.

## Framing

The log lives in `core/log/` as a series of segment files of at most 16 MiB,
written by [wal-db](https://github.com/jamesgober/wal-db) 1.0. wal-db frames
each record with its length and a CRC32C checksum. On open it cuts an
unfinished record at the end of the log (a write the crash interrupted, which
never returned `Ok`).

nex-db writes each record with one append followed by a sync, and returns
from `commit` only after the sync. The largest record is 16 MiB; nex-db
refuses a larger commit before writing it, and the same limit bounds what
recovery reads. The limit is part of the format: a build with a smaller limit
would read a longer record as damage.

## Record

```text
offset  size  field
0       2     format     record format, 1
2       8     seq        commit sequence number
10      1     kind       what the record is
11      1     class      how it was written
12      16    engines    bit mask of the engine ids that have a section
28      2     sections   number of sections
30      ...   sections, one after another
```

- **seq** starts at 1 and rises by exactly 1 per record. Recovery refuses a
  log whose sequence numbers skip or repeat.
- **engines** has bit `n` set when the record holds a section of engine `n`.
  It lets a reader see which engines a record touches without reading the
  sections, and it must match the sections exactly. Engine ids above 127 do
  not exist.
- A record holds at most one section per engine.
- No bytes follow the last section.

### Kinds

| Value | Kind | Since | Holds |
|---|---|---|---|
| 1 | Commit | 0.1 | one transaction: a section per engine it touched |
| 2 | Prepared | 0.5 | one participant's part of a commit across processes |
| 3 | Decision | 0.5 | the outcome of a commit across processes |
| 4 | SoftBatch | 0.3 | coalesced low-priority updates (session last-seen times, counters) |
| 5 | Catalog | 0.1 | a catalog change; its only section is engine 0's |
| 6 | CheckpointMarker | 0.3 | the engines' durable marks at a point in the log |

A Catalog record holds only an engine 0 section, and engine 0 appears in no
other kind. An unknown kind keeps the database closed.

### Classes

| Value | Class | Meaning |
|---|---|---|
| 1 | Durable | an ordinary commit, synced before it returns |
| 2 | Priority | a change that must take effect first (a revocation); synced before it returns, and from 0.8 sent to replicas ahead of ordinary records |
| 3 | Soft (0.3) | written in batches; a crash may lose the last batch |

A record is Priority when any of its sections asks for it.

## Section

```text
offset  size  field
0       2     engine      engine id
2       1     flags       must be 0 in format 1
3       2     format      the engine's section format
5       4     collection  the collection the section belongs to
9       4     length      length of the body
13      ...   body
```

- **collection** must be a collection the catalog binds to **engine**. A
  section for any other collection keeps the database closed.
- **format** is the engine's own format number for the body. An engine reads
  every format it has ever written.
- **flags** bit 0 will mark a sealed section (0.3): an auth section whose
  body is encrypted with the auth engine's keys, so the rest of the database
  moves its bytes without being able to read them. Other bits are reserved.

### Engine ids

| Id | Engine |
|---|---|
| 0 | the catalog |
| 1 | auth |
| 2 | content |
| 3, 4, 5 | reserved: log, blob, hot engines |
| 6 to 63 | reserved for later engines |
| 64 to 127 | reserved |

## Section bodies

Strings are a `u16` length followed by UTF-8 bytes (`str16`). Byte strings
are a `u32` length followed by the bytes (`bytes32`). A body is a sequence of
operations, each starting with a one-byte operation code, until the body
ends.

### Catalog (engine 0), format 2

| Code | Operation | Fields |
|---|---|---|
| 1 | define | `id u32`, `engine u16`, `name str16`, `definition bytes32` |

A define of an existing collection must repeat its id, engine, and definition
exactly; anything else is refused. The definition (at most 64 KiB) belongs to
the engine; the auth and content engines accept only an empty one in this
version. Format 1 (without the definition) was never released.

The first record of a new database is a Catalog record that defines the
realm `users` (id 1, auth) and the space `site` (id 2, content).

### Auth (engine 1), format 1

| Code | Operation | Fields |
|---|---|---|
| 1 | create account | `account [16]`, `identifier digest [32]`, `created ms u64`, `password hash str16` |
| 2 | issue session | `token digest [32]`, `account [16]`, `created ms u64`, `expires ms u64` |
| 3 | revoke session | `token digest [32]`, `reason u8` (1 = revoked), `at ms u64` |

Times are milliseconds since the Unix epoch, chosen when the operation was
staged, so a replay reaches the same state. Digests are keyed BLAKE3 values;
the token itself and the identifier itself never appear. The password hash is
an Argon2id string in the PHC format.

From 0.3 auth sections are sealed and padded, and this table describes the
plaintext inside.

### Content (engine 2), format 1

| Code | Operation | Fields |
|---|---|---|
| 1 | create entity | `entity record bytes32` |

The entity record is the one stored in the content store; see
[FILE_FORMATS.md](./FILE_FORMATS.md#entity-record).

## Reading a log

A record is accepted only when:

1. wal-db's checksum matches;
2. `format` is known, `kind` and `class` are known;
3. the sections parse exactly to the end of the record and their engines
   match the mask;
4. `seq` is one more than the previous record's;
5. every section's collection is bound to its engine, and its `flags` are 0.

A failure of 2 to 5 keeps the database closed with `Error::Corrupt`. wal-db
1.0 handles a failed checksum (1) by cutting the log there, which is right
for an interrupted last write but loses the records after damage in the
middle of the log. nex-db then refuses to open when an engine's files hold a
commit the shortened log no longer has; a stricter open in wal-db is
requested so that every such case is refused.
