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
written by [wal-db](https://github.com/jamesgober/wal-db) 1.1. wal-db frames
each record with its length and a CRC32C checksum. On open it cuts an
unfinished record at the end of the log (a write the crash interrupted, which
never returned `Ok`). nex-db opens the log under wal-db's strict policy, so
damage anywhere before that point refuses the open and changes nothing.

nex-db writes each record with one append followed by a sync, and returns
from `commit` only after the sync. The largest record is 16 MiB; nex-db
refuses a larger commit before writing it, and the same limit bounds what
recovery reads. The limit is part of the format: a build with a smaller limit
refuses a log holding a longer record.

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
2       1     flags       bit 0: sealed; other bits 0
3       2     format      the engine's section format
5       4     collection  the collection the section belongs to
9       4     length      length of the body
13      ...   body
```

- **collection** must be a collection the catalog binds to **engine**. A
  section for any other collection keeps the database closed.
- **format** is the engine's own format number for the body. An engine reads
  every format it has ever written.
- **flags** bit 0 marks a sealed section: a body encrypted by its engine,
  so the rest of the database moves the bytes without being able to read
  them. Other bits are reserved and must be 0. Auth sections are sealed from
  0.3; no other engine seals.

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

### Auth (engine 1)

Format 2 (written from 0.3) is sealed: the section's flags have bit 0 set and
its body is

```text
key id u32          1: XChaCha20-Poly1305 under the log seal key
nonce [24]          random
ciphertext          the padded plaintext, encrypted
tag [16]
```

with associated data `seq u64 | engine u16 | collection u32 | format u16`, so
a body copied to another commit, engine, or collection fails to open. The
plaintext is `length u32 | operations | zeros`, padded to a multiple of 256
bytes, so a section of any single operation has the same size. Non-zero
padding, a wrong key id, or a failed tag keeps the database closed. The log
seal key is `keyed BLAKE3(root key, "nex-db 2026 auth log seal")`.

Format 1 (0.1 and 0.2) is the same operations in plain form, with the flags
0. It is still read, never written.

The operations:

| Code | Operation | Fields |
|---|---|---|
| 1 | create account | `account [16]`, `identifier digest [32]`, `created ms u64`, `password hash str16` |
| 2 | issue session | `token digest [32]`, `account [16]`, `created ms u64`, `expires ms u64` |
| 3 | revoke session | `token digest [32]`, `reason u8` (1 = revoked, 2 = rotated), `at ms u64` |
| 4 | create account (sealed record) | `account [16]`, `identifier digest [32]`, `record bytes32` |
| 5 | issue session at an epoch | `token digest [32]`, `account [16]`, `created ms u64`, `expires ms u64`, `epoch u32` |
| 6 | raise an account's epoch | `account [16]`, `epoch u32` |
| 7 | replace an account's record | `account [16]`, `record bytes32` (sealed, as in operation 4) |

A session is valid only while its epoch equals the account's current epoch
(0 until the first raise), so operation 6 ends every older session of the
account at once. An epoch never goes down. Operations 1 and 2 appear only in
format 1 logs; operation 2 is read as epoch 0.

From 0.3 a new account is
operation 4: its record, the password hash included, is sealed under the file
key before it enters the section, so the store holds exactly the bytes the log
carries; see [FILE_FORMATS.md](./FILE_FORMATS.md#account-store-authaccounts).

Times are milliseconds since the Unix epoch, chosen when the operation was
staged, so a replay reaches the same state. Digests are keyed BLAKE3 values;
the token itself and the identifier itself never appear. The password hash is
an Argon2id string in the PHC format.

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
5. every section's collection is bound to its engine, and its `flags` hold
   no bit other than sealed.

A failure of any of these keeps the database closed with `Error::Corrupt`,
with one exception: a failed checksum (1) on the last record, with no intact
record after it, is an interrupted write, and wal-db cuts it. A missing
segment, or a record above the 16 MiB limit, also keeps the database closed.
As a second check, nex-db refuses to open when an engine's files hold a commit
the log does not have.
