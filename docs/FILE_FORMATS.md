<h1 align="center">
        <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>nex-db</b><br>
    <sub><sup>FILE FORMATS</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./README.md" title="Documentation"><b>DOCS</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./API.md" title="API"><b>API</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./LOG_FORMAT.md" title="Log format"><b>LOG FORMAT</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>FILE FORMATS</span>
    </sup>
</div>
<br>

What a database directory holds, and the bytes of each file nex-db writes
itself. The commit log has its own document, [LOG_FORMAT.md](./LOG_FORMAT.md).

**Status:** draft, with the same rules as the log format: formats may change
before 1.0 behind a format number, and are frozen for the 1.x line from 1.0.

All integers are little endian unless a field says big endian. Strings are
`str16` (a `u16` length, then UTF-8) and byte strings `bytes32` (a `u32`
length, then the bytes).

## The directory

```text
<database>/
├─ LOCK                  ownership of the directory
├─ core/
│   ├─ log/              the commit log (wal-db segments)
│   └─ catalog.ckpt      the catalog
├─ auth/
│   ├─ keys              the root key (default key source only)
│   ├─ key.check         a check of the root key
│   └─ accounts/         the account store (lsm-db)
└─ content/
    └─ store/            the content store (lsm-db)
```

Later versions add `auth/hot/` (session checkpoints), `auth/audit/` (the
audit chain), `auth/revocations/` (revocations kept across restores),
`content/routes/` and `content/search/` (rebuildable indexes). A file that
can be rebuilt from the log is rebuilt when it is missing or fails its check;
every other file that fails its check keeps the database closed.

Every file nex-db writes whole (`catalog.ckpt`, `keys`) is written to a
temporary file, synced, and renamed over the old one, so a crash leaves the
old file or the new one, never a mix.

## LOCK

Holds the owning process id as decimal text. It is a marker, not the lock
itself: the lock is the operating system's lock on the open file, released
when the process ends however it ends. With Rust 1.89 or later nex-db uses
the standard file lock; with older compilers it opens the file without
sharing on Windows, and on Unix treats the file as held while the process it
names is alive.

## core/catalog.ckpt

The whole catalog, rewritten after each change.

```text
format u16                2
through u64               the sequence number of the last catalog change it holds
count u32
count times:
    id u32
    engine u16
    name str16
    definition bytes32
checksum [32]             BLAKE3 of every byte before it
```

A checkpoint whose checksum fails, or whose format is unknown, keeps the
database closed. A checkpoint with an empty log means the log was lost and
also keeps it closed.

## auth/keys

The root key from which the auth engine derives its keys, when the database
uses the default key source (`Keys::in_directory()`). With `Keys::file(path)`
the same file lives at `path`, outside the directory; with `Keys::env(var)`
the key is 64 hexadecimal characters in an environment variable and no file
holds it.

```text
format u16       1
key [32]         random
checksum [32]    BLAKE3 of format and key
```

Created once, with the database. A database whose key file is missing or
damaged stays closed (`Error::KeyUnavailable`): a new key would make every
stored digest and sealed record useless. On Unix the file is readable by its
owner only.

## auth/key.check

`keyed BLAKE3(root key, "nex-db 2026 root key check")`, 32 bytes, written
with the database (or at the first open of a 0.1 or 0.2 database). Opening
with a root key whose check differs fails with `Error::KeyUnavailable` before
anything is decrypted. It reveals nothing about the key.

Derived keys are `keyed BLAKE3(root key, label)`:

| Label | Use |
|---|---|
| `nex-db 2026 auth token digest` | session token digests |
| `nex-db 2026 auth identifier digest` | identifier digests |
| `nex-db 2026 auth log seal` | sealed auth sections in the log (0.3) |
| `nex-db 2026 auth file` | sealed account records (0.3) |

## The engine stores

The account store and the content store are
[lsm-db](https://github.com/jamesgober/lsm-db) 1.1 databases with lsm-db's own
log turned off: the commit log already holds every change. Each commit's
changes reach a store as one batch that also writes the store's mark:

| Key | Value |
|---|---|
| `\0meta/applied` | `u64`: the last commit sequence number the store holds |

On open, recovery replays the commit log from the lowest mark of all engines;
a store skips the commits it already holds. A store whose mark is above the
end of the log means the log lost records, and the database stays closed.

Keys start with the collection id (`u32`, **big endian**, so a collection's
keys sort together), then a one-byte tag.

### Account store (`auth/accounts/`)

| Key | Value |
|---|---|
| `collection, 'a', account [16]` | account record, sealed (from 0.3) or plain |
| `collection, 'i', identifier digest [32]` | `account [16]` |
| `collection, 'c', account [16]` | credential record, plain accounts only |

A sealed account record (written from 0.3) is

```text
marker u8                 2
key id u32                1: XChaCha20-Poly1305 under the file key
nonce [24]
ciphertext
tag [16]
```

with the store key as associated data, so a record copied to another key
fails to open. The file key is `keyed BLAKE3(root key, "nex-db 2026 auth
file")`. Inside, the credential travels with the account:

```text
format u8                 2
created ms u64
identifier digest [32]
standing u8               1 active, 2 pending verification, 3 locked out,
                          4 suspended, 5 banned
until ms u64              when a lock-out or suspension ends; 0 for none
reason u32                application-defined; 0 for none
credential kind u8        1 = password
password hash str16       Argon2id, PHC format
```

A standing change writes the whole record again, sealed with a new nonce.
Account epochs are not in the record: they live in the log.

Records are sealed when the commit is staged, not when it is applied, and the
sealed bytes travel inside the sealed log section; applying a commit stores
them as they are, so every replay writes the same bytes.

Accounts created by 0.1 and 0.2 keep their plain records, still read:

```text
account record            format u8 (1), created ms u64, identifier digest [32],
                          standing u8, epoch u32
credential record         kind u8 (1 = password), password hash str16
```

Sessions are not stored here: in this version they live in memory and are
rebuilt from the commit log at open.

### Content store (`content/store/`)

| Key | Value |
|---|---|
| `collection, 'e', rid [16]` | entity record |

Routes are not stored: they are rebuilt from the entity records at open.

### Entity record

```text
format u8                 1
rid [16]
created ms u64
revision u32
type str16
site str16
path str16                empty when the entity has no route
field count u16
field count times:
    name str16
    tag u8
    value                 by tag:
        1 text            bytes32, UTF-8
        2 int             i64
        3 bool            u8, 0 or 1
        4 account         [16]
        5 entity          [16]
```

## Ids

`AccountId` and `Rid` are 16-byte ULIDs, stored as their bytes and shown as
26 characters of Crockford base32. Ids are never reused.

## Tokens

A session token is 36 bytes, shown as 48 characters of URL-safe base64
without padding:

```text
version u8          1
routing [3]         0 in this version; never trusted
random [32]         from the operating system
```

The database stores only `keyed BLAKE3(token digest key, random)`.
