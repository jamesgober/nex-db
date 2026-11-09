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
│   ├─ sessions.ckpt     sessions and epochs, as of the last checkpoint
│   ├─ account-keys      each account's data key (0.5)
│   ├─ audit.chain       the audit chain
│   ├─ accounts/         the account store (lsm-db)
│   └─ realms/<id>/      each further realm (0.4): its own sessions.ckpt,
│                        account-keys, audit.chain, and accounts/
└─ content/
    ├─ store/            the content store (lsm-db)
    └─ spaces/<id>/store/  each further space's store (0.4)
```

A further realm's keys derive from the root key with the label `nex-db 2026
realm root` and its collection id (big-endian `u32`). A realm's catalog
definition is its policy, empty for the defaults, else: `format u8 (1)`,
`lockout failures u32`, `lockout window ms u64`, `lockout ms u64`, `max
session ms u64`, `max idle ms u64` (0 for none), `pending verification u8`. A
space's definition is the settings it starts with, encoded as the `'m'`
record below, or empty.

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
| `nex-db 2026 auth single-use token digest` | single-use token digests (0.4), held in the session table with a 4-byte payload: `S`, the purpose, and a custom code |
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
a store skips the commits it already holds. A checkpoint writes `upto` (every
commit visible when it started) as the mark, flushes the store, and syncs its
directory, so a store no recent commit touched does not hold the log back. A store whose mark is above the
end of the log means the log lost records, and the database stays closed.

Keys start with the collection id (`u32`, **big endian**, so a collection's
keys sort together), then a one-byte tag.

### Account store (`auth/accounts/`)

| Key | Value |
|---|---|
| `collection, 'a', account [16]` | account record, sealed (from 0.3) or plain |
| `collection, 'i', identifier digest [32]` | `account [16]` |
| `collection, 'c', account [16]` | credential record, plain accounts only |
| `collection, 'k', key digest [32]` | an API key record (0.4), sealed as an account record is: `format u8 (1)`, `account [16]`, `id [16]`, `created ms u64`, `expires ms u64` (0 never), `revoked ms u64` (0 live), `scope count u8`, `scope str16` each |
| `collection, 'K', key id [16]` | the key's digest [32] |
| `collection, 'r', account [16]` | the account's unused recovery codes (0.4), sealed: `format u8 (1)`, `count u8`, `digest [32]` each |
| `collection, 'w', credential digest [32]` | a passkey (0.5), sealed: `format u8 (1)`, `account [16]`, `sign count u32`, `created ms u64`, `last used ms u64`, then the COSE public key; the digest is keyed BLAKE3 (label `nex-db 2026 auth passkey credential digest`) of the credential id |
| `collection, 'W', account [16], credential digest [32]` | empty: the account's passkeys, read by a prefix scan |
| `collection, 't', account [16]` | the account's TOTP record (0.5), sealed: `format u8 (1)`, `confirmed u8`, `last step u64` (the step of the last code accepted), `secret [20]` |
| `collection, 'p'` | the realm's roles (0.4), plain: `format u8 (1)`, `role count u16`, then per role `name str16`, `permission count u16`, `permission str16` each, `inherited count u16`, `role id u32` each. A role's id is its position |

A sealed account record (written from 0.3) is

```text
marker u8                 2
key id u32                1: XChaCha20-Poly1305 under the file key
nonce [24]
ciphertext
tag [16]
```

with the store key as associated data, so a record copied to another key
fails to open. From 0.5 an account's private records (the account record,
its TOTP record, and its recovery codes) are sealed with key id 2, the
account's data key from `auth/account-keys`, made when the account is
created; a record written before 0.5 stays under key id 1 until the account
next changes. The file key is `keyed BLAKE3(root key, "nex-db 2026 auth
file")`. Inside, the credential travels with the account:

```text
format u8                 3 (2 in 0.3: ends after the password hash)
created ms u64
identifier digest [32]    the first identifier
standing u8               1 active, 2 pending verification, 3 locked out,
                          4 suspended, 5 banned
until ms u64              when a lock-out or suspension ends; 0 for none
reason u32                application-defined; 0 for none
credential kind u8        1 = password
password hash str16       Argon2id, PHC format
identifier count u8       further identifiers (at most 4), then each [32]
role count u8             at most 16, then each role id u32
```

A change of standing, password, identifiers, or roles writes the whole record
again, sealed with a new nonce.
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

Sessions are not stored here; see [auth/sessions.ckpt](#authsessionsckpt).

## auth/account-keys

Each account's data key (0.5), in fixed slots that are overwritten in place:

```text
header    "NXDBKEYS" [8], format u16 (1), slot size u16 (96), [4] zero
slot      account [16], created ms u64, nonce [24], key [32], tag [16]
```

An all-zero slot is free. The 32-byte key is random, sealed with
XChaCha20-Poly1305 under the file key with the account id as associated
data. A key is written and synced while the commit that first uses it is
staged, before that commit reaches the log; it never travels in the log.
Erasing an account overwrites its slot with zeros and syncs. A key whose
account was never created (its commit did not land) is dropped at a
checkpoint a minute or more later.

## auth/sessions.ckpt

Sessions and account epochs live in memory. A checkpoint writes them here,
whole, with the sequence number they hold through; at open they are loaded
and the log after that number is replayed.

```text
format u16                1
through u64               the checkpoint holds every commit up to this one
sealed bytes32            as a sealed account record (marker, key id, nonce,
                          ciphertext, tag) under the file key, with
                          "sessions.ckpt" and `through` as associated data
```

The plaintext:

```text
audit chain tail          file length u64, next record id u64, last hash [32],
                          last time ns u64 (see auth/audit.chain)
epoch count u32
epoch count times:        account [16], epoch u32
slot count u32
slot count times:         token digest [32], kind u8, then by kind:
    1 live session        account [16], created ms u64, expires ms u64, epoch u32,
                          idle ms u64, recheck ms u64, payload bytes16,
                          last used ms u64
    2 revoked             kept until ms u64, reason u8 (1 revoked, 2 rotated,
                          3 signed out everywhere)
```

Each checkpoint first drops sessions that have expired and tombstones whose
session would have expired (a tombstone of a session whose expiry is unknown
is kept a day), so the table stays bounded.

## auth/audit.chain

The realm's audit chain, in the [audit-trail](https://github.com/jamesgober/audit-trail)
file format: a 16-byte header, then one length-prefixed record per security
write (account created, session issued, revoked, or rotated, signed out
everywhere, standing changed). Each record's hash covers the previous one's,
with keyed BLAKE3 under `keyed BLAKE3(root key, "nex-db 2026 auth audit")`.
The actor of a record is `commit <seq>.<n>`, the n-th operation of commit
`seq`; its time is the one the operation carries.

Records are appended as commits apply and synced by each checkpoint, which
stores the chain's tail. At open the file is cut back to that length and
replay appends the rest again, the same bytes. A file shorter than its
checkpoint keeps the database closed. A damaged file keeps the database
closed: the log below its mark may be gone, so nothing else holds those
sessions.

### Content store (`content/store/`)

| Key | Value |
|---|---|
| `collection, 'e', rid [16]` | entity head (format 6; format 5 from 0.4 and formats 2 to 4 from builds before 0.4.0 still read), or a 0.1 to 0.3 entity record (format 1) |
| `collection, 'v', rid [16], number u32 (big-endian)` | a fixed revision |
| `collection, 'r', site, 0, path` | a route |
| `collection, 'b', target rid [16], source rid [16]` | empty: `source` refers to `target` (a draft or published field); `referenced_by` reads the target's prefix |
| `collection, 'm'` | the space's settings: `format u8 (1)`, `default locale`, `chain count u8`, then per chain `locale`, `count u8`, and that many `locale` |

| `collection, 't'` | the space's types: `format u8 (3)`, `type count u16`, then per type `name str16`, `singleton u8`, `field count u16`, per field `name str16`, `kind u8` (1 text, 2 int, 3 bool, 4 account, 5 entity, 6 list, 7 terms), `flags u8` (bit 0 unique; bits 1 and 2 the reference rule of an entity or terms field: 0 none, 1 restrict, 2 detach, 3 cascade), then `taxonomy count u16` and per terms field `name str16`, `taxonomy str16`, then `searchable count u16` and per searchable field `name str16`, `weight u8` (1 to 10). Format 1 has no taxonomies; formats 1 and 2 have no searchable fields |

A locale is stored as `length u8` and its ASCII tag (at most 15 bytes).

The route index is rebuilt at open from the route records, and from the
paths of format 1 entity records, which have none. Reference records of
format 1 and format 2 heads, which have none, are written at open from the
heads (format 2 published references taken from the drafts).

### Entity head (format 6)

```text
format u8                 6
rid [16]
created ms u64
updated ms u64
type str16
site str16
status u8                 1 draft, 2 review, 3 published, 4 archived, 5 trashed
visibility u8             1 public, 2 members, 3 private
last revision u32         the newest of any locale; 0 before the first
first published ms u64    0 when never published
locale count u8           at least 1; the first is the entity's own locale
locale count times:
    locale
    source revision u32   for a translation, the revision it was made from
    published revision u32  0 when this locale is not published
    published ms u64
    published path str16  empty for none
    published refs u16    entities the published body refers to, then
                          each rid [16], sorted (format 2: absent)
    draft path str16      empty for none
    draft fields          as in the entity record below
    schedule u8           0 none, 1 publish, 2 unpublish; then at ms u64
                          (format 4: absent)
gone count u16            paths left gone (410) by a trash, then each:
    locale
    path str16
author count u8           at most 16, then each account [16], in order
has parent u8             1, then parent rid [16]; 0 for none
order i64                 its place among its parent's children
flags u8                  bit 0: sticky; the other bits 0 (format 5: absent)
```

Format 3 ends after the gone paths (no authors, no parent, order 0).

A format 1 record reads as an entity in `en`. When one is first rewritten,
its body is stored as the revision its head points at.

### Revision

```text
format u8                 1
locale
at ms u64
message str16             at most 1,024 bytes
path str16                empty for none
fields                    as in the entity record below
```

### Route

```text
format u8                 1
kind u8                   1 page, 2 redirect, 3 gone
status u16                the redirect's HTTP status; 0 otherwise
target [16]               the entity a redirect points at
entity [16]
revision u32
visibility u8             as in the head
locale                    the locale the path serves
```

### Entity record (format 1, 0.1 to 0.3)

Read as an entity published at revision 1 whose draft is the same.

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
        6 list            count u16 (at most 1,000), then each value
                          as tag and value, none a list (0.4)
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
