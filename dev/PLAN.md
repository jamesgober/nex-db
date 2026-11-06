# nex-db - Plan

> Scope, requirements, and decisions. The detailed architecture and performance design are kept in a private design document; this file holds what a contributor needs to build to the plan. Read with [`DIRECTIVES.md`](./DIRECTIVES.md) and [`ROADMAP.md`](./ROADMAP.md).

---

## 1. What it is

- An embedded database for Rust, opened inside the application's process.
- Engines run side by side on one core. Each collection belongs to one engine, chosen when the collection is created; a collection never changes engine.
- One core for every engine: one commit log, one catalog, one read snapshot. A commit that touches several engines is atomic.
- One client API of typed operations. No SQL and no query strings. A query language, if one is added later, compiles onto the same typed operations, can never do more than the API, and never reaches auth data.
- The auth engine is sealed: its own keys, its own files, typed operations only, and it can run in its own process from the same binary.
- Embedded first. Server mode, replication, sharding, and multi-region deployment come later, on seams that exist from the first version.

## 2. What it is not

| Not | Instead |
|---|---|
| a SQL database | typed operations |
| a wrapper over several databases | one log and one commit for every engine |
| a graph or vector database | out of scope; the engine contract leaves room |
| a multi-process embedded database | one process owns a database directory; other processes use server mode (later) |

## 3. Engines

Engines are grouped by data shape so their number stays small.

| Engine | Shape | Holds | Ships |
|---|---|---|---|
| auth | sealed: a hot key table with expiry, records, and an audit chain under its own keys | accounts, credentials, sessions, tokens, API keys, roles | 1.0 |
| content | records and documents with declared fields, revisions, locales | pages, posts, profiles, terms, media metadata | 1.0 |
| log | ordered streams | comments, notification inboxes, messages, activity | after 1.0 |
| blob | chunked, content-addressed bytes with range reads | media bytes | after 1.0 |
| hot | a hot key table with expiry and counters | presence, rate counters | after 1.0 |

Derived structures (route index, listings, reverse index, search, counters) are kept by each engine in the same commit as its data and can be rebuilt from the log.

## 4. Requirements

### 4.1 Functional

| Id | Requirement | Version |
|---|---|---|
| FR-1 | open and create a database directory; one owning process (lock file) | 0.1 |
| FR-2 | one commit log; every commit carries a sequence number and one section per engine it touches | 0.1 |
| FR-3 | atomic commits across engines through `db.commit(\|tx\| ..)` | 0.1 |
| FR-4 | crash recovery: every acknowledged commit survives a kill at any point; nothing unacknowledged appears | 0.1 |
| FR-5 | a catalog of collections, each bound to one engine | 0.1 |
| FR-6 | consistent read snapshots across engines (`db.read`) | 0.3 |
| FR-7 | auth: sessions (issue, validate, rotate, revoke, revoke all), accounts, identifiers, password hashing and verification inside the engine, standing with time limits, counters and lockout, audit chain | 0.3 |
| FR-8 | auth: MFA factors, API keys, single-use tokens, external identities, roles and policy | 0.4 |
| FR-9 | content: types with declared fields, revisions with a publish pointer, statuses, scheduled publishing, locales with fallback chains and per-locale paths | 0.4 |
| FR-10 | content: route index with redirects on slug change; typed references with a reverse index; listings; change feed | 0.4 |
| FR-11 | auth in its own process (split mode) | 0.5 |
| FR-12 | per-account data keys and erasure by key destruction | 0.5 |
| FR-13 | per-locale search | 0.5 |
| FR-14 | backup and point-in-time restore; revocations are never undone by a restore | 0.5 |
| FR-15 | a read replica that follows the log | 0.8 |

### 4.2 Non-functional

| Id | Requirement |
|---|---|
| NFR-1 | zero third-party runtime dependencies; cryptography only through crypt-io |
| NFR-2 | `#![forbid(unsafe_code)]` |
| NFR-3 | no allocation on read hits, proved with a counting allocator |
| NFR-4 | lock-free reads on hot paths |
| NFR-5 | every limit configurable with a safe default; every queue bounded; overload refused with an error, never queued without limit |
| NFR-6 | Linux, macOS, and Windows on x86_64 and aarch64, stable and MSRV 1.85 |
| NFR-7 | every hot path has a criterion benchmark with a baseline; a regression over 5% blocks the change |
| NFR-8 | log, catalog, and file formats versioned; frozen for 1.x at 1.0 |

### 4.3 Enterprise and distributed

nex-db is stateful. State lives behind the engine contract and storage traits; nothing assumes a single process for good; clock skew is tolerated (sequence order never depends on wall clocks); commits can carry an idempotency key; behaviour under partition is defined (each machine keeps protecting itself, revocations apply on arrival); multi-machine simulation tests run before 1.0; observer hooks cost nothing when unused; error codes are stable.

## 5. Building blocks

First-party crates by published version only, never by path: wal-db, lsm-db, txn-db, index-db, page-db, lock-db, bloom-lib, crypt-io, key-vault, audit-trail, store-io, id-forge, clock-lib; later raft-io, wire-codec, net-io, serve-net, tls-net. Third-party dependencies inside those crates are being removed upstream before 1.0 (OD-5).

## 6. API shape

```text
let db = nex_db::open("data/site")?;
let check = db.auth().validate(&token)?;                 // Valid | Expired | Revoked | Unknown | Malformed
let route = db.content().resolve("example.com", "/blog/hello")?;
let password = db.auth().hash_password(&form_password)?;
let account = db.commit(|tx| {
    let account = tx.auth().create_account(&email, &password)?;
    tx.content().create(Entity::new("profile").field("account", account).path(&profile_path))?;
    Ok(account)
})?;
```

Tier 1 (above) covers the common uses with no builder; Tier 2 adds a builder, type definitions, listings, and pinned reads; Tier 3 is the change feed, observers, and backups. The engine contract is internal (D-030). `docs/API.md` holds the full API.

## 7. Security requirements

- No query surface over auth data; no list, scan, or export of credentials, session digests, or identifiers.
- Tokens and keys stored only as keyed digests; passwords as Argon2id, verified inside the auth engine.
- Auth files, auth log sections, and backups encrypted under auth keys that the rest of the database never holds.
- Revocation is never undone: not by an old snapshot, not by a lagging replica, not by a restore.
- Fail closed: a missing key or a corrupt log keeps the database closed.
- Every threat in the private threat list has an attack test that must fail to get through; every measure states its cost.

## 8. Open decisions

| Id | Question | Recommendation |
|---|---|---|
| OD-1 | when the crate is published | decide at 0.8. The repository itself went public on 2026-11-02 (D-042); `publish = false` stays until James decides |
| OD-2 | password verification inside the auth engine (changes the application's identity store trait) | yes |
| OD-3 | nex-db as the store for James's site and the first deployment | yes |
| OD-4 | 1.0 scope and the order of work after 1.0 | 1.0: auth, content, split auth, read replica; then log, blob, hot engines, then server and distribution |
| OD-5 | upstream releases removing third-party runtime dependencies from the building blocks | yes, before 1.0 |
| OD-6 | when to start a query language | after 1.0, read-oriented first |
| OD-7 | hosted multi-tenant mode | design ready; build only if wanted |
| OD-8 | search languages with stemming at 1.0 | English plus the site's languages |
| OD-9 | standalone crates for the timer wheel, fixed-key table, perfect hash and trie, text index, local channel | yes; James names them |
| OD-10 | pointer notes in the two input plans | yes |

## 9. Decision log

| Id | Decision |
|---|---|
| D-001 | One package, `nex-db`; engines are internal modules behind features |
| D-002 | Edition 2024, MSRV 1.85 (the db-collection baseline) |
| D-003 | `#![forbid(unsafe_code)]`; any `unsafe` needed (shared-memory channel) lives in a separate crate's `sys` module |
| D-004 | Zero third-party runtime dependencies; first-party crates by published version only |
| D-005 | No async runtime |
| D-006 | No SQL; typed operations are the whole surface |
| D-007 | `publish = false` until OD-1 is decided |
| D-008 | Architecture and performance design live in the private design document; public files stay plain |
| D-009 | (0.1) The commit log is one wal-db log of 16 MiB segments; a record is at most 16 MiB. Each record has a header (format, seq, kind, class, engine mask, section count) and one section per engine (engine, flags, format, collection, length, body), all fixed-width little endian and hand-written |
| D-010 | (0.1) The commit pipeline runs under one commit lock: validate, assign seq, encode, append and sync, record the written keys, apply each section from the encoded bytes, publish the visible seq. Group commit and the bounded queue arrive in 0.3; the class byte (durable, priority) is written now |
| D-011 | (0.1) A failed log write, sync, or apply stops every later commit; it is never retried. Reads continue; a restart recovers |
| D-012 | (0.1) Snapshot isolation through a conflict table per engine (latest commit seq per written key), pruned below the oldest running transaction; a conflicting closure runs again, four attempts in all, then `Error::Conflict` |
| D-013 | (0.1) Reads in 0.1 read the latest applied state of one engine. Consistent reads across engines at one snapshot (`db.read`, FR-6) arrive in 0.3 |
| D-014 | (0.1) The catalog is engine 0. Each change rewrites `core/catalog.ckpt` atomically with a BLAKE3 checksum. A new database defines the default realm `users` (auth) and the default space `site` (content) in its first record |
| D-015 | (0.1) Recovery replays every record in order, checks that sequence numbers have no gap, and lets each engine skip what its store holds. It refuses to open when a store holds a commit past the end of the log |
| D-016 | (0.1) Engine stores are lsm-db with its own write-ahead log off; each commit's changes go in as one batch with an applied-through mark |
| D-017 | (0.1) Auth sessions live in a standard map behind the hot-table seam, in memory only, rebuilt from the log at open (so auth replays the whole log in 0.1). Replaced in 0.3 |
| D-018 | (0.1) Session token: version byte, 3-byte routing prefix (zero), 32 random bytes; 48 characters of URL-safe base64 without padding. Stored as keyed BLAKE3 of the random part |
| D-019 | (0.1) A new database gets a random 32-byte root key in `auth/keys` (checksummed, owner-only on Unix). Token and identifier keys are keyed BLAKE3 of the root with fixed labels. A missing or damaged key file keeps an existing database closed. Replaced by key-vault in 0.3 |
| D-020 | (0.1) Passwords: Argon2id with crypt-io's defaults (19 MiB, 2 passes, 1 lane); at most one hash per core at a time (`Error::Busy` beyond); an unknown identifier costs one Argon2id check against a dummy hash |
| D-021 | (0.1) Content: entities in lsm-db; routes in standard maps (site, then path) behind the route-index seam, rebuilt from the store at open. Replaced in 0.4. A path belongs to a site; the default site is `default` |
| D-022 | (0.1) Directory lock: the standard library file lock when built with Rust 1.89 or later; below that, an exclusive-share open on Windows and a pid file on Unix, checked through `/proc` on Linux and `ps` elsewhere (when `ps` cannot run, the directory stays locked) |
| D-023 | (0.1) The engine contract (`Engine`, `Staged`) is internal until the design lock (0.2). Settled by D-030 |
| D-024 | (0.1) Engines sit behind the `auth` and `content` features (both default). A database that uses an engine the build lacks refuses to open |
| D-025 | (0.1) Limits: identifier 320 bytes, password 1024 bytes, session lifetime 400 days, 1,000,000 sessions, names 64 bytes, site 253 bytes, path 2048 bytes, 256 fields, text 1 MiB, commit 16 MiB. Configurable from 0.3 |
| D-026 | (0.1) Known gap until 0.3: auth sections and account records are not sealed, so the Argon2id hash is stored in plain form in the log and the account store |
| D-027 | (0.1) Known gap until wal-db 1.1 (requested): wal-db 1.0 cuts the log at the first damaged record when it opens, also in the middle of the log. D-015's check catches this whenever a store has flushed past the cut. Closed by D-041 |
| D-028 | (0.1) The dev profile builds `argon2` and `blake2` with optimisation, so tests and examples hash at release speed |
| D-029 | (0.1) `cargo audit` ignores RUSTSEC-2026-0385 (`ctutils`) in `.cargo/audit.toml`: the crate is reachable only through crypt-io features nex-db does not enable, so it is not built (`cargo deny`, which follows enabled features, passes). Removed when nex-db moves to crypt-io 1.2.2. Done in 0.2 (D-035) |
| D-030 | (0.2) The engine contract stays crate-internal through 1.0. Engines are modules of this crate (one package, one version), so the contract can change with the core; making it public later is additive. Cost: no engine from outside the crate before then |
| D-031 | (0.2) Contract settled: `Engine` is `id`, `name`, `format`, `define`, `apply`, `durable_through`, `checkpoint`, `reclaim`; `Staged` is `engine`, `collection`, `is_empty`, `priority`, `validate`, `reserve`, `encode`. `define` checks a collection definition while staging (never during replay); the catalog stores the bytes. Staging is not a trait method: each engine's staging type sits in the transaction facade behind its feature. The change-feed hook (`describe`) and `health` arrive in 0.4 as provided methods with defaults |
| D-032 | (0.2) The commit pipeline, recovery, and catalog live in `core::pipeline::Core`, which reaches engines only through a `Registry` trait the facade implements over its typed fields (no allocation per lookup). A toy engine in the tests runs on `Core` alone, also in a build with no engine feature |
| D-033 | (0.2) Collections are created through `Core::define_collection`: definitions take their own lock (new id = highest + 1; a taken name is `AlreadyExists { what: "collection" }`), so ordinary commits never wait on a definition. The definition is checked by its engine and stored by the catalog |
| D-034 | (0.2) Catalog format 2 adds the definition (`bytes32`, at most 64 KiB). Before 1.0 a format changes behind its number and an unknown number keeps the database closed; 0.1 was never released, so format 1 has no reader. The 0.1 example's directory must be deleted before running the 0.2 example |
| D-035 | (0.2) crypt-io 1.2.2 (published 2026-10-26): `ctutils` and `hmac` leave the lockfile and the `cargo audit` ignore of D-029 is removed |
| D-036 | (0.2) `docs/API.md` settles the public API through 1.0. Content, after the survey of common content systems: statuses `Draft`, `Review`, `Published`, `Archived`, `Trashed`, with visibility (`Public`, `Members`, `Password`, `Private`) and schedules kept apart from status; one working draft per entity that saves without making revisions; publish state per locale; releases; who created, updated, and published; `unique` and `singleton` type flags; references found in a body passed in by the caller; redirects 301/302/307/308 to a route or a URL; term routes; redirect chains shortened |
| D-037 | (0.2) `Content::get(rid)` keeps reading the space's default locale; `get_in(rid, locale)` follows the fallback chain. Tier 1 keeps one argument |
| D-038 | (0.2) Building-block checks that shape 0.3: any lsm-db write or flush error halts writes (a failed flush drops the memtable from the live handle); nex-db syncs a store's directory itself before trusting a flush; the log's 16 MiB record limit is a format constant; audit-trail takes its time from the caller (the commit's time) and needs a durable sink from nex-db; page-db writes evicted pages without waiting for the log, so auth checkpoint pages are written only after the log covers them |
| D-039 | (0.2) Sealed auth sections need a nonce derived from the sequence number; crypt-io 1.x draws every nonce itself. Requested upstream (crypt-io 1.3). If it is not there by 0.3, sections use XChaCha20-Poly1305 with random 24-byte nonces, at 24 bytes more per auth section |
| D-040 | (0.2) The upstream requests were drafted first and posted on James's go (2026-10-29), worded for each crate's general use: the building-block repositories are public. The wal-db strict-open request is built in wal-db's own repository; dependency clean-ups wait on OD-5 |
| D-041 | (0.2) wal-db 1.1 with `OpenPolicy::Strict`: only an unfinished last record is cut; mid-log damage, a missing segment, or a record above the limit fails the open and leaves the log unchanged. Cost: an open that meets a damaged tail reads on to confirm nothing intact follows it (bounded by the log's size, at open only). D-015's check stays as a second guard |
| D-042 | (2026-11-02) James made the repository public, so CI runs on GitHub's public runners on the full matrix. Repository visibility only: the crate stays `publish = false`, and tagging 1.0 still needs James. The low profile stays: no announcements, topics, or promotion |
| D-043 | (2026-11-02) James's rule for every crate: go back and fix issues and tune performance before getting close to release. The roadmap gets a 0.9.x review milestone before any 1.0 release candidate; anything still open goes in the 1.0 readiness note James reads |
| D-044 | (2026-11-05) James approved `docs/API.md`. From here every change to a public name or shape it lists needs a decision in this log, and `docs/API.md` changes in the same commit |
| D-045 | (0.3) Group commit. The sequencer lock covers only validate, number, encode, reserve, and queue; a commit that finds no writer at work takes every queued record, appends them in sequence order, and syncs once; commits then apply and become visible strictly in sequence order. At most 4,096 commits are in flight (`Error::Busy { what: "commit queue" }` beyond). Writing outside the sequencer lock is required on Windows, where a write to the log waits for a sync in progress on the same file. Cost: one shared buffer and two lock hand-offs per commit; a lone commit is written and synced at once, with no window to wait for. Security: a failed append, sync, or apply halts the database and fails every commit not yet applied; nothing becomes visible out of order. Measured with `core/commit_throughput` (1 to 64 writers) |
| D-046 | (0.2, 2026-11-06) A fresh-eyes review of `docs/API.md` against this plan, under James's standing order to make the best decisions on the requirements and keep moving. Changes: previews go through `db.auth().redeem` and `resolve_draft`, so the content engine never checks auth data; `LockedOut` only after the password matched (unknown identifier and wrong password stay `Failed` with the same work); no page passwords in the content engine; `get` reads the published revision and `draft` the working draft; `new_recovery_codes` returns a redacted, wiped `RecoveryCodes`; `single_use_token_for(identifier, ..)` for password reset without revealing accounts; `allowed(account, permission)`; `open_replica` (FR-15); no `begin`; no group-commit window setting; `commit_with` returns `Committed<T>`; `standing` returns `Option`; plain names for API keys and releases; `Sealed` becomes `AuthHalted`; `Database::builder(dir)`. Code: `AuthTx::revoke` takes `impl AsRef<str>`; the dummy hash is built before the lookup result is used |
| D-047 | (0.3) Auth log sections are sealed (format 2, flags bit 0): XChaCha20-Poly1305 with a random 192-bit nonce under the log seal key (key id 1), associated data binding the sequence number, engine, collection, and format, and plaintext padded to 256-byte buckets. Format 1 (plain) stays readable. `Engine::apply` takes the decoded `Section` so the engine checks flags and format together. Cost: about 300 bytes per auth section instead of 50 to 160, and one AEAD seal per auth commit and one open per apply. Why 256 and not 64: with 64-byte buckets a revocation, a session, and an account each fall in a different bucket, so the size would still tell them apart. Security: a copied database log no longer holds Argon2id hashes, identifier digests, or token digests in readable form |
| D-048 | (0.3) Account records are sealed in the account store under the file key (XChaCha20-Poly1305, the store key as associated data), with the credential inside the account record. They are sealed while staging and carried in the log section (operation 4), so `apply` stays free of randomness and every replay stores the same bytes. Plain records from 0.1 and 0.2 stay readable. Cost: about 45 bytes per account in the log and the store, one seal per new account, and one open per password check. Security: a copied account store holds no Argon2id hash and no standing in readable form |
| D-049 | (0.3) Account epochs: each session carries the account's epoch when it was issued, and `validate` compares it with the epoch table (one map lookup per validation) after the expiry check. `revoke_all` raises the epoch in a priority commit and returns how many sessions were live; `rotate` revokes a token as `Rotated` and issues one with the same expiry. Epochs live in memory and are rebuilt from the log, like the sessions. Cost: `revoke_all` counts by walking the session table (the hot table's per-account index replaces the walk); four bytes per session record. Security: a sign-out everywhere cannot be undone by an old snapshot or a replay, since an epoch only rises |
| D-050 | (0.3) Standing and lock-out. The standing is in the sealed account record (code, until, reason) and a change rewrites the record in its commit; one that takes access away also raises the epoch, so every session ends at once. `verify_password` counts failures per account in memory (bounded to 100,000 accounts; older windows dropped first) and on the tenth within fifteen minutes commits a fifteen-minute lock-out, so the lock survives a restart while the count does not. A lock-out never replaces a ban or a suspension. API refinements against the approved `docs/API.md`: `LockedOut { until: Option<SystemTime> }` (a ban has no end); `Standing::LockedOut` has no reason; reasons are application-defined `u32` codes. Cost: one record open per password check (already needed for the hash); one durable commit per lock-out. Security: after a restart an attacker gets a fresh count of ten, not a free account |
| D-051 | (0.3) Every stored millisecond count turns into a time through one function that clamps at the end of the year 9999, so damaged data cannot panic a reader on any platform |

### Third-party runtime dependencies brought in by first-party crates (OD-5, temporary)

nex-db adds none of its own. `cargo tree -e normal` (default features, 0.1.0):

| Through | Crates | Status |
|---|---|---|
| wal-db 1.1, lsm-db 1.1 | `crc32c` | exception until OD-5 |
| wal-db, lsm-db (through error-forge 1.0) | `pastey`, `parking_lot`, `parking_lot_core`, `lock_api`, `scopeguard`, `smallvec`, `cfg-if`; `windows-link` on Windows, `libc` on Unix | exception until OD-5 |
| crypt-io 1.2.2 (audited cryptography) | `argon2`, `blake2`, `password-hash`, `base64ct`, `rand_core`, `getrandom` (`libc` on Unix), `blake3`, `arrayvec`, `constant_time_eq`, `cpufeatures`, `chacha20poly1305`, `chacha20`, `poly1305`, `aead`, `cipher`, `universal-hash`, `inout`, `crypto-common`, `digest`, `block-buffer`, `generic-array`, `typenum`, `opaque-debug`, `subtle`, `zeroize` | allowed (cryptography through crypt-io) |
| crypt-io (first-party) | `mod-rand` | first-party |

### Defence ideas

| Version | Idea | Method | Cost |
|---|---|---|---|
| 0.1 | A log cut by damage shows as a store holding commits past the log's end | compare every engine's applied mark with the last log seq at open; refuse to open when a mark is higher | one comparison per engine at open |
| 0.2 | A section can only reach the engine its collection is bound to | the core checks every section's collection against the catalog before `apply`; a mismatch halts writes and keeps the database closed (tested with two toy engines) | one catalog lookup per section |
