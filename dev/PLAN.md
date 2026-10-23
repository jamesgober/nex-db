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

Tier 1 (above) covers the common uses with no builder; Tier 2 adds a builder, type definitions, listings, and pinned reads; Tier 3 is the engine contract and the change feed. `docs/API.md` (0.2) holds the full API.

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
| OD-1 | when the repository goes public and the crate is published | private through 0.x; decide at 0.8 |
| OD-2 | password verification inside the auth engine (changes WASP's identity store trait) | yes |
| OD-3 | nex-db as the store for James's site and WASP's first deployment | yes |
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
