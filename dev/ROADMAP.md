# nex-db - Roadmap

> One milestone at a time, each ending with something that runs. Work only on the current milestone. Requirements (FR, NFR) are in [`PLAN.md`](./PLAN.md).

**Current milestone: 0.5.0 (feature complete). 0.1.0 to 0.4.1 are released (GitHub pre-releases).**

---

## 0.1.0 Scaffold and walking skeleton

- [x] Repository, `Cargo.toml`, `src/lib.rs` with `VERSION`, CI, `cargo deny` configuration, plan files.
- [x] Core: commit log on wal-db with the engine-tagged record header; sequencer; visible sequence; catalog; recovery replay (FR-1, FR-2, FR-4, FR-5).
- [x] Auth: sessions in a standard map behind the hot-table seam (replaced in 0.3); accounts and identifiers in lsm-db; Argon2id through crypt-io; `validate`, `issue_session`, `revoke`, `create_account`, `hash_password`, `sign_in`.
- [x] Content: entities in lsm-db; routes in a standard map behind the route-index seam (replaced in 0.4); `create`, `get`, `resolve`.
- [x] `db.commit` across both engines (FR-3).
- [x] `examples/site.rs`: sign up (account and profile in one commit), sign in, validate, resolve, reopen.
- [x] Kill test: the process is killed at random points in a loop; every reopen matches the last acknowledged commit.
- **Exit:** the example runs on all three platforms; the kill test passes 10,000 iterations.
- Seams in 0.1, each replaced later behind the same calls: sessions in a standard map (hot table, 0.3), routes in standard maps (route index, 0.4), the root key file (key-vault, 0.3), one commit lock with a sync per commit (group commit, 0.3), full log replay at open (checkpoints and truncation, 0.3).
- [x] wal-db 1.0 truncated the log at the first damaged record when it opened (`PLAN.md` D-027). Closed with wal-db 1.1 strict open (D-041; done in 0.2).
- [x] Move to crypt-io 1.2.2 and drop the `cargo audit` ignore (`PLAN.md` D-029, D-035; done in 0.2).
- Run on macOS: the repository is public, so CI runs the full matrix again (`PLAN.md` D-042). The example and kill test on macOS are still to be seen there.

## 0.2.0 Design lock

- [x] `docs/API.md` (whole public API, Tier 1 first), `docs/LOG_FORMAT.md`, `docs/FILE_FORMATS.md`.
- [x] The engine contract as code with documentation; a toy third engine in the tests (`PLAN.md` D-030 to D-033).
- [x] Building-block checks done (`PLAN.md` D-038, D-039).
- [x] Upstream requests filed (2026-10-29, on James's go): crypt-io, lsm-db, txn-db, index-db, audit-trail, key-vault; wal-db strict open shipped in wal-db 1.1; dependency clean-ups wait on OD-5 (`PLAN.md` D-040).
- [x] **Exit:** James approves `docs/API.md` (2026-11-05, `PLAN.md` D-044).
- Blockers recorded for 0.3, each requested from its crate:
  - crypt-io has no AEAD call that takes the caller's nonce, which sealed auth sections need (`PLAN.md` D-039).
  - lsm-db 1.1 has no checksum on its manifest (a damaged manifest can drop runs without an error) and drops the memtable when a flush fails.
  - txn-db 1.0 needs `drain_through` and its oldest-reader mark for the account-store overlay.
- macOS: store-io 0.4 has no macOS backend (it arrives in store-io 0.5). Direct I/O on macOS waits for it.

## 0.3.0 Core and auth

- Full commit pipeline (snapshot isolation, serializable option, group commit, bounded queue, fsync halt), write classes, snapshots and versioned overlays, checkpoints, log truncation, catalog locks.
  - [x] Group commit with a bounded queue; a failed write, sync, or apply halts writes (`PLAN.md` D-045).
  - [x] Snapshots: `db.read` with versions kept for running snapshots (`PLAN.md` D-052).
  - [x] Checkpoints and log truncation (`PLAN.md` D-056).
  - [x] Audit chain (`PLAN.md` D-057).
  - [x] Session payload, idle limit, and recheck time (`PLAN.md` D-059).
  - [x] Loom models of the table's slots and the commit pipeline's ordering (`PLAN.md` D-063).
- Key hierarchy through key-vault and crypt-io; sealed auth sections.
  - [x] Sealed and padded auth sections in the log (`PLAN.md` D-047).
  - [x] Sealed account records in the account store (`PLAN.md` D-048).
  - [x] Key sources outside the directory and a key check (`PLAN.md` D-053); the OS keychain source in 0.4.
- Hot table, timer wheel, epoch table, tombstones, checkpoints; standing, counters, lockout, audit chain, revocation journal (FR-6, FR-7).
  - [x] Epoch table, `revoke_all`, `rotate` (`PLAN.md` D-049).
  - [x] Standing, failure counters, and lock-out (`PLAN.md` D-050).
  - [x] Fixed-key session table with lock-free reads (`PLAN.md` D-061) and the timer wheel (D-062); `Builder::max_sessions` (D-064).
  - [x] Benchmarks `auth/validate_hit` (1, 1 million; 10 million with `NEX_BENCH_LARGE`), `auth/issue_durable`, `auth/revoke_durable`, `core/commit_throughput`, and `table/get_hit`.
- Moved (`PLAN.md` D-058, D-065): named realms, `commit_serializable`, and catalog locks to 0.4; the revocation journal to 0.5; incremental session-table checkpoints to 0.6.
- **Exit:** James's site signs users in on nex-db. Released 2026-11-07 with this open: the site's adapter to nex-db comes with 0.4, so `examples/site.rs` stands in for it (sign up, sign in, validate, reopen) and runs on Linux, macOS, and Windows in CI. James confirms on his site.

## 0.4.0 Content and adapters

- Types, revisions, statuses, scheduling, locales, route index, redirects, references, reverse index, listings, change feed (FR-9, FR-10).
  - [x] Drafts, revisions, publishing, statuses, visibility; redirects on a path change (`PLAN.md` D-069, D-070).
  - [x] Change feed (`PLAN.md` D-071).
  - [x] Listings by site and type, two orders, cursors (`PLAN.md` D-072).
  - [x] Locales: per-locale drafts, publishing, and paths, fallback chains (`PLAN.md` D-074).
  - [x] Types: declared field kinds, unique fields, singletons (`PLAN.md` D-075, fixed in D-081).
  - [x] Trash, restore, delete with gone routes (`PLAN.md` D-076).
  - [x] References of entity fields, `referenced_by`, and their rules on delete (`PLAN.md` D-078).
  - [x] Page tree (`children`, `ancestors`) and authors with `by_author` listings (`PLAN.md` D-083); descendant paths following a move still to come.
  - [x] Terms as entities, list values, terms fields, and `term` listings (`PLAN.md` D-084).
  - [x] Scheduled publishing and unpublishing per locale (`PLAN.md` D-085).
- [x] `commit_serializable` (from 0.3, `PLAN.md` D-086).
- [x] Named realms and spaces with `RealmPolicy` (from 0.3, `PLAN.md` D-087), and catalog locks (D-088).
  - Blocker recorded: lsm-db 1.1 scans materialize the whole range, so derived indexes stay in memory and are rebuilt at open; a lazy, bounded scan is requested from lsm-db.
- Auth extras (FR-8). Metrics and health hooks.
  - [x] Health and observers (`PLAN.md` D-073); the `metrics` feature (D-093).
  - [x] `account`, `add_identifier`, `remove_identifier` (from 0.3, `PLAN.md` D-066), roles (D-067), `set_password` (D-068).
  - [x] Single-use tokens (`PLAN.md` D-077).
  - [x] Session listing and `revoke_session` (`PLAN.md` D-089), API keys (D-090), recovery codes (D-091).
  - Waiting: TOTP and passkeys need crypt-io 1.5 (HMAC-SHA1, ES256 and RS256 verification); in 0.4 if it is out first, else 0.5 (`PLAN.md` D-092).
- **Exit:** James's site serves its pages from nex-db. Released 2026-11-08 with this open: the site's adapter is built against 0.4, so `examples/site.rs` stands in for it (sign up, sign in, publish, resolve, reopen) on Linux, macOS, and Windows in CI. James confirms on his site.
- Moved to 0.5: TOTP and passkeys (they wait for crypt-io 1.5, `PLAN.md` D-092; a 0.4 patch release if it lands first), devices, descendant paths following a moved parent, sticky posts, `revert`, releases, `get_many`, `Keys::vault`, and assets.

## 0.5.0 Feature complete

- Split auth (FR-11), per-account keys and erasure (FR-12), search (FR-13), backup and restore (FR-14).
- From 0.4: sticky entities, `get_many`, outdated translations, `stream`, `add_redirect` and `remove_route`.
  - [x] Sticky entities and `sticky_first` (`PLAN.md` D-097).
  - [x] `Listing::outdated` (D-098); `add_redirect`, `remove_route`, `get_many`, `stream` (D-099).
- From 0.4: TOTP and passkeys (crypt-io 1.5), released in 0.4.1.
  - [x] TOTP, feature `mfa` (`PLAN.md` D-094).
  - [x] Passkeys, feature `mfa` (`PLAN.md` D-095).
- **Exit:** every P0 and P1 item in `docs/API.md` exists.

## 0.6.0 Optimisation

- Benchmarks for every hot path with baselines; zero allocations on read hits proved.
- **Exit:** every performance target met, or the gap recorded with a plan.

## 0.7.0 Hardening

- Fuzz targets for every decoder; attack tests for every threat; soak tests; kill tests on all three platforms.
- Upstream dependency removals adopted (OD-5).
- **Exit:** no third-party runtime dependency outside crypt-io's audited cryptography.

## 0.8.0 Alpha

- Read replica following the log (FR-15); multi-machine simulation tests.
- **Exit:** two weeks in production on James's site with no data issue.

## 0.9.0 Beta

- Format freeze rehearsal; documentation complete; `docs/STABILITY-1.0.md` drafted.
- **Exit:** every 0.8 database opens, and a downgrade is refused cleanly.

## 0.9.x Review

Before any 1.0 release candidate (`PLAN.md` D-043):

- Revisit every accepted gap, deferred item, known issue, and missed target, and fix it or say why not.
- A fresh performance tuning pass.
- The security and edge-case review run again.
- **Exit:** the 1.0 readiness note, for James, lists whatever is still open.

## 1.0.0 release candidates

- **Exit:** two release candidates with no API change between them.

## 1.0.0 Stable

- Full audit recorded; API frozen until 2.0; formats frozen for 1.x. James approves.

## After 1.0

Log engine, blob engine, hot engine, server mode, replica groups, sharding, multi-region (order: OD-4). Each is additive on the frozen API.
