# nex-db - Roadmap

> One milestone at a time, each ending with something that runs. Work only on the current milestone. Requirements (FR, NFR) are in [`PLAN.md`](./PLAN.md).

**Current milestone: 0.3.0 (core and auth). 0.2.0 is done: James approved `docs/API.md` on 2026-11-05. 0.1.0 is merged and waits for James to run the example before it is tagged.**

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
- Key hierarchy through key-vault and crypt-io; sealed auth sections.
  - [x] Sealed and padded auth sections in the log (`PLAN.md` D-047).
  - [x] Sealed account records in the account store (`PLAN.md` D-048).
  - [x] Key sources outside the directory and a key check (`PLAN.md` D-053); the OS keychain source in 0.4.
- Hot table, timer wheel, epoch table, tombstones, checkpoints; standing, counters, lockout, audit chain, revocation journal (FR-6, FR-7).
  - [x] Epoch table, `revoke_all`, `rotate` (`PLAN.md` D-049).
  - [x] Standing, failure counters, and lock-out (`PLAN.md` D-050).
- **Exit:** James's site signs users in on nex-db.

## 0.4.0 Content and adapters

- Types, revisions, statuses, scheduling, locales, route index, redirects, references, reverse index, listings, change feed (FR-9, FR-10).
- Auth extras (FR-8). Metrics and health hooks.
- **Exit:** James's site serves its pages from nex-db.

## 0.5.0 Feature complete

- Split auth (FR-11), per-account keys and erasure (FR-12), search (FR-13), backup and restore (FR-14).
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
