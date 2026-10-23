# nex-db - Roadmap

> One milestone at a time, each ending with something that runs. Work only on the current milestone. Requirements (FR, NFR) are in [`PLAN.md`](./PLAN.md).

**Current milestone: 0.1.0 (scaffold done; walking skeleton next).**

---

## 0.1.0 Scaffold and walking skeleton

- [x] Repository, `Cargo.toml`, `src/lib.rs` with `VERSION`, CI, `cargo deny` configuration, plan files.
- [ ] Core: commit log on wal-db with the engine-tagged record header; sequencer; visible sequence; catalog; recovery replay (FR-1, FR-2, FR-4, FR-5).
- [ ] Auth: sessions in a standard map behind the hot-table seam (replaced in 0.3); accounts and identifiers in lsm-db; Argon2id through crypt-io; `validate`, `issue_session`, `revoke`, `create_account`, `hash_password`, `sign_in`.
- [ ] Content: entities in lsm-db; routes in a standard map behind the route-index seam (replaced in 0.4); `create`, `get`, `resolve`.
- [ ] `db.commit` across both engines (FR-3).
- [ ] `examples/site.rs`: sign up (account and profile in one commit), sign in, validate, resolve, reopen.
- [ ] Kill test: the process is killed at random points in a loop; every reopen matches the last acknowledged commit.
- **Exit:** the example runs on all three platforms; the kill test passes 10,000 iterations.

## 0.2.0 Design lock

- `docs/API.md` (whole public API, Tier 1 first), `docs/LOG_FORMAT.md`, `docs/FILE_FORMATS.md`.
- The engine contract as code with documentation; a toy third engine in the tests.
- Building-block checks done; upstream requests filed.
- **Exit:** James approves `docs/API.md`.

## 0.3.0 Core and auth

- Full commit pipeline (snapshot isolation, serializable option, group commit, bounded queue, fsync halt), write classes, snapshots and versioned overlays, checkpoints, log truncation, catalog locks.
- Key hierarchy through key-vault and crypt-io; sealed auth sections.
- Hot table, timer wheel, epoch table, tombstones, checkpoints; standing, counters, lockout, audit chain, revocation journal (FR-6, FR-7).
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

## 0.9.0 Beta and release candidates

- Format freeze rehearsal; documentation complete; `docs/STABILITY-1.0.md` drafted.
- **Exit:** two release candidates with no API change between them.

## 1.0.0 Stable

- Full audit recorded; API frozen until 2.0; formats frozen for 1.x. James approves.

## After 1.0

Log engine, blob engine, hot engine, server mode, replica groups, sharding, multi-region (order: OD-4). Each is additive on the frozen API.
