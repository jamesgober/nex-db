# nex-db - Engineering Directives

> Engineering standards and the definition of done for this project. Read alongside `REPS.md` (root, authoritative), [`PLAN.md`](./PLAN.md) (scope and decisions), and [`ROADMAP.md`](./ROADMAP.md) (current phase). If anything here conflicts with `REPS.md`, `REPS.md` wins, except where `PLAN.md` records an approved exception (D-005: no async runtime).

---

## 0. Philosophy

A database is trusted with data that must not be lost or leaked. Plan the full path, then build one verified step at a time. "Good enough" is treated as a defect. At every design choice, take the fastest option that keeps the guarantees, and state its cost.

---

## 1. What this is

An embedded database: engines side by side on one core (one commit log, one catalog, one snapshot), typed operations only, an auth engine sealed under its own keys. See `PLAN.md` sections 1 to 3.

---

## 2. Engineering law (non-negotiable)

- **One log, one truth.** Every state change is a commit in the log, applied to its engine from the encoded bytes. Recovery and replicas use the same apply path. Derived structures are rebuilt from the log, never trusted when damaged.
- **Engines never read each other.** Work across engines is composed by the caller in one commit.
- **Sealed auth.** No query, scan, list, or export of credentials, session digests, or identifiers. Auth keys never leave the auth engine.
- **Zero third-party runtime dependencies.** Cryptography only through crypt-io. First-party crates by published version, never `path`. No async runtime.
- **Fail closed.** A missing key, a corrupt record before the log tail, or a failed fsync stops writes (or keeps the database closed). A failed fsync is never retried.
- **Bounded.** Every queue, cache, and table has a configured limit; overload returns an error.
- **Fast reads.** Read hits allocate nothing and take no lock. Proved by counting-allocator tests and loom models.
- **Zero CPU when idle.** No polling; timers sleep until due.
- **Unsafe.** `#![forbid(unsafe_code)]`.
- **Secrets.** Never in `Debug`, `Display`, errors, logs, or the change feed. Wiped after use.
- **Cross-platform.** Linux, macOS, and Windows on x86_64 and aarch64, stable and MSRV 1.85, in CI. Crash-safety tests on all three.
- **Error handling.** Every fallible path returns `Result`; `Error` is `#[non_exhaustive]`, carries a stable code, and says what to do.
- **Production-ready.** `#![deny(missing_docs)]`; no `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!`/`unreachable!`/`dbg!`/printing in library code; every public item has rustdoc with a runnable example.
- **Performance.** No claim without criterion numbers; regressions over 5% block a change. Numbers stay in private notes until James decides what is published.

---

## 3. Definition of done

1. Compiles clean on Linux, macOS, and Windows (x86_64 and aarch64), stable and MSRV 1.85.
2. `fmt`, `clippy -D warnings` (all targets; default, all, and no default features), tests in the same three modes, `cargo doc -D warnings` with default and all features, and `cargo package` in a fresh target directory: clean on Windows and in WSL Ubuntu, stable and 1.85.
3. `cargo audit` and `cargo deny check` pass; `cargo tree -e normal` shows no third-party crate (except crypt-io's audited cryptography, and any exception recorded in `PLAN.md`).
4. A Tier 1 API exists and headlines the docs.
5. Every format decoder has a fuzz target; every threat has an attack test; every crash point in the commit path is covered by a kill test.
6. Hot-path changes carry benchmarks; no regression over 5%.
7. `README.md`, `docs/API.md`, and `CHANGELOG.md` updated in the same change; `docs/release/vX.Y.Z.md` written before the tag; every version string bumped.
8. `PLAN.md` decision log updated for every design decision; at least one new defence idea per version.
9. 1.0.0 only after the full audit is recorded in `docs/STABILITY-1.0.md` and James approves it.

---

## 4. Project-specific invariants

- An acknowledged commit survives a crash; an unacknowledged one never appears in part.
- A reader never sees half a commit; the visible sequence only moves forward.
- A revoked session never validates again on any path: snapshot, replica, or restore.
- A collection's engine never changes.
- The auth engine's plaintext never reaches the core, another engine, the change feed, or a log line.
- Every derived structure equals what a rebuild from the log would produce.

---

## 5. Writing style

- Plain, specific, human prose. No marketing voice, no comparisons with other projects in public files.
- Banned in shipping files: "comprehensive", "robust", "seamless", "leverage", the em-dash character (U+2014), and emoji.
- Every security measure states its cost; estimates are labelled as estimates.
- Release notes in the past tense. Commits in the imperative present tense.
