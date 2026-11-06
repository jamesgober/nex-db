# Changelog

All notable changes to `nex-db` are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [0.2.0] - 2026-11-06

The design lock: the public API through 1.0 is written down and approved.

### Added

- `docs/API.md` (the public API through 1.0; its examples run as doctests), `docs/LOG_FORMAT.md`, and `docs/FILE_FORMATS.md`.
- The engine contract as documented internal code, with a toy engine in the tests that runs on the core with no other engine.

### Changed

- Catalog format 2: a collection keeps its engine's definition. A database written by 0.1 does not open; delete its directory.
- crypt-io 1.2.2.
- wal-db 1.1, opened under its strict policy: damage before the end of the log, or a missing segment, now always keeps the database closed and leaves the log unchanged.
- `AuthTx::revoke` takes `impl AsRef<str>`, like `Auth::revoke`.

### Fixed

- The first sign-in of a process costs the same work whether the identifier exists or not.
- On Unix with Rust below 1.89, a database whose owner had crashed stayed locked on systems without `/proc` (macOS).

## [0.1.0] - 2026-11-05

The walking skeleton.

### Added

- Core: a commit log on wal-db with an engine-tagged record format; one commit sequence and a visible sequence number; the catalog (engine 0) with the default realm and space; recovery that replays the log into every engine and refuses to open on a gap, a damaged record, a missing key, or a store ahead of the log; a directory lock so one process owns a database.
- `nex_db::open`, `Database::commit` (atomic across engines, snapshot-isolation conflict check, up to four attempts), and `Transaction` with `auth()` and `content()`.
- Auth engine (`auth` feature): `hash_password` (Argon2id), `create_account`, `issue_session`, `validate`, `revoke`, `sign_in`. Tokens and identifiers are stored as keyed BLAKE3 digests.
- Content engine (`content` feature): `create`, `get`, `resolve`; entities with typed fields and a path on a site.
- `Error` with stable codes (`NEX-1001` to `NEX-1008`).
- `examples/site.rs`, integration tests, a kill test (`tests/kill.rs`), and criterion benchmarks (`benches/core.rs`).
- Repository scaffold: `Cargo.toml` (edition 2024, MSRV 1.85), `src/lib.rs` with `VERSION`, CI on Linux, macOS, and Windows (stable and 1.85), `cargo deny` configuration.
- `dev/PLAN.md`, `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/nex-db/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/nex-db/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/nex-db/releases/tag/v0.1.0
