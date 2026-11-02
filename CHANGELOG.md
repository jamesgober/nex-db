# Changelog

All notable changes to `nex-db` are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Core: a commit log on wal-db with an engine-tagged record format; one commit sequence and a visible sequence number; the catalog (engine 0) with the default realm and space; recovery that replays the log into every engine and refuses to open on a gap, a damaged record, a missing key, or a store ahead of the log; a directory lock so one process owns a database.
- `nex_db::open`, `Database::commit` (atomic across engines, snapshot-isolation conflict check, up to four attempts), and `Transaction` with `auth()` and `content()`.
- Auth engine (`auth` feature): `hash_password` (Argon2id), `create_account`, `issue_session`, `validate`, `revoke`, `sign_in`. Tokens and identifiers are stored as keyed BLAKE3 digests.
- Content engine (`content` feature): `create`, `get`, `resolve`; entities with typed fields and a path on a site.
- `Error` with stable codes (`NEX-1001` to `NEX-1008`).
- `examples/site.rs`, integration tests, a kill test (`tests/kill.rs`), and criterion benchmarks (`benches/core.rs`).
- Repository scaffold: `Cargo.toml` (edition 2024, MSRV 1.85, no dependencies), `src/lib.rs` with `VERSION`, CI on Linux, macOS, and Windows (stable and 1.85), `cargo deny` configuration.
- `dev/PLAN.md`, `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/nex-db/commits/main
