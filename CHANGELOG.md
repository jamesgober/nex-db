# Changelog

All notable changes to `nex-db` are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- `Auth::account` and `Account`; `add_identifier` and `remove_identifier` (up to five identifiers per account).
- Roles: `Role`, `RoleId`, `define_role`, `assign_roles`, `roles`, `role`, `role_named`, and `allowed`.
- `set_password`: replaces the password and ends the account's sessions in the same commit.
- Single-use tokens: `single_use_token`, `single_use_token_for` (password reset by address), `redeem`, and `Purpose`.
- Drafts and publishing: `save_draft` with `Patch`, `save_revision`, `publish`, `unpublish`, `set_path`, `set_status`, `set_visibility`; `Content::draft`, `revisions`, `revision`; `Status`, `Visibility`, `RevisionInfo`; `Entry::status`, `visibility`, `updated_at`, `published_at`, `first_published_at`.
- `RouteKind::Redirect` (a moved entity's old path, 301) and `RouteKind::Gone`; `RouteEntry::visibility`.
- The change feed: `Database::feed`, `Database::position`, `Feed`, `Position`, `Change`, and `Error::FeedBehind` (NEX-1012).
- Listings: `Content::list`, `next_page`, `Listing` (`latest`, `updated`, `site`, `limit`), `Page`, and `Cursor`.
- `Database::health` and `Health`; `Builder::observer`, `Observer`, `CommitInfo`, and `SecurityEvent`.
- `trash`, `restore`, and `delete` (paths of a trashed or deleted entity answer `RouteKind::Gone`).
- Types: `Content::define`, `type_named`, `Type` (`field`, `unique`, `singleton`), and `FieldType`.
- Terms: `Value::List`, `FieldType::List` and `FieldType::Terms`, `Type::terms` and `Type::taxonomy`, and `Listing::term`.
- Page tree and authors: `Entity::parent`, `order`, and `author`; `set_parent`, `set_order`, `set_authors`; `Content::children` and `ancestors`; `Entry::parent`, `order`, and `authors`; `Listing::by_author`.
- References: `Type::reference` and `Rule` (`Restrict`, `Detach`, `Cascade`), applied by `delete`; `Content::referenced_by`; `Error::Restricted` (NEX-1010).
- Locales: `Locale`, `SpaceSpec`, `Content::space` and `set_space`, `Entity::locale`, `translate`, `publish_in`, `unpublish_in`, `set_path_in`, `get_in`, `draft_in`; `Entry::locale` and `fallback`; `RouteEntry::locale`; `RevisionInfo::locale`.

### Changed

- A commit that loses to a conflict waits for the winning commit to be visible before it retries.
- Entity heads are format 4 (the references of published bodies, authors, parent, and order); formats 2 and 3 still read.
- Account records are format 3 (further identifiers and roles); format 2 records still read.
- `create` makes a draft: `get` and `resolve` find an entity only once it is published. Content sections are format 2; stores and logs written by 0.1 to 0.3 still read, their entities published at revision 1.

### Fixed

- Editing an entity stored by 0.1 to 0.3 no longer loses its published body.

## [0.3.0] - 2026-11-07

### Added

- Group commit: one writer appends and syncs each batch of commits; at most 4,096 commits wait at once (`Error::Busy` beyond).
- `Auth::revoke_all` and `AuthTx::revoke_all` (sign an account out everywhere), and `rotate`.
- `Auth::verify_password`, `Login`, `Auth::standing`, `set_standing`, and `Standing`; ten failed sign-ins within fifteen minutes lock an account out for fifteen minutes. `SignIn::LockedOut`.
- `RevokeReason::Rotated` and `RevokeReason::SignedOutEverywhere`.
- `SessionSpec::idle`, `recheck_after`, and `payload` (up to 256 bytes), and `Session::idle_limit`, `recheck_at`, and `payload`.
- `Database::builder`, `Builder`, and `Keys`: the root key from a file outside the directory (`Keys::file`) or an environment variable (`Keys::env`). `auth/key.check` makes the wrong key fail as `KeyUnavailable`.
- An audit chain per realm (`auth/audit.chain`, audit-trail format, keyed BLAKE3): every security write, kept after the log is truncated.
- Checkpoints and log truncation: the log stays bounded and an open replays only what came after the last checkpoint. `Builder::checkpoint_every` (64 MiB by default). Sessions and epochs are kept in a sealed `auth/sessions.ckpt`.
- `Database::read`, `Read`, `AuthRead`, and `ContentRead`: reads across engines at one snapshot. `Error::SnapshotTooOld` (NEX-1009) after 60 seconds.
- `Builder::max_sessions` (1,000,000 by default).

### Changed

- Auth sections in the log are sealed and padded (format 2); account records in the account store are sealed. Logs and stores written by 0.1 and 0.2 still read.
- Sessions live in a fixed-slot table read without locks; expired sessions and old revocations are reclaimed about a second after their time instead of at checkpoints.
- `Engine::apply` (internal) takes the decoded section; `Engine::checkpoint` takes the mark to reach.
- wal-db 1.1.1.

### Fixed

- A damaged time value in stored data could panic when read; times are now clamped to the year 9999.

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

[Unreleased]: https://github.com/jamesgober/nex-db/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jamesgober/nex-db/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/nex-db/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/nex-db/releases/tag/v0.1.0
