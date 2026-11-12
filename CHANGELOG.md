# Changelog

All notable changes to `nex-db` are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Signed audit exports, feature `audit-export`: `db.auth().audit_export(ids)` verifies the realm's audit chain and signs the records with ids in `ids` with an Ed25519 key derived from the root key; an auditor checks it with `AuditExport::from_bytes(bytes, &public_key)` and `db.auth().audit_public_key()` alone. Events carry ids, kinds, and times; `continues` joins exports of consecutive ranges.
- Read replicas: `db.ship(after, out)` writes the commits after a position as a shipment; `nex_db::open_replica(dir)` opens a directory restored from a backup of the primary as a `Replica`, and `replica.receive(from)` commits a shipment's records in order through the commit path. A replica serves the database's reads, refuses writes with `Error::ReadOnlyReplica` (NEX-1013), and its directory opens as a database to promote it. Shipments are sealed end to end (XChaCha20-Poly1305 under a key derived from the root key) and checked to continue the replica's own history. A primary behind which a checkpoint dropped a replica's commits answers `Error::ReplicaBehind` (NEX-1014). `tests/replica.rs` includes a deterministic simulation of a primary and a replica with cut and repeated shipments and restarts, compared at every checked position.
- `db.content().put(entity)` (also in a transaction): create and publish in one step, so a page is served once the commit returns.
- `db.auth().sign_up(identifier, password)`: hash the password and create the account in one call.

### Changed

- Split auth: a request reads its own reply from the auth process instead of waiting for a reader thread to hand it over, which saves a thread wake-up on every call. A watchdog thread checks every 100 ms that the auth process is still running and that no request has waited past its limit. Measured with the local latency harness, alternating with 0.7.0: a session check takes a median of 5.6 to 6.0 us against 8.1 to 8.3 us on Linux, and 11 to 27 us against 20 to 37 us on Windows (mean 17 to 33 us against 37 to 71 us). Eight threads sharing the channel do more checks a second on both: 54,000 to 83,000 against 18,000 to 67,000.
- Renamed for plain names (the old names stay, deprecated, until 0.9):

  | 0.7 | 0.8 |
  |---|---|
  | `Rid` | `EntityId` |
  | `Login` (from `verify_password`) | `PasswordCheck` |
  | `Entry::rid()` | `Entry::id()` |
  | `Hit::rid()` | `Hit::entity()` |
  | `Change::EntityChanged { rid, .. }` | `Change::EntityChanged { entity, .. }` (no alias: rename the field in patterns) |

  To migrate, replace the names in the left column with those in the right. The compiler points at each use of a deprecated name, and at each pattern on the old field.
- The text of a malformed entity id error says `entity id` instead of `record id`.
- `docs/API.md` marks items that are not built yet as planned instead of giving them a version.

### Fixed

- **Split auth left passwords, tokens, and secrets in freed memory** of both processes: every request and reply frame was built in a buffer that grew and was freed unwiped, and the read buffers kept the last 64 KiB of frames. Each process now reads frames straight off the pipe into one buffer that wipes each frame once handled, and builds frames in per-thread buffers sized up front and wiped after each send.
- **A split session check made 4 allocations in the application** (its rustdoc says it allocates none). The request frame, the slot it waits in, and the reply buffer are now kept per thread: none once a thread has made one check. `tests/alloc.rs` counts it.
- **A split checkpoint or backup had the same two-minute limit as any request**, so one on a large store or a slow disk ended the auth process and stopped writes. They now have an hour. **An answer too long for a frame was never sent**, so its request waited out the limit with the same result; it now returns `Error::Invalid` at once.
- **Split auth with `Keys::env` left the root key in the application process**: the auth process inherits its environment from the application. Split auth now refuses `Keys::env`; use a key file. `docs/API.md` also says what the split defends against (memory disclosure in the application) and what it does not (code execution as the same OS user).
- `docs/API.md` said reads inside `db.commit` are snapshot isolation; they see the latest committed state. It now says so, and points to `commit_serializable` for writes derived from reads.
- **`rotate` renewed a session past its idle limit**, which `validate` already answered `Expired` for. Both now use one rule: the absolute expiry and the idle limit against the last use.
- **A delete in the commit that also wrote a revision left that revision in the store** for good (listed, and in every backup). The delete now removes revisions written earlier in the same commit, also when an older log is replayed.
- **A lock-out did not slow guessing, and its answer named the password.** During a lock-out every guess was still checked, a wrong one answered `Failed`, and only the right one answered `LockedOut`. Now no password is checked while sign-in is locked out, and every password answers `LockedOut` after the same work.
- **`check_totp` counted no failures**, so an application using `verify_password` and `check_totp` allowed unlimited code guessing. Second-factor checks now count toward the account's lock-out, and while it holds they answer `false` for every code.
- **Ten wrong passwords signed the owner out of every device.** The lock-out after repeated failures no longer changes the account's standing: it blocks new sign-ins only, commits nothing (so the tenth failure of a real account no longer takes longer than any other), and ends no session. It counts failures for identifiers that name no account too, so a lock-out does not tell which accounts exist. It is kept in the session checkpoint (format 2) and survives a clean restart.
- **Counting stopped once 100,000 accounts had a recent failure.** The oldest windows now go first when the table fills.
- **A decoy presented to `revoke`, `rotate`, or `redeem` raised nothing**, and `revoke` removed it. Each now raises `SecurityEvent::DecoyPresented` and answers as for a token never issued; the decoy stays planted until `retire_decoy` (new) removes it.
- Store prefix scans share one helper (they were two copies of the same code). A prefix of only `0xFF` bytes now scans to the end of the key space instead of an empty range. No key nex-db writes starts that way, so no stored data was missed.
- The scheduling thread allocated on every pass, even with nothing due. Its first pass could fall inside `tests/alloc.rs`'s count on a loaded machine, so the test failed now and then. A pass with nothing due now allocates nothing.
- The README and crate-level examples published a page without `publish`, so the page they resolved was a draft and not served. They now use `put` and compile as doctests.

## [0.7.0] - 2026-11-10

Hardening: fuzzing, attack and soak tests, decoy tokens, and no third-party dependency outside crypt-io's cryptography.

### Added

- Decoy tokens: `plant_decoy()` gives a token that names no session. Validating it answers `Validation::Unknown`, as for any token never issued, and raises `SecurityEvent::DecoyPresented`; `revoke` retires it. Log op 17 and session checkpoint slot kind 3.

## [0.6.0] - 2026-11-09

Optimisation: the session table, a cache of published entries, allocation-free read hits, and canary routes.

### Added

- Canary routes: `add_canary(site, path)` marks a path nothing is served at. `resolve` answers `None` for it, as for any unknown path, and raises `SecurityEvent::CanaryRequested`. Route records gain kind 4.

### Changed

- wal-db 1.2 and lsm-db 1.2 (and error-forge 1.1 through them): with them no third-party crate comes in outside crypt-io's cryptography. On-disk formats and checksums are unchanged.

- The session table keeps entries in place and finds them with one index probe: about half the memory per session, and faster checks of unknown tokens.
- Session tokens parse through a lookup table.
- Content reads of entries served before come from a cache of decoded entries (up to 4,096 entities per space), and cloning an `Entry` no longer copies its fields.
- Split auth: replies are read through a buffer and written in one write each.
- The session table allocates its cells in chunks of at most 1,024, so mid-size tables waste less memory.

### Fixed

- Two reads of one entity or account in one `db.read` could disagree when a commit applied between them.
- A read could see a commit that was applied but not yet visible, and then an older version on the next read.

## [0.5.0] - 2026-11-09

Feature complete: split auth, erasure, search, and backups.

### Added

- Sticky entities: `Entity::sticky`, `set_sticky`, `Entry::sticky`, and `Listing::sticky_first`.
- `Listing::outdated(locale)`: translations made from an older revision than their source publishes.
- `get_many`, one snapshot for many entities, and `stream`, every entry of a listing.
- `add_redirect` and `remove_route`.
- Backups and point-in-time restore: `Database::backup`, `restore`, `BackupInfo`, and `RestorePoint`. Later backups into the same directory add the commits since; revocations after the restore point are applied again.
- Per-account data keys and `erase_account`: an account's private records are sealed under its own key, kept in `auth/account-keys` and never in the log; erasing the account removes its records and destroys the key. `RevokeReason::Erased` and `Change::AccountErased`.
- Search: `Type::searchable`, `Content::search`, `Search`, `Hit`, and `Hits`: every word of a query in a published body of one locale, ranked by BM25 over weighted fields; English locales stem and skip common words.
- Split auth, feature `split-auth`: `Builder::auth`, `AuthMode` (`embedded`, `separate_process`, `separate_process_program`), and `serve_auth_process`. The auth engines run in a process of their own, started from the application's program and reached over its standard input and output; the application process holds no auth key, session, or password hash, and the auth parts of the one commit log stay sealed. The same calls work in both modes, and a database opens in either.
- `auth/LOCK`: the auth files are locked by the process that opens them.

### Changed

- Entity heads are written in format 6 (a flags byte); format 5 still reads. Types are written in format 3 (searchable fields); formats 1 and 2 still read. Log records are written in format 2 (with the commit time); format 1 still reads.
- `translate` records the source revision on every call, not only the first.

## [0.4.1] - 2026-11-08

Second factors, and a read fix.

### Added

- Passkeys (feature `mfa`): `passkey_registration`, `add_passkey`, `passkey_sign_in`, `verify_passkey`, `passkeys`, `remove_passkey`; `RelyingParty`, `PasskeyChallenge`, `PasskeyRegistration`, `PasskeyAssertion`, `PasskeyId`, and `PasskeyInfo`.
- TOTP second factors (feature `mfa`): `add_totp`, `confirm_totp`, `check_totp`, `remove_totp`, `verify_totp`, and `TotpEnrollment`; `SignIn::NeedsSecondFactor` and `Login::NeedsSecondFactor`.

### Changed

- crypt-io 1.5.

### Fixed

- A content read could fail with `Error::Corrupt` while a commit publishing the same entity applied, and could see that commit before it was visible.

## [0.4.0] - 2026-11-08

Content and adapters.

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
- The `metrics` feature: `metrics::Recorder`, an observer that reports into metrics-lib.
- Session listing: `Auth::sessions`, `SessionInfo`, `SessionId`, and `revoke_session`.
- API keys: `create_api_key`, `validate_api_key`, `revoke_api_key`, `ApiKey`, `ApiKeyId`, and `ApiKeyCheck`.
- Recovery codes: `new_recovery_codes`, `use_recovery_code`, and `RecoveryCodes`.
- Named realms and spaces: `Database::define_realm`, `auth_realm`, `set_realm_policy`, `define_space`, `content_space`, and `collections`; `RealmPolicy`, `CollectionInfo`, and `CollectionKind`; `Transaction::auth_realm` and `content_space`.
- `Database::commit_serializable`, and `ContentTx::draft` to read inside a transaction.
- Scheduled publishing: `Action`, `schedule`, `schedule_in`, `cancel_schedule`, `cancel_schedule_in`, and `Entry::scheduled`; a thread of the database fires them.
- Terms: `Value::List`, `FieldType::List` and `FieldType::Terms`, `Type::terms` and `Type::taxonomy`, and `Listing::term`.
- Page tree and authors: `Entity::parent`, `order`, and `author`; `set_parent`, `set_order`, `set_authors`; `Content::children` and `ancestors`; `Entry::parent`, `order`, and `authors`; `Listing::by_author`.
- References: `Type::reference` and `Rule` (`Restrict`, `Detach`, `Cascade`), applied by `delete`; `Content::referenced_by`; `Error::Restricted` (NEX-1010).
- Locales: `Locale`, `SpaceSpec`, `Content::space` and `set_space`, `Entity::locale`, `translate`, `publish_in`, `unpublish_in`, `set_path_in`, `get_in`, `draft_in`; `Entry::locale` and `fallback`; `RouteEntry::locale`; `RevisionInfo::locale`.

### Changed

- A log record holds one section per collection (an engine may now have several); records written before still read.
- A commit that loses to a conflict waits for the winning commit to be visible before it retries.
- Publication times strictly increase within a database, so listings keep publication order when the system clock steps back.
- Entity heads are format 5 (the references of published bodies, authors, parent, order, and schedules); formats 2 to 4 still read.
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

[Unreleased]: https://github.com/jamesgober/nex-db/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/jamesgober/nex-db/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/jamesgober/nex-db/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/nex-db/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/jamesgober/nex-db/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/jamesgober/nex-db/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/nex-db/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/nex-db/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/nex-db/releases/tag/v0.1.0
