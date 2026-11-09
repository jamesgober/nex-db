<h1 align="center">
        <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>nex-db</b><br>
    <sub><sup>API REFERENCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./README.md" title="Documentation"><b>DOCS</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>API</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="./LOG_FORMAT.md" title="Log format"><b>LOG FORMAT</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./FILE_FORMATS.md" title="File formats"><b>FILE FORMATS</b></a>
    </sup>
</div>
<br>

This is the whole public API planned for 1.0, in the order most applications
meet it: the everyday calls first (Tier 1), then configuration and the wider
operations (Tier 2), then the parts few applications need (Tier 3).

Every item carries the version it arrives in. Items marked **0.1** exist now;
their examples are compiled and run as doctests. Later items are shown as
signatures. Their names and shapes were approved on 2026-11-05; changing one
needs a recorded decision.

Grades say how much an item matters: **P0** required, **P1** expected, **P2**
high value, **P3** nice to have. Every P0 and P1 item exists by 0.5.

- [Setup](#setup)
- [Tier 1](#tier-1)
- [The database](#the-database)
- [Transactions](#transactions)
- [The auth engine](#the-auth-engine)
- [The content engine](#the-content-engine)
- [The change feed](#the-change-feed)
- [Health and observers](#health-and-observers)
- [Backup and restore](#backup-and-restore)
- [Read replica](#read-replica)
- [Errors](#errors)
- [Limits](#limits)
- [What the API never offers](#what-the-api-never-offers)
- [Examples in the repository](#examples-in-the-repository)

## Setup

nex-db is not published. Depend on it from its repository:

```toml
[dependencies]
nex-db = { git = "https://github.com/jamesgober/nex-db", tag = "v0.4.1" }
# or pick engines:
# nex-db = { git = "...", tag = "v0.4.1", default-features = false, features = ["auth"] }
```

| Feature | Default | Adds |
|---|---|---|
| `auth` | yes | the auth engine: accounts, passwords, sessions |
| `content` | yes | the content engine: entities, routes |
| `split-auth` (0.5) | no | the auth engine in its own process |
| `metrics` (0.4) | no | an observer that reports into metrics-lib |
| `mfa` (0.4.1) | no | TOTP and passkeys, through crypt-io's AWS-LC backend: needs a C compiler; on Windows x86-64 no NASM |

The core (commit log, catalog, recovery) is always built. A database that uses
an engine the build leaves out refuses to open with `Error::Invalid`.

The minimum supported Rust version is 1.85. nex-db has no async runtime. A
commit blocks until the log sync that covers it; `hash_password`,
`verify_password`, and `sign_in` block for one password hash; a feed read
blocks until the next change. From 0.4 the database runs one thread of its
own (with the `content` feature), which sleeps until a scheduled publish or
unpublish is due; expiry and checkpoints run on the threads that commit.

## Tier 1

Open a database, sign a user up across two engines in one commit, sign in,
validate the session on each request, and resolve a page.

```rust
use nex_db::{Entity, SessionSpec, SignIn, Validation};

# let dir = std::env::temp_dir().join(format!("nex-db-api-tier1-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
let db = nex_db::open(&dir)?; // creates the database on first use

// Sign up: an account (auth) and a profile page (content), both or neither.
let password = db.auth().hash_password("correct horse battery staple")?;
let account = db.commit(|tx| {
    let account = tx.auth().create_account("ann@example.com", &password)?;
    let profile = tx.content().create(
        Entity::new("profile")
            .field("account", account)
            .site("example.com")
            .path("/u/ann"),
    )?;
    tx.content().publish(profile)?; // a new entity is a draft until published
    Ok(account)
})?;

// Sign in: the password is checked inside the auth engine.
let SignIn::Success { token, .. } =
    db.auth().sign_in("ann@example.com", "correct horse battery staple", SessionSpec::web())?
else {
    return Ok(()); // wrong identifier or password: show the sign-in form again
};
// token.as_str() is the cookie value.

// Every signed-in request: validate the cookie.
match db.auth().validate(token.as_str())? {
    Validation::Valid(session) => assert_eq!(session.account(), account),
    _ => { /* not signed in: treat as a guest */ }
}

// Every content request: resolve the path, then read the published entity.
let route = db.content().resolve("example.com", "/u/ann")?.expect("published");
let page = db.content().get(route.entity())?.expect("exists");
assert_eq!(page.field("account").and_then(|v| v.as_account()), Some(account));

db.auth().revoke(token.as_str())?; // sign out
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

| Call | Since | Grade |
|---|---|---|
| `nex_db::open(path) -> Result<Database>` | 0.1 | P0 |
| `db.auth().validate(&token) -> Result<Validation>` | 0.1 | P0 |
| `db.auth().hash_password(password) -> Result<HashedPassword>` | 0.1 | P0 |
| `db.auth().sign_in(identifier, password, spec) -> Result<SignIn>` | 0.1 | P1 |
| `db.auth().revoke(&token) -> Result<bool>` | 0.1 | P0 |
| `db.auth().revoke_all(account) -> Result<u32>` | 0.3 | P0 |
| `db.content().resolve(site, path) -> Result<Option<RouteEntry>>` | 0.1 | P0 |
| `db.content().get(rid) -> Result<Option<Entry>>` | 0.1 | P0 |
| `db.commit(\|tx\| ..) -> Result<T>` | 0.1 | P0 |

`sign_in` checks the password and issues a session in one call; applications
with their own session handling use `verify_password` (0.3) instead.

## The database

### Opening

`nex_db::open(path)` opens the directory, creating a new database when it is
empty. Opening an existing database replays its commit log, so every commit
that returned `Ok` before a crash is back and none that did not return appears
in part. Nothing is served until that has finished.

One process owns a directory at a time. A second `open` of the same directory,
from this process or another, fails with `Error::Locked`.

```rust
# let dir = std::env::temp_dir().join(format!("nex-db-api-open-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
let db = nex_db::open(&dir)?;
assert!(matches!(nex_db::open(&dir), Err(nex_db::Error::Locked)));
assert_eq!(db.path(), dir.as_path());
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

From 0.3 the builder configures what `open` takes by default:

| Builder call | Since | Default |
|---|---|---|
| `Database::builder(dir)` | 0.3 | |
| `.keys(Keys::file(path))`, `Keys::env(var)`, `Keys::in_directory()` | 0.3 | `Keys::in_directory()` |
| `.keys(Keys::vault(name))`: the OS keychain | 0.4 | |
| `.auth(AuthMode::embedded())`, `AuthMode::separate_process()` | 0.3 / 0.5 | embedded |
| `.max_snapshot_age(Duration)` | 0.3 | 60 s |
| `.checkpoint_every(bytes)`: log written between checkpoints, which bound the log and the time an open takes | 0.3 | 64 MiB |
| `.max_sessions(n)`: sessions and revocations held at once; past it `issue_session` fails with `Busy` | 0.3 | 1,000,000 |
| `.commit_queue(n)`, `.hashing_slots(n)` | 0.3 | 4,096; one per CPU |
| `.idempotency_window(Duration)` | 0.3 | 24 hours |
| `.cache(bytes)` | 0.4 | 256 MiB |
| `.observer(impl Observer)` | 0.4 | none |
| `.open() -> Result<Database>` | 0.3 | |

Keys are named, never given in configuration. A key the database needs and
cannot get keeps it closed (`Error::KeyUnavailable`).

Commits never wait for a timer: a commit is written and synced as soon as no
other batch is being written, and commits that arrive meanwhile share the next
sync.

### Collections: realms and spaces

Data lives in collections, each bound to one engine when it is created. Auth
collections are **realms** (one namespace of accounts and sessions); content
collections are **spaces** (one or more sites). A new database has the realm
`users` and the space `site`, which `db.auth()` and `db.content()` use.

| Call | Since | Grade |
|---|---|---|
| `db.auth() -> Auth` (default realm) | 0.1 | P0 |
| `db.content() -> Content` (default space) | 0.1 | P0 |
| `db.define_realm(name, RealmPolicy) -> Result<()>` | 0.4 | P1 |
| `db.auth_realm(name) -> Result<Auth>` | 0.4 | P1 |
| `db.define_space(name, SpaceSpec) -> Result<()>` | 0.4 | P1 |
| `db.content_space(name) -> Result<Content>` | 0.4 | P1 |
| `db.collections() -> Vec<CollectionInfo>` (`name()`, `kind()`: `CollectionKind::Realm`, `Space`) | 0.4 | P2 |
| `db.set_realm_policy(name, RealmPolicy) -> Result<()>` (the default realm is `"users"`) | 0.4 | P1 |
| `tx.auth_realm(name) -> Result<AuthTx>`, `tx.content_space(name) -> Result<ContentTx>` | 0.4 | P1 |

A `RealmPolicy` sets a realm's lockout threshold and window
(`.lockout(failures, window, duration)`, default 10 within 15 minutes, for 15
minutes), absolute and idle session limits (`.max_session(d)`, at most and by
default 400 days; `.max_idle(d)`, none by default; a longer session asked for
is cut to them), and whether new accounts start as `PendingVerification`
(`.pending_verification()`). A changed policy applies to sign-ins and
sessions from then on. A `SpaceSpec` sets a space's default locale and
fallback chains (the settings it starts with; `set_space` changes them).
Each realm has its own accounts, sessions, and keys: a token or identifier of
one realm means nothing in another. One commit may span realms and spaces.
A database holds up to 15 realms and 15 spaces besides the defaults; names
are 1 to 64 ASCII letters, digits, `-`, or `_`.

A collection never changes engine. Dropping one (`db.drop_collection(name)`,
0.5, P2) marks it and reclaims it in the background.

### Reading at one snapshot

Single reads (`validate`, `resolve`, `get`) see the latest committed state. To
read several things as of one moment, use `db.read`:

| Call | Since | Grade |
|---|---|---|
| `db.read(\|r\| ..) -> Result<T>` | 0.3 | P0 |
| `r.auth() -> AuthRead`: `validate(token)` (latest), `standing(account)` | 0.3 | P0 |
| `r.content() -> ContentRead`: `get(rid)`, `resolve(site, path)` | 0.3 | P0 |

Every read inside the closure sees the same commit. A snapshot held longer
than the configured maximum fails with `Error::SnapshotTooOld`, so a forgotten
reader cannot hold memory without limit. Session state is the exception: a
revoked session is revoked for every snapshot at once.

## Transactions

`db.commit(|tx| ..)` runs the closure, then commits everything it staged as
one atomic write across every engine it touched. When `commit` returns `Ok`,
the commit survives a crash.

```rust
use nex_db::{Entity, Error};

# let dir = std::env::temp_dir().join(format!("nex-db-api-tx-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
# let db = nex_db::open(&dir)?;
let password = db.auth().hash_password("pw for bo")?;
db.commit(|tx| {
    let account = tx.auth().create_account("bo@example.com", &password)?;
    let profile =
        tx.content().create(Entity::new("profile").field("account", account).path("/u/bo"))?;
    tx.content().publish(profile)?;
    Ok(())
})?;

// The path is taken: the whole commit is refused, so no account is created.
let again = db.commit(|tx| {
    let account = tx.auth().create_account("bo2@example.com", &password)?;
    tx.content().create(Entity::new("profile").field("account", account).path("/u/bo"))?;
    Ok(())
});
assert!(matches!(again, Err(Error::AlreadyExists { what: "path" })));
assert!(matches!(db.auth().sign_in("bo2@example.com", "pw for bo", nex_db::SessionSpec::web())?, nex_db::SignIn::Failed));
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

Rules:

- Nothing is written until the closure returns `Ok`. An `Err` from the closure
  is returned unchanged and nothing is written.
- Isolation is snapshot isolation: a commit conflicts when a key it writes was
  committed by someone else after it started. On a conflict the closure runs
  again, up to four times in all, then `commit` returns `Error::Conflict`. The
  closure must therefore have no side effects outside `tx`.
- Do slow work (hashing a password) before `commit`, not inside it.
- Return what the commit made (an `AccountId`, a `Token`, a `Rid`) from the
  closure. A value kept from an attempt that was retried never becomes valid.
- The 16 MiB limit is for the whole commit across engines; a larger one is
  refused with `Error::Invalid { field: "commit", .. }`. Split large bodies
  and large releases into several commits.
- From 0.3 `max_snapshot_age` also limits how long a closure may run.
- If the log write or sync fails, the database stops accepting commits
  (`Error::Storage`); reads continue. Restart the process.

| Call | Since | Grade |
|---|---|---|
| `db.commit(\|tx\| ..) -> Result<T>` | 0.1 | P0 |
| `tx.auth() -> AuthTx`, `tx.content() -> ContentTx` | 0.1 | P0 |
| `db.commit_serializable(\|tx\| ..) -> Result<T>` (also checks what the closure read: entities, routes, types and settings, references to an entity, accounts, identifiers, sessions, the roles policy; not listings or other index reads); `tx.content().draft(rid)` reads inside a transaction | 0.4 | P1 |
| `db.commit_with(CommitOptions, \|tx\| ..) -> Result<Committed<T>>` (retries, idempotency key) | 0.3 | P2 |

An idempotency key makes a retried request commit at most once. A commit with
a key already used within the idempotency window (24 hours by default) writes
nothing and returns `Committed::Duplicate { position }`; a new one returns
`Committed::New(value)`.

## The auth engine

The auth engine keeps accounts, password hashes, and sessions. It has typed
operations only: no query, scan, list, or export of credentials, session
tokens, or identifiers exists at any tier. Its files and its parts of the log
are encrypted with its own keys (0.3), and from 0.5 it can run in its own
process.

### Sessions

A session token is 48 characters of URL-safe base64, ready for a cookie. The
plaintext exists once, in the value `issue_session` or `sign_in` returns; the
database keeps only a keyed digest of it, so a copy of the database files
holds no usable token. `Token` shows nothing in `Debug` and is wiped from
memory when dropped.

```rust
use nex_db::{RevokeReason, SessionSpec, Validation};

# let dir = std::env::temp_dir().join(format!("nex-db-api-sessions-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
# let db = nex_db::open(&dir)?;
# let password = db.auth().hash_password("pw")?;
# let account = db.auth().create_account("cy@example.com", &password)?;
let token = db.auth().issue_session(account, SessionSpec::web())?; // 30 days
assert_eq!(format!("{token:?}"), "Token(..)");
assert!(matches!(db.auth().validate(token.as_str())?, Validation::Valid(_)));

assert!(db.auth().revoke(token.as_str())?);
assert_eq!(
    db.auth().validate(token.as_str())?,
    Validation::Revoked { reason: RevokeReason::Revoked }
);
assert_eq!(db.auth().validate("not a token")?, Validation::Malformed);
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

`Validation` (non-exhaustive) is one of:

| Variant | Meaning |
|---|---|
| `Valid(Session)` | a live session; `Session` is a small `Copy` value |
| `Expired` | its absolute lifetime, or (0.3) its idle limit, has passed |
| `Revoked { reason }` | revoked; `RevokeReason` (non-exhaustive): `Revoked`, and from 0.3 `Rotated`, `SignedOutEverywhere`, `Banned`, `Erased` |
| `Unknown` | well formed, but no such session |
| `Malformed` | not a token: wrong length, alphabet, or version |

Every outcome except `Valid` means the caller is a guest. The reason is there
so an application can score suspicious traffic.

`Session` gives `account()`, `created_at()`, `expires_at()`, from 0.3
`idle_limit()`, `recheck_at()`, and `payload() -> &[u8]`, and from 0.4
`device()`. The payload is up to
256 bytes the application stored with the session (permissions, attributes),
opaque to nex-db.

`SessionSpec` builds what `issue_session` stores:

| Call | Since |
|---|---|
| `SessionSpec::web()` (30 days), `SessionSpec::new(ttl)` (up to 400 days) | 0.1 |
| `.idle(Duration)`, `.recheck_after(Duration)`, `.payload(bytes) -> Result<SessionSpec>` (at most 256 bytes) | 0.3 |
| `.device(DeviceId)` | 0.5 (moved from 0.4 with devices) |

| Operation | Since | Grade | Notes |
|---|---|---|---|
| `validate(token) -> Result<Validation>` | 0.1 | P0 | read only |
| `issue_session(account, spec) -> Result<Token>` | 0.1 | P0 | durable |
| `revoke(token) -> Result<bool>` | 0.1 | P0 | takes effect ahead of ordinary commits; `false` when the token names no session or one already revoked |
| `rotate(token) -> Result<Token>` | 0.3 | P0 | the old token becomes `Revoked { Rotated }` |
| `revoke_all(account) -> Result<u32>` | 0.3 | P0 | signs the account out everywhere; returns how many sessions ended |
| `sessions(account) -> Result<Vec<SessionInfo>>` | 0.4 | P2 | newest first; `SessionInfo`: `id()`, `created_at()`, `expires_at()`, `last_used_at()`, `idle_limit()`; never tokens or digests; single-use tokens are not listed |
| `revoke_session(account, SessionId) -> Result<bool>` | 0.4 | P2 | for "sign out that device"; a `SessionId` (32 hex digits as text) is a keyed digest of the session's digest: random to anyone without the keys and no way to the token; also in a transaction |

### Accounts and passwords

```rust
use nex_db::{SessionSpec, SignIn};

# let dir = std::env::temp_dir().join(format!("nex-db-api-accounts-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
# let db = nex_db::open(&dir)?;
let password = db.auth().hash_password("hunter2 hunter2")?;
let account = db.auth().create_account("Dee@Example.com ", &password)?;

// Identifiers are trimmed and compared without case.
assert!(matches!(
    db.auth().sign_in("dee@example.com", "hunter2 hunter2", SessionSpec::web())?,
    SignIn::Success { account: a, .. } if a == account
));
assert!(matches!(
    db.auth().sign_in("dee@example.com", "wrong", SessionSpec::web())?,
    SignIn::Failed
));
assert!(matches!(
    db.auth().create_account("dee@example.com", &password),
    Err(nex_db::Error::AlreadyExists { what: "identifier" })
));
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

Passwords are hashed with Argon2id inside the auth engine; the hash never
leaves it. `HashedPassword` is opaque and wiped on drop. Hashing takes tens of
milliseconds by design, and only as many hashes run at once as there are
hashing slots; past that, `Error::Busy`. An unknown identifier costs the same
work as a wrong password, and both give `SignIn::Failed`, so the outcome does
not reveal which accounts exist.

Identifiers are stored only as keyed digests and cannot be read back: keep the
email address in the application's own profile if it needs to show or send to
it.

| Operation | Since | Grade | Notes |
|---|---|---|---|
| `hash_password(password) -> Result<HashedPassword>` | 0.1 | P0 | before `commit` |
| `create_account(identifier, &HashedPassword) -> Result<AccountId>` | 0.1 | P0 | unique by identifier |
| `sign_in(identifier, password, spec) -> Result<SignIn>` | 0.1 | P0 | check and issue in one call |
| `verify_password(identifier, password) -> Result<Login>` | 0.3 | P1 | check only; ten failures within fifteen minutes lock the account out for fifteen minutes (set per realm from `RealmPolicy`) |
| `account(id) -> Result<Option<Account>>` | 0.4 | P0 | standing, created, roles; never the hash, never identifiers |
| `standing(account) -> Result<Option<Standing>>` | 0.3 | P0 | the read a request makes when a session's `recheck_at` has passed |
| `set_standing(account, Standing, by: Option<AccountId>) -> Result<()>` | 0.3 | P0 | a ban or lock-out ends every session at once; `by` is `None` for an automatic lock-out |
| `set_password(account, &HashedPassword) -> Result<()>` | 0.4 | P1 | ends the account's other sessions |
| `add_identifier(account, identifier)`, `remove_identifier(account, identifier) -> Result<bool>` | 0.4 | P1 | a second email, a username; at most five per account, and never fewer than one |
| `erase_account(account) -> Result<()>` | 0.5 | P2 | destroys the account's key: its data in every copy and backup becomes unreadable |

`SignIn` (non-exhaustive): `Success { account, token }` and `Failed` (0.1);
`LockedOut { until: Option<SystemTime> }` (0.3) and
`NeedsSecondFactor { challenge }` (0.4.1). `LockedOut` covers a lock-out, a
suspension, and a ban; `until` is `None` when only an administrator can lift
it. It is returned only after the password matched. A wrong password on a
locked-out account, or an unknown identifier, gives `Failed` after the same
work, so only someone who knows the password learns the account is locked.

`Login` is `SignIn` without the session: `Verified(AccountId)`, `Failed`,
`LockedOut { until }`, `NeedsSecondFactor { account }` (0.4.1: the password
matched and the account has TOTP on; it is not signed in until
`check_totp` accepts a code).

An account with TOTP on never signs in on its password alone, in any build:
one without the `mfa` feature answers `NeedsSecondFactor` too, and cannot
complete it.

`Standing` (non-exhaustive): `Active`, `PendingVerification`,
`LockedOut { until }`, `Suspended { until: Option<SystemTime>, reason }`,
`Banned { reason }`. A reason is an application-defined `u32` code. A lock-out
or suspension whose `until` has passed reads as `Active`. Who set a standing
is in the audit log. A change of standing that takes access away revokes
every session of the account in the same commit.

### Second factors, tokens, keys, roles (0.4)

| Operation | Grade | Notes |
|---|---|---|
| `add_totp(account) -> Result<TotpEnrollment>`, `confirm_totp(account, code) -> Result<bool>`, `remove_totp(account) -> Result<bool>` (0.4.1, feature `mfa`; also in a transaction) | P1 | a 160-bit secret, sealed; `TotpEnrollment::secret()` (base32) and `uri(issuer, label)` (`otpauth://`, SHA1, six digits, 30 s) shown once; TOTP is on once a code is confirmed |
| `verify_totp(challenge, code, spec) -> Result<SignIn>` (0.4.1, feature `mfa`) | P1 | completes `SignIn::NeedsSecondFactor`: the challenge is a single-use token that lasts five minutes; a wrong code counts toward lock-out and leaves the challenge for another try; a code works once (one step of drift either way) |
| `check_totp(account, code) -> Result<bool>` (0.4.1, feature `mfa`; also in a transaction) | P1 | after `Login::NeedsSecondFactor`, for an application that issues its own sessions |
| `new_recovery_codes(account) -> Result<RecoveryCodes>` (tx) | P1 | ten codes, `xxxxx-xxxxx` (Crockford base32, 50 bits each); replaces any earlier codes; shown once (`codes()`); stored as keyed digests |
| `use_recovery_code(account, code) -> Result<bool>` (tx) | P1 | `true` once per code; dashes, spaces, and case ignored; two uses at once give `true` to one |
| `passkey_registration(account) -> Result<PasskeyChallenge>`, `add_passkey(account, &RelyingParty, &PasskeyRegistration) -> Result<PasskeyId>` (0.4.1, feature `mfa`; also in a transaction) | P2 | the challenge's bytes go to `navigator.credentials.create` (`as_bytes()`, `to_base64url()`), the account's id as the user id; checks the client data (type, challenge, origin, not cross-origin), the RP ID hash, user presence (and verification with `RelyingParty::require_user_verification`), and that the key is `ES256`, `EdDSA`, or `RS256`; attestation is not checked; `PasskeyRegistration::new(client_data_json, authenticator_data)` |
| `passkey_sign_in() -> Result<PasskeyChallenge>`, `verify_passkey(&RelyingParty, &PasskeyAssertion, spec) -> Result<SignIn>` (0.4.1, feature `mfa`) | P2 | a sign-in of its own (no password, no TOTP); the same checks, the signature, and a rising signature counter (an authenticator that keeps it at zero is allowed); `PasskeyAssertion::new(credential_id, client_data_json, authenticator_data, signature)`; challenges work once, within five minutes |
| `passkeys(account) -> Result<Vec<PasskeyInfo>>`, `remove_passkey(account, PasskeyId) -> Result<bool>` (0.4.1, feature `mfa`) | P2 | `PasskeyInfo`: `id()`, `created_at()`, `last_used_at()` |
| `single_use_token(purpose, account, ttl) -> Result<Token>` | P1 | email verification, magic link, preview; `Purpose` (non-exhaustive): `VerifyEmail`, `ResetPassword`, `SignInLink`, `Preview`, `Custom(u16)`; `ttl` at most 30 days; never validates as a session; also in a transaction |
| `single_use_token_for(identifier, purpose, ttl) -> Result<Option<Token>>` | P1 | password reset by email address; the same work whether the identifier exists or not, so answer the same either way |
| `redeem(token, purpose) -> Result<Option<AccountId>>` | P1 | works once, for the purpose it was issued for; two redeems at once give the account to one; also in a transaction |
| `create_api_key(account, scopes: &[&str], expiry: Option<SystemTime>) -> Result<ApiKey>` | P1 | the key text (`as_str()`) is shown once; `id()` to revoke it; at most 32 scopes of 1 to 64 bytes without spaces, stored and returned as given; also in a transaction |
| `validate_api_key(text) -> Result<ApiKeyCheck>`, `revoke_api_key(id) -> Result<bool>` | P1 | `ApiKeyCheck` (non-exhaustive): `Valid { account, id, scopes }`, `Expired`, `Revoked`, `Unknown`, `Malformed`; one read of the account store; a session token is never a key, nor a key a session |
| `define_role(Role) -> Result<RoleId>`, `assign_roles(account, &[RoleId])`, `roles(account)`, `role(id)`, `role_named(name)` | P1 | `Role::new(name).permission(p).inherits(id)`; a role inherits only roles already defined; roles are never removed; at most 256 per realm and 16 per account |
| `allowed(account, permission) -> Result<bool>` | P1 | checks the account's roles against the current policy |
| `link_external(account, provider, subject)`, `find_external(provider, subject)` | P2 | OAuth and OpenID Connect sign-in |
| `devices(account)`, `bind_device_key(account, device, public_key)` | P2 | |

`TotpEnrollment`, `RecoveryCodes`, `ApiKey`, and `Token` show nothing in
`Debug` and are wiped from memory when dropped.

### Audit (0.3)

Every security-relevant write (account created, signed in, failed, locked,
standing changed, revoked) adds an event to the realm's hash-chained audit
log in the same commit. `audit_export(range) -> Result<AuditExport>` (0.8,
P3) returns the events (ids, kinds, and times only) with a proof that none was
changed or removed.

### Transactions

Inside `db.commit`, `tx.auth()` stages:

| Operation | Since |
|---|---|
| `create_account(identifier, &HashedPassword) -> Result<AccountId>` | 0.1 |
| `issue_session(account, spec) -> Result<Token>` | 0.1 |
| `revoke(token) -> Result<bool>` | 0.1 |
| `revoke_all`, `set_standing`, `rotate` | 0.3 |
| `add_identifier`, `remove_identifier`, `define_role` | 0.4 |
| `set_password`, `assign_roles`, `new_recovery_codes`, `use_recovery_code`, `create_api_key`, `revoke_api_key`, `revoke_session` | 0.4 |

A token staged with `tx.auth().issue_session` is valid only once the commit
returns `Ok`.

## The content engine

The content engine keeps a site's entities (pages, posts, profiles, terms,
assets), their revisions and translations, and the routes that point at them.

### Entities

An entity is created from an `Entity` builder and read back as an `Entry`.
Its id, the `Rid`, never changes and is never reused, whatever happens to its
path or locale.

```rust
use nex_db::{Entity, Value};

# let dir = std::env::temp_dir().join(format!("nex-db-api-entities-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
# let db = nex_db::open(&dir)?;
let rid = db.content().create(
    Entity::new("post")
        .field("title", "Hello")
        .field("words", 120)
        .field("draft", false)
        .site("example.com")
        .path("/blog/hello"),
)?;
assert!(db.content().get(rid)?.is_none()); // a draft until published
db.content().publish(rid)?;
let entry = db.content().get(rid)?.expect("published");
assert_eq!(entry.kind(), "post");
assert_eq!(entry.revision(), 1);
assert_eq!(entry.field("title"), Some(&Value::Text("Hello".into())));
assert_eq!(entry.route(), Some(("example.com", "/blog/hello")));
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

`Value` (non-exhaustive): `Text`, `Int`, `Bool`, `Account(AccountId)`,
`Entity(Rid)` (0.1); `List(Vec<Value>)` (0.4: at most 1,000 values, none a
list; `Value::from([rid, ..])` makes a list of references); `Time`, `Float`,
`Bytes`, `Blob(BlobRef)` (0.4, to come). A term is an entity, so a term
value is `Value::Entity` in a list.

`Entry` gives `rid()`, `kind()`, `revision()`, `created_at()`, `route()`,
`field(name)`, `fields()` (0.1), and from 0.4 `locale()`, `fallback()` (the
locale asked for, when another one was served), `status()`, `visibility()`,
`updated_at()`, `published_at()`, `first_published_at()`, `display_date()`,
`created_by()`, `updated_by()`, `published_by()`, `authors()`, `parent()`,
`terms()`, `body() -> &[u8]`, and `alternates()` (every locale with its path).

### Types (0.4)

A space declares its types. Undeclared fields are stored but not indexed.

| Declaration | Meaning |
|---|---|
| `Type::new("post")` | a type; `.singleton()` for one-per-space settings and navigation |
| `.field(name, FieldType)` | `Text`, `Int`, `Float`, `Bool`, `Time`, `Account`, `Entity`, `Terms(taxonomy)`, `Blob`, `List(..)` |
| `.translatable()` | one value per locale |
| `.indexed()`, `.unique()` | listed and filtered; unique within the space |
| `.reference(name, Rule::Restrict \| Rule::Detach \| Rule::Cascade)` | what deleting the target does |
| `.searchable(weight)` | part of the text index, with a weight |
| `.copied_from(reference, field)` | a copy of a field of the entity an `Entity` reference points at, kept current by the engine |
| `.revisions(RevisionPolicy::keep(n) \| keep_for(Duration))` | how many revisions to keep |

`db.content().define(Type) -> Result<()>` (P0), and `type_named(name)` to
read one back. Changing a type adds fields or flags; a redefinition that drops
a field, a kind, or a flag is refused, so stored values always stay readable.

Built so far: `Type::new`, `.singleton()` (a second entity of the type is
`AlreadyExists { what: "singleton" }`), `.field(name, FieldType)` with
`FieldType::Text`, `Int`, `Bool`, `Account`, `Entity`, and `List` (a value
of another kind is refused when saved), `.terms(name, taxonomy)` (a
`FieldType::Terms` field: a list of references to entities of type
`taxonomy`, each checked when added; its rule is `Detach`, so deleting a term
takes it out of the list; `Type::taxonomy(name)` reads it back), and
`.unique()` on the field declared last, not a list (a
second published entity with the same value is
`AlreadyExists { what: "field value" }`; drafts may share it), and
`.reference(name, Rule)` (a `FieldType::Entity` field; `Type::rule(name)`
reads the rule back; a redefinition may change a rule). The other
declarations arrive with what gives them meaning: `Float`, `Time`, and
`Blob` with their values, `.indexed`
with filtered listings, `.translatable` with shared fields, `.searchable`
with search (0.5), `.revisions` with revision pruning.

### Drafts, revisions, and publishing (0.4)

Each entity has one working draft, which saves (and autosaves) over itself
without making revisions. Saving a revision, or publishing, records a fixed
revision with who, when, and a message. Readers of the public site see only
the published revision: `get` and `resolve` read only that, and `draft`
reads the working draft.

```rust
use nex_db::{Entity, Patch};

# let dir = std::env::temp_dir().join(format!("nex-db-api-drafts-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
# let db = nex_db::open(&dir)?;
let rid = db.content().create(Entity::new("post").field("title", "First").path("/p/first"))?;
assert_eq!(db.content().publish(rid)?, 1);

// Edit the draft: readers still see revision 1.
db.content().save_draft(rid, Patch::new().set("title", "Second"))?;
assert_eq!(db.content().get(rid)?.unwrap().field("title").unwrap().as_text(), Some("First"));
assert_eq!(db.content().draft(rid)?.unwrap().field("title").unwrap().as_text(), Some("Second"));

assert_eq!(db.content().publish(rid)?, 2);
assert_eq!(db.content().get(rid)?.unwrap().field("title").unwrap().as_text(), Some("Second"));
assert_eq!(db.content().revisions(rid)?.len(), 2);
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

| Operation (in `tx.content()` unless noted) | Grade | Notes |
|---|---|---|
| `create(Entity) -> Result<Rid>` | P0 | 0.1; starts as a draft from 0.4 |
| `save_draft(rid, Patch) -> Result<()>` | P0 | no revision |
| `save_revision(rid, message) -> Result<u32>` | P0 | |
| `publish(rid) -> Result<u32>` | P0 | publishes the draft; returns the revision (a new one only when the draft changed) in the entity's own locale; `publish_in(rid, locales)` for others |
| `unpublish(rid) -> Result<bool>` | P0 | every locale; the paths stop resolving; drafts and revisions stay; `unpublish_in(rid, locales)` for some |
| `schedule(rid, Action::Publish \| Action::Unpublish, at)` | P1 | fired by the database within moments of `at` (at once when past), in its own commit; `schedule_in(rid, locale, ..)`, `cancel_schedule(rid)`, `cancel_schedule_in`; one schedule per locale, replaced by a new one; `Entry::scheduled()`; a publish takes the draft as it is then; one that cannot run (its path taken) is dropped and reported to the observer; trashing drops them |
| `set_status(rid, Status)`, `set_visibility(rid, Visibility)` | P1 | |
| `trash(rid)`, `restore(rid)`, `delete(rid)` | P1 | `trash` takes every locale down and leaves its paths `Gone` (410); `restore` brings it back as a draft and frees them; `delete` removes the entity and its revisions for good, its paths `Gone` until another entity takes them; with references, `delete` applies their rules |
| `revert(rid, revision)` | P2 | copies an old revision into the draft |
| `db.content().revisions(rid)`, `revision(rid, n)` | P1 | read |

`Status`: `Draft`, `Review`, `Published`, `Archived`, `Trashed`. Workflow
stages beyond these are an application field. `Visibility`: `Public`,
`Members`, `Private`. The application decides who may see `Members` and
`Private` pages; nex-db stores no page password. Publishing is per locale:
each locale has its own published revision and its own schedule.

A **release** publishes or unpublishes many entities at one time, in one
commit: `create_release(name)`, `add_to_release(release, rid, locales,
action)`, `schedule_release(release, at)`, `publish_release(release)` (P2).

### Locales (0.4)

A locale is a `Locale`, a small `Copy` tag such as `fr-CA`
(`Locale::new("fr-CA")?`, `Locale::EN`). Each space has a default locale and
fallback chains (`fr-CA` to `fr`), set with
`db.content().set_space(SpaceSpec::new(en).fallback(fr_ca, &[fr])?)` and read
with `space()`; a space that sets none uses `en`. An entity is written in one
locale (`Entity::locale`, default the space's), and each translation has its
own draft, published revision, and path. A read that finds nothing published
in the locale asked for, or along its chain, gets the entity's own locale.

```rust
use nex_db::{Entity, Locale, Patch, SpaceSpec};

# let dir = std::env::temp_dir().join(format!("nex-db-api-locales-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
# let db = nex_db::open(&dir)?;
let (en, fr) = (Locale::new("en")?, Locale::new("fr")?);
let rid = db.content().create(Entity::new("page").field("title", "Hello").path("/hello"))?;
db.commit(|tx| {
    tx.content().publish(rid)?;
    tx.content().translate(rid, fr, Patch::new().set("title", "Bonjour").path("/fr/bonjour"))?;
    tx.content().publish_in(rid, &[fr])
})?;
let page = db.content().get_in(rid, fr)?.expect("published");
assert_eq!(page.field("title").and_then(|v| v.as_text()), Some("Bonjour"));
let route = db.content().resolve(nex_db::DEFAULT_SITE, "/fr/bonjour")?.expect("routed");
assert_eq!(route.locale(), fr);
assert_eq!(db.content().get(rid)?.expect("published").locale(), en);
# let _ = SpaceSpec::new(en);
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

| Operation | Grade | Notes |
|---|---|---|
| `get(rid) -> Result<Option<Entry>>` | P0 | 0.1; the published revision in the space's default locale (by its chain, then the entity's own), or `None` when nothing is published |
| `draft(rid)`, `draft_in(rid, locale) -> Result<Option<Entry>>` | P0 | the working draft, for editors |
| `get_in(rid, locale) -> Result<Option<Entry>>` | P0 | follows the fallback chain; `Entry::fallback()` says when it did |
| `publish_in(rid, &[Locale])`, `unpublish_in(rid, &[Locale])`, `set_path_in(rid, locale, path)` (tx) | P0 | per locale; `publish`, `unpublish`, and `set_path` act on the entity's own locale (`unpublish`: every locale) |
| `get_many(&[Rid], locale) -> Result<Vec<Option<Entry>>>` | P1 | 0.5; one snapshot, in order, at most 1,000 |
| `translate(rid, locale, Patch)` (tx) | P0 | starts a translation from the entity's own fields (without a path); each call records the published revision of the entity's own locale as the one it was translated from |
| `list(Listing::outdated(locale))` | P1 | 0.5; entities of every type whose translation into `locale` was made from an older revision than their own locale publishes, newest source first; the entries are the translations' drafts, in any status |

Each locale has its own path; all of them point at the same `Rid`.

### Routes

`resolve(site, path)` finds what a path points at. The site is the host name
the application serves; the path is normalized by the application before the
call. Routes are created with entities (`Entity::path`) and change with them.

```rust
use nex_db::{Entity, RouteKind};

# let dir = std::env::temp_dir().join(format!("nex-db-api-routes-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
# let db = nex_db::open(&dir)?;
let rid = db.content().create(Entity::new("page").site("example.com").path("/about"))?;
assert!(db.content().resolve("example.com", "/about")?.is_none()); // drafts are not routed
db.content().publish(rid)?;
let route = db.content().resolve("example.com", "/about")?.expect("routed");
assert_eq!((route.entity(), route.kind(), route.revision()), (rid, RouteKind::Page, 1));

// Moving a published page leaves a 301 at the old path.
db.content().set_path(rid, "/about-us")?;
let old = db.content().resolve("example.com", "/about")?.expect("redirect");
assert_eq!(old.kind(), RouteKind::Redirect { to: rid, status: 301 });
assert_eq!(db.content().get(rid)?.expect("published").route(), Some(("example.com", "/about-us")));
assert!(db.content().resolve("example.com", "/missing")?.is_none());
assert!(db.content().resolve("other.example", "/about")?.is_none());
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

`RouteEntry` is a small `Copy` value: `entity()`, `revision()`, `kind()`
(0.1), and `locale()` (the locale the path serves) and `visibility()` (0.4). `RouteKind` (non-exhaustive):

| Kind | Since | Answer |
|---|---|---|
| `Page` | 0.1 | serve the entity |
| `Redirect { to, status }` | 0.4 | 301, 302, 307, or 308 to the entity `to` (its current path is `get(to)?.route()`) |
| `Gone` | 0.4 | 410 |
| `Alias { canonical }` | 0.4 | serve the entity; link to the canonical path |
| `Term` | 0.4 | a taxonomy archive page |

Changing an entity's path makes the old path a 301 redirect to the new one,
and the paths of its descendants follow. A redirect to a path that later
redirects again is shortened, so a chain is never followed.

| Operation | Grade | Notes |
|---|---|---|
| `resolve(site, path) -> Result<Option<RouteEntry>>` | P0 | 0.1 |
| `set_path(rid, path)`, `set_path_in(rid, locale, path)` (tx) | P0 | the old path redirects with 301 |
| `add_redirect(site, from, to: Rid, status) -> Result<()>` (tx), `remove_route(site, path) -> Result<bool>` (tx) | P1 | 0.5; a redirect to an entity, never over a page; it stays when its target is deleted; `remove_route` takes away a redirect or gone marker, not a page. Redirects to other sites are the application's |
| `routes(rid) -> Result<Vec<(String, String)>>` | P2 | every path of an entity |
| `resolve_draft(site, path) -> Result<Option<RouteEntry>>` | P2 | 0.6; drafts at their real paths, for previews |

Only published entities are routed. `RouteEntry::visibility()` tells the
application when it must check the session before serving a page. For a
preview link, the application redeems a single-use token
(`db.auth().redeem(token, Purpose::Preview)`) and then calls `resolve_draft`;
the content engine never checks auth data itself.

### Page tree and authors (0.4)

An entity has an optional parent and an order among its parent's children,
set with `Entity::parent(rid)` and `Entity::order(i64)`, or later with
`set_parent(rid, Option<Rid>)` and `set_order(rid, i64)` (tx). `children(rid)`
lists the children in any status, lowest order first, ties by record id;
`ancestors(rid)` gives the parent first and the root last. A parent is a
reference that restricts: it cannot be deleted while it has children. A
parent that would make a cycle, or a tree deeper than 64, is `Invalid`. The
paths of descendants do not yet follow a move of their parent.

Authors are an ordered list of up to 16 accounts shared by every locale:
`Entity::author(account)`, `set_authors(rid, &[AccountId])` (tx), and
`Entry::authors()`. The tree and the authors take effect at once, published
or not.

### Taxonomies, references, assets (0.4)

- **Terms:** a term is an entity of its taxonomy's type (`Entity::new("tag")`)
  with its name, path, description, translations, parent, and order like any
  entity, and its own route. A type's `.terms(field, taxonomy)` declares
  the field that holds a post's terms.
- **References:** every `Entity`, `Account`, and `Terms` field is indexed both
  ways in the same commit, so "what links here" is one read. References found
  inside a body, which nex-db never parses, are passed with
  `Entity::references(&[Rid])` and indexed the same way.

  Built so far: `Entity` fields, in drafts and published bodies of every
  locale. Saving a reference to an entity that does not exist is
  `Invalid`. `delete` applies the rule of each referring field:
  `Rule::Restrict` (also the rule of a field none is declared for) refuses
  with `Restricted { what: "entity" }`, `Rule::Detach` removes the field
  (a published body by a new published revision without it), and
  `Rule::Cascade` deletes the referring entity by the same rules, at most
  1,000 entities per delete. A reference added while its target is deleted
  conflicts with the delete, so one of the two commits lands and the other
  retries against it.
- **Assets:** an entity of type `asset` with the media type, size, width,
  height, duration, content hash, focal point, alt text and caption per
  locale, and a list of variants. Media bytes are stored by the application
  (by the blob engine after 1.0); the asset holds a reference to them.

### Listings, search, hierarchy (0.4 to 0.5)

| Operation | Since | Grade |
|---|---|---|
| `list(&Listing) -> Result<Page<Entry>>`, `next_page(&Cursor)` | 0.4 | P0 |
| `Listing::latest(kind)`, `.updated()`, `.site(s)`, `.limit(n)` | 0.4 | P0 |
| `.by_author(a)` | 0.4 | P0 |
| `.term(t)` | 0.4 | P0 |
| `.sticky_first()`: sticky entities (`Entity::sticky()`, `set_sticky(rid, bool)`, `Entry::sticky()`) first, then the others, each in the listing's order | 0.5 | P0 |
| `children(rid) -> Vec<Rid>`, `ancestors(rid) -> Result<Vec<Rid>>` | 0.4 | P1 |
| `referenced_by(rid) -> Result<Vec<Rid>>` | 0.4 | P1 |
| `stream(Listing) -> Stream`, an iterator of `Result<Entry>` reading page by page, for sitemaps and feeds | 0.5 | P1 |
| `search(locale, query) -> Result<Page<Hit>>` | 0.5 | P1 |
| `related(rid, limit)` | 0.5 | P2 |

Listings return pages of at most 1,000 (default 100) with an opaque `Cursor`;
its text form (`to_string()`, `Cursor::parse`) can travel in a URL.
`by_author(a)` keeps the entities `a` is an author of, and `term(t)` those
whose published body refers to `t` (a term in a terms field, or any
reference); one filter at a time, the last one set. Every
listing is answered from an index, never by scanning. `latest` orders by
first publication, newest first; `updated()` by the last publish. Only
published entities are listed.

## The change feed

`db.feed(from: Position) -> Result<Feed>` (0.4, P1) reads committed changes in
order, each with the `Position` of its commit. `Change` (non-exhaustive):
`EntityChanged { rid, revision }` (the published revision after the commit, 0
for none), `RouteChanged { site, path }`, `AccountCreated { account }`,
`SessionRevoked { account: Option<AccountId> }` (one session, or every
session of the account), `StandingChanged { account }`, and
`AccountChanged { account }` (roles, identifiers, or password). Auth changes
carry ids and kinds only.

A `Feed` is an iterator that blocks for the next change; `next_timeout(d)` and
`try_next()` return `None` when nothing came. `db.position()` returns the
position of the last visible commit, to start a feed from now. The feed keeps
the changes of the last 65,536 commits that changed something, since the
database opened; resuming from an older position fails with
`Error::FeedBehind`, and the consumer drops what it built and starts again from
`db.position()`. Typical use: drop cached pages when an entity they were built
from changes. Locales and the paths of an entity join `EntityChanged` with
locales.

```rust
use std::time::Duration;
use nex_db::{Change, Entity};

# let dir = std::env::temp_dir().join(format!("nex-db-api-feed-{}", std::process::id()));
# let _ = std::fs::remove_dir_all(&dir);
# let db = nex_db::open(&dir)?;
let mut feed = db.feed(db.position())?;
let rid = db.content().create(Entity::new("page").path("/hello"))?;
db.content().publish(rid)?;
let mut changed = Vec::new();
while let Some((_, change)) = feed.next_timeout(Duration::from_millis(10))? {
    if let Change::EntityChanged { rid, revision } = change {
        changed.push((rid, revision));
    }
}
assert_eq!(changed, [(rid, 0), (rid, 1)]);
# drop(feed);
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

## Health and observers

| Call | Since | Grade |
|---|---|---|
| `db.health() -> Health` (`Ready`, `Recovering`, `ReadOnly { reason }`) | 0.4 | P1 |
| `Observer` trait: `on_commit(&CommitInfo)` (position, attempts, time taken), `on_error(&Error)`, `on_security_event(&SecurityEvent)`; every method has an empty default; set with `Builder::observer`; not called when none is set | 0.4 | P1 |
| `nex_db::metrics::Recorder` (feature `metrics`): `Recorder::new(&metrics_lib::Registry)`, an `Observer` for `Builder::observer`; counters `nex_db_commits_total`, `nex_db_commit_retries_total`, `nex_db_errors_total { code }`, `nex_db_security_events_total { kind }`, and the timer `nex_db_commit_seconds`; labels carry codes and kinds only | 0.4 | P2 |

Security events (repeated failures, a lock-out, a revoked session presented
again) always reach the observer, with ids and kinds only, never an
identifier; nex-db never keeps one to itself. `SecurityEvent`
(non-exhaustive): `SignInFailed { account: Option<AccountId> }` (`None` for an
identifier no account has), `LockedOut { account }`, `SignInBlocked`, and
`RevokedSessionPresented`. Observers run on the calling thread, so they hand
slow work to another thread. `Recovering` is not seen through this API in
0.4, since `open` returns once recovery is done; it is for split auth.

## Backup and restore

| Call | Since | Grade |
|---|---|---|
| `db.backup(to_dir) -> Result<BackupInfo>` | 0.5 | P1 |
| `nex_db::restore(backup_dir, into_dir, RestorePoint::Latest \| At(SystemTime) \| Position(p))` | 0.5 | P1 |

A backup is taken while the database runs and stays encrypted. Revocations
survive a restore: a session revoked after the restore point stays revoked.

## Read replica

`nex_db::open_replica(dir, source) -> Result<Replica>` (0.8, P1) opens a copy
that follows another database's log and serves reads only: the same read
operations as `db.auth()`, `db.content()`, and `db.read`. Revocations reach it
ahead of ordinary changes.

## Errors

Every fallible call returns `nex_db::Result<T>` with `nex_db::Error`, which is
non-exhaustive. Absence is `Option`, never an error. Each variant has a stable
code and a message that says what to do. No error, `Debug` output, or log line
ever contains a token, password, hash, or key.

| Variant | Code | Since | When | What to do |
|---|---|---|---|---|
| `AlreadyExists { what }` | NEX-1001 | 0.1 | a unique value is taken (`identifier`, `path`, `collection`) | choose another; for a sign-up, answer as if it succeeded |
| `Conflict` | NEX-1002 | 0.1 | retries ran out under contention | retry later |
| `Busy { what }` | NEX-1003 | 0.1 | a bounded resource is full: hashing slots, the session table; from 0.3 the commit queue | back off |
| `Invalid { field, reason }` | NEX-1004 | 0.1 | a value breaks its rule | fix the input |
| `KeyUnavailable` | NEX-1005 | 0.1 | a key cannot be read | restore the key or its source |
| `Locked` | NEX-1006 | 0.1 | another owner holds the directory | stop it, or use another directory |
| `Corrupt { what, at }` | NEX-1007 | 0.1 | stored data failed a check | restore from a backup |
| `Storage { what, source }` | NEX-1008 | 0.1 | the operating system refused, or a write could not be made durable | check the disk; restart |
| `SnapshotTooOld` | NEX-1009 | 0.3 | a `db.read` outlived its limit | read again |
| `Restricted { what }` | NEX-1010 | 0.4 | a reference rule refuses a delete | remove the references first |
| `AuthHalted` | NEX-1011 | 0.7 | the auth engine refuses every call after a security event | an operator resumes it |
| `FeedBehind { oldest }` | NEX-1012 | 0.4 | a change feed was asked for changes older than it keeps | drop what was built from the feed; start again from `db.position()` |

`error.code()` returns the code. `Display` gives the message; `source()` gives
the operating-system error for `Storage`.

## Limits

| Limit | Value |
|---|---|
| one commit | 16 MiB |
| identifier | 320 bytes |
| password | 1,024 bytes |
| sessions per database (0.1) | 1,000,000 |
| session payload (0.3) | 256 bytes |
| session lifetime | 400 days |
| type and field names | 64 bytes |
| site | 253 bytes |
| path | 2,048 bytes |
| fields per entity | 256 |
| one text value | 1 MiB |
| collection name | 64 bytes |
| listing page | 1,000 entries |

From 0.3 every limit that is not part of a format can be set in the builder.

## What the API never offers

- A query language, or any string-built query.
- A scan, list, or export of credentials, session tokens or digests, or
  identifiers.
- Raw key-value access to any engine's data.
- Moving a collection to another engine.
- Opening one directory from two processes.

## Examples in the repository

| Example | Shows |
|---|---|
| `site` | sign up across two engines, sign in, validate, resolve, reopen after a crash |

Run it with `cargo run --example site`.
