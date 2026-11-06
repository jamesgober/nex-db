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
- [Errors](#errors)
- [Limits](#limits)
- [What the API never offers](#what-the-api-never-offers)
- [Examples in the repository](#examples-in-the-repository)

## Setup

nex-db is not published. Depend on it from its repository:

```toml
[dependencies]
nex-db = { git = "https://github.com/jamesgober/nex-db", tag = "v0.2.0" }
# or pick engines:
# nex-db = { git = "...", tag = "v0.2.0", default-features = false, features = ["auth"] }
```

| Feature | Default | Adds |
|---|---|---|
| `auth` | yes | the auth engine: accounts, passwords, sessions |
| `content` | yes | the content engine: entities, routes |
| `split-auth` (0.5) | no | the auth engine in its own process |
| `metrics` (0.4) | no | an observer that reports into metrics-lib |

The core (commit log, catalog, recovery) is always built. A database that uses
an engine the build leaves out refuses to open with `Error::Invalid`.

The minimum supported Rust version is 1.85. nex-db starts no threads of its
own and has no async runtime; every call blocks the calling thread for at most
one log sync (a commit) or one password hash (`hash_password`, `sign_in`).

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
    tx.content().create(
        Entity::new("profile")
            .field("account", account)
            .site("example.com")
            .path("/u/ann"),
    )?;
    Ok(account)
})?;

// Sign in: the password is checked inside the auth engine.
let token = match db.auth().sign_in("ann@example.com", "correct horse battery staple", SessionSpec::web())? {
    SignIn::Success { token, .. } => token, // set token.as_str() as the cookie value
    _ => unreachable!("the password is right"),
};

// Every signed-in request: validate the cookie.
match db.auth().validate(token.as_str())? {
    Validation::Valid(session) => assert_eq!(session.account(), account),
    _ => { /* not signed in: treat as a guest */ }
}

// Every content request: resolve the path, then read the entity.
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
| `Database::builder().path(dir)` | 0.3 | required |
| `.keys(Keys::vault(name))`, `Keys::file(path)`, `Keys::env(var)` | 0.3 | a key file in the directory |
| `.auth(AuthMode::embedded())`, `AuthMode::separate_process()` | 0.3 / 0.5 | embedded |
| `.durability(Durability::GroupCommit { window: Duration })` | 0.3 | 200 µs |
| `.max_snapshot_age(Duration)` | 0.3 | 60 s |
| `.commit_queue(n)`, `.hashing_slots(n)` | 0.3 | 4,096; one per CPU |
| `.cache(bytes)` | 0.4 | 256 MiB |
| `.observer(impl Observer)` | 0.4 | none |
| `.open() -> Result<Database>` | 0.3 | |

Keys are named, never given in configuration. A key the database needs and
cannot get keeps it closed (`Error::KeyUnavailable`).

### Collections: realms and spaces

Data lives in collections, each bound to one engine when it is created. Auth
collections are **realms** (one namespace of accounts and sessions); content
collections are **spaces** (one or more sites). A new database has the realm
`users` and the space `site`, which `db.auth()` and `db.content()` use.

| Call | Since | Grade |
|---|---|---|
| `db.auth() -> Auth` (default realm) | 0.1 | P0 |
| `db.content() -> Content` (default space) | 0.1 | P0 |
| `db.define_realm(name, RealmPolicy) -> Result<()>` | 0.3 | P1 |
| `db.auth_realm(name) -> Result<Auth>` | 0.3 | P1 |
| `db.define_space(name, SpaceSpec) -> Result<()>` | 0.4 | P1 |
| `db.content_space(name) -> Result<Content>` | 0.4 | P1 |
| `db.collections() -> Vec<CollectionInfo>` (names and engines) | 0.4 | P2 |

A collection never changes engine. Dropping one (`db.drop_collection(name)`,
0.5, P2) marks it and reclaims it in the background.

### Reading at one snapshot

Single reads (`validate`, `resolve`, `get`) see the latest committed state. To
read several things as of one moment, use `db.read`:

| Call | Since | Grade |
|---|---|---|
| `db.read(\|r\| ..) -> Result<T>` | 0.3 | P0 |
| `r.auth()`, `r.content()`: the read operations of each engine | 0.3 | P0 |

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
    tx.content().create(Entity::new("profile").field("account", account).path("/u/bo"))?;
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
- A commit larger than 16 MiB is refused with `Error::Invalid`.
- If the log write or sync fails, the database stops accepting commits
  (`Error::Storage`); reads continue. Restart the process.

| Call | Since | Grade |
|---|---|---|
| `db.commit(\|tx\| ..) -> Result<T>` | 0.1 | P0 |
| `tx.auth() -> AuthTx`, `tx.content() -> ContentTx` | 0.1 | P0 |
| `db.commit_serializable(\|tx\| ..) -> Result<T>` (also checks what the closure read) | 0.3 | P1 |
| `db.commit_with(CommitOptions, \|tx\| ..) -> Result<T>` (retries, idempotency key) | 0.3 | P2 |
| `db.begin() -> Result<Transaction>`, `tx.commit() -> Result<()>`, `tx.abort()` | 0.3 | P2 |

An idempotency key makes a retried request commit at most once: a second
commit with a key already used in the last 24 hours returns the first one's
outcome without writing.

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

`Session` gives `account()`, `created_at()`, `expires_at()`, and from 0.3
`idle_limit()`, `recheck_at()`, `device()`, and `payload() -> &[u8]`: up to
256 bytes the application stored with the session (permissions, attributes),
opaque to nex-db.

`SessionSpec` builds what `issue_session` stores:

| Call | Since |
|---|---|
| `SessionSpec::web()` (30 days), `SessionSpec::new(ttl)` (up to 400 days) | 0.1 |
| `.idle(Duration)`, `.payload(bytes)`, `.device(DeviceId)`, `.recheck_after(Duration)` | 0.3 |

| Operation | Since | Grade | Notes |
|---|---|---|---|
| `validate(token) -> Result<Validation>` | 0.1 | P0 | read only |
| `issue_session(account, spec) -> Result<Token>` | 0.1 | P0 | durable |
| `revoke(token) -> Result<bool>` | 0.1 | P0 | takes effect ahead of ordinary commits; `false` when the token named no live session |
| `rotate(token) -> Result<Token>` | 0.3 | P0 | the old token becomes `Revoked { Rotated }` |
| `revoke_all(account) -> Result<u32>` | 0.3 | P0 | signs the account out everywhere; returns how many sessions ended |
| `sessions(account) -> Result<Vec<SessionInfo>>` | 0.4 | P2 | ids, devices, times; never tokens or digests |
| `revoke_session(account, SessionId) -> Result<bool>` | 0.4 | P2 | for "sign out that device" |

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

| Operation | Since | Grade | Notes |
|---|---|---|---|
| `hash_password(password) -> Result<HashedPassword>` | 0.1 | P0 | before `commit` |
| `create_account(identifier, &HashedPassword) -> Result<AccountId>` | 0.1 | P0 | unique by identifier |
| `sign_in(identifier, password, spec) -> Result<SignIn>` | 0.1 | P1 | check and issue in one call |
| `verify_password(identifier, password) -> Result<Login>` | 0.3 | P0 | check only; counts failures |
| `account(id) -> Result<Option<Account>>` | 0.3 | P0 | standing, created, roles; never the hash |
| `standing(account) -> Result<Standing>` | 0.3 | P0 | |
| `set_standing(account, Standing, by: AccountId) -> Result<()>` | 0.3 | P0 | a ban or lock ends every session at once |
| `set_password(account, &HashedPassword) -> Result<()>` | 0.4 | P1 | ends the account's other sessions |
| `add_identifier`, `remove_identifier` | 0.4 | P1 | a second email, a username |
| `erase_account(account) -> Result<()>` | 0.5 | P2 | destroys the account's key: its data in every copy and backup becomes unreadable |

`SignIn` (non-exhaustive): `Success { account, token }` and `Failed` (0.1);
`Locked { until }` and `NeedsSecondFactor { challenge }` (0.3, 0.4). Show the
same message for `Failed` and `Locked` so the reply reveals nothing.

`Login` is `SignIn` without the session: `Verified(AccountId)`, `Failed`,
`Locked { until }`, `NeedsSecondFactor { challenge }`.

`Standing` (non-exhaustive): `Active`, `PendingVerification`,
`Locked { until, reason }`, `Suspended { until, reason, by }`,
`Banned { reason, by }`. A change of standing that takes access away revokes
every session of the account in the same commit.

### Second factors, tokens, keys, roles (0.4)

| Operation | Grade | Notes |
|---|---|---|
| `add_totp(account) -> Result<TotpEnrollment>`, `confirm_totp(account, code)` | P1 | the secret is sealed; codes are single-use |
| `verify_totp(challenge, code) -> Result<SignIn>` | P1 | completes `NeedsSecondFactor` |
| `recovery_codes(account) -> Result<Vec<String>>` | P1 | shown once; stored hashed |
| `add_passkey`, `verify_passkey` | P2 | WebAuthn public keys and counters |
| `single_use_token(purpose, account, ttl) -> Result<Token>` | P1 | email verification, password reset, magic link |
| `redeem(token, purpose) -> Result<Option<AccountId>>` | P1 | works once |
| `api_key_create(account, scopes, expiry) -> Result<ApiKey>` | P1 | the key text is shown once |
| `api_key_check(text) -> Result<ApiKeyCheck>`, `api_key_revoke(id)` | P1 | |
| `define_role(Role)`, `assign_roles(account, &[RoleId])`, `roles(account)` | P1 | |
| `link_external(account, provider, subject)`, `find_external(provider, subject)` | P2 | OAuth and OpenID Connect sign-in |
| `devices(account)`, `bind_device_key(account, device, public_key)` | P2 | |

### Audit (0.3)

Every security-relevant write (account created, signed in, failed, locked,
standing changed, revoked) adds an event to the realm's hash-chained audit
log in the same commit. `audit_export(range) -> Result<AuditExport>` (0.8,
P3) returns the events with a proof that none was changed or removed.

### Transactions

Inside `db.commit`, `tx.auth()` stages:

| Operation | Since |
|---|---|
| `create_account(identifier, &HashedPassword) -> Result<AccountId>` | 0.1 |
| `issue_session(account, spec) -> Result<Token>` | 0.1 |
| `revoke(token) -> Result<bool>` | 0.1 |
| `revoke_all`, `set_standing`, `rotate` | 0.3 |
| `set_password`, `add_identifier`, `remove_identifier`, `assign_roles` | 0.4 |

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
let entry = db.content().get(rid)?.expect("created");
assert_eq!(entry.kind(), "post");
assert_eq!(entry.revision(), 1);
assert_eq!(entry.field("title"), Some(&Value::Text("Hello".into())));
assert_eq!(entry.route(), Some(("example.com", "/blog/hello")));
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

`Value` (non-exhaustive): `Text`, `Int`, `Bool`, `Account(AccountId)`,
`Entity(Rid)` (0.1); `Time`, `Float`, `Bytes`, `Term(TermId)`, `List(..)`,
`Blob(BlobRef)` (0.4).

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
| `.copied_from(reference, field)` | a copy of a referenced entity's field, kept current by the engine |
| `.revisions(RevisionPolicy::keep(n) \| keep_for(Duration))` | how many revisions to keep |

`db.content().define(Type) -> Result<()>` (P0). Changing a type adds fields
or flags; removing one keeps the stored values readable.

### Drafts, revisions, and publishing (0.4)

Each entity has one working draft, which saves (and autosaves) over itself
without making revisions. Saving a revision, or publishing, records a fixed
revision with who, when, and a message. Readers of the public site see only
the published revision.

| Operation (in `tx.content()` unless noted) | Grade | Notes |
|---|---|---|
| `create(Entity) -> Result<Rid>` | P0 | 0.1; starts as a draft from 0.4 |
| `save_draft(rid, Patch) -> Result<()>` | P0 | no revision |
| `save_revision(rid, message) -> Result<u32>` | P0 | |
| `publish(rid, locales) -> Result<u32>` | P0 | publishes the draft; returns the revision |
| `unpublish(rid, locales)` | P0 | |
| `schedule(rid, Action::Publish \| Action::Unpublish, at)` | P1 | fired by the database at `at` |
| `set_status(rid, Status)`, `set_visibility(rid, Visibility)` | P1 | |
| `trash(rid)`, `restore(rid)`, `delete(rid)` | P1 | `delete` applies the reference rules |
| `revert(rid, revision)` | P2 | copies an old revision into the draft |
| `db.content().revisions(rid)`, `revision(rid, n)` | P1 | read |

`Status`: `Draft`, `Review`, `Published`, `Archived`, `Trashed`. Workflow
stages beyond these are an application field. `Visibility`: `Public`,
`Members`, `Password(..)`, `Private`. Publishing is per locale: each locale
has its own published revision and its own schedule.

A **release** publishes or unpublishes many entities at one time, in one
commit: `release(name)`, `release_add(release, rid, locales, action)`,
`release_schedule(release, at)`, `release_publish(release)` (P2).

### Locales (0.4)

A locale is a `Locale`, a small `Copy` tag such as `fr-CA`. Each space has a
default locale and fallback chains (`fr-CA` to `fr` to `en`).

| Operation | Grade | Notes |
|---|---|---|
| `get(rid) -> Result<Option<Entry>>` | P0 | 0.1; the space's default locale |
| `get_in(rid, locale) -> Result<Option<Entry>>` | P0 | follows the fallback chain; `Entry::fallback()` says when it did |
| `get_many(&[Rid], locale) -> Result<Vec<Option<Entry>>>` | P1 | one snapshot |
| `translate(rid, locale, Patch)` (tx) | P0 | records the source revision it was translated from |
| `list(Listing::outdated(locale))` | P1 | translations older than their source |

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
let route = db.content().resolve("example.com", "/about")?.expect("routed");
assert_eq!((route.entity(), route.kind(), route.revision()), (rid, RouteKind::Page, 1));
assert!(db.content().resolve("example.com", "/missing")?.is_none());
assert!(db.content().resolve("other.example", "/about")?.is_none());
# drop(db);
# std::fs::remove_dir_all(&dir).unwrap();
# Ok::<(), nex_db::Error>(())
```

`RouteEntry` is a small `Copy` value: `entity()`, `revision()`, `kind()`
(0.1), and `locale()` (0.4). `RouteKind` (non-exhaustive):

| Kind | Since | Answer |
|---|---|---|
| `Page` | 0.1 | serve the entity |
| `Redirect { to, status }` | 0.4 | 301, 302, 307, or 308 to another route or to a URL |
| `Gone` | 0.4 | 410 |
| `Alias { canonical }` | 0.4 | serve the entity; link to the canonical path |
| `Term` | 0.4 | a taxonomy archive page |

Changing an entity's path makes the old path a 301 redirect to the new one,
and the paths of its descendants follow. A redirect to a path that later
redirects again is shortened, so a chain is never followed.

| Operation | Grade | Notes |
|---|---|---|
| `resolve(site, path) -> Result<Option<RouteEntry>>` | P0 | 0.1 |
| `set_path(rid, locale, path)` (tx) | P0 | the old path redirects |
| `add_redirect(site, from, to, status)` (tx), `remove_route(site, path)` (tx) | P1 | |
| `routes(rid) -> Result<Vec<(String, String)>>` | P2 | every path of an entity |
| `preview(token, site, path) -> Result<Option<RouteEntry>>` | P2 | 0.6; drafts at their real paths |

Only published, public entities are in the routes `resolve` reads. Drafts are
reached through `preview` with a single-use token from the auth engine.

### Taxonomies, references, assets (0.4)

- **Terms:** `create_term(taxonomy, Term)` with a name, path, and description
  per locale, a parent, and an order. A term has its own route.
- **References:** every `Entity`, `Account`, and `Terms` field is indexed both
  ways in the same commit, so "what links here" is one read. References found
  inside a body, which nex-db never parses, are passed with
  `Entity::references(&[Rid])` and indexed the same way.
- **Assets:** an entity of type `asset` with the media type, size, width,
  height, duration, content hash, focal point, alt text and caption per
  locale, and a list of variants. Media bytes are stored by the application
  (by the blob engine after 1.0); the asset holds a reference to them.

### Listings, search, hierarchy (0.4 to 0.5)

| Operation | Since | Grade |
|---|---|---|
| `list(Listing) -> Result<Page<Entry>>`, `next_page(cursor)` | 0.4 | P0 |
| `Listing::latest(kind)`, `.term(t)`, `.by_author(a)`, `.updated()`, `.sticky_first()`, `.site(s)`, `.limit(n)` | 0.4 | P0 |
| `children(rid)`, `ancestors(rid)` | 0.4 | P1 |
| `referenced_by(rid)` | 0.4 | P1 |
| `stream(Listing)` for sitemaps and feeds | 0.4 | P1 |
| `search(locale, query) -> Result<Page<Hit>>` | 0.5 | P1 |
| `related(rid, limit)` | 0.5 | P2 |

Listings return pages of at most 1,000 (default 100) with an opaque cursor.
Every listing is answered from an index, never by scanning.

## The change feed

`db.feed(from: Position) -> Result<Feed>` (0.4, P1) reads committed changes in
order: `EntityChanged { rid, locales, revision, paths }`, `RouteChanged`,
`AccountCreated { account }`, `SessionRevoked { account }`,
`StandingChanged { account }`. Auth events carry ids and kinds only. A feed is
an iterator that blocks for the next change; a consumer that falls behind its
bound is cut off and resumes from its last `Position`. Typical use: drop
cached pages when an entity they were built from changes.

## Health and observers

| Call | Since | Grade |
|---|---|---|
| `db.health() -> Health` (`Ready`, `Recovering`, `ReadOnly { reason }`) | 0.4 | P1 |
| `Observer` trait: `on_commit`, `on_error`, `on_security_event`; no cost when none is set | 0.4 | P1 |
| `nex_db::metrics::Recorder` (feature `metrics`) | 0.4 | P2 |

Security events (repeated failures, a lockout, a revoked session presented
again) always reach the observer; nex-db never keeps one to itself.

## Backup and restore

| Call | Since | Grade |
|---|---|---|
| `db.backup(to_dir) -> Result<BackupInfo>` | 0.5 | P1 |
| `nex_db::restore(backup_dir, into_dir, RestorePoint::Latest \| At(SystemTime) \| Position(p))` | 0.5 | P1 |

A backup is taken while the database runs and stays encrypted. Revocations
survive a restore: a session revoked after the restore point stays revoked.

## Errors

Every fallible call returns `nex_db::Result<T>` with `nex_db::Error`, which is
non-exhaustive. Absence is `Option`, never an error. Each variant has a stable
code and a message that says what to do. No error, `Debug` output, or log line
ever contains a token, password, hash, or key.

| Variant | Code | Since | When | What to do |
|---|---|---|---|---|
| `AlreadyExists { what }` | NEX-1001 | 0.1 | a unique value is taken (`identifier`, `path`, `collection`) | choose another; for a sign-up, answer as if it succeeded |
| `Conflict` | NEX-1002 | 0.1 | retries ran out under contention | retry later |
| `Busy { what }` | NEX-1003 | 0.1 | a bounded resource is full (hashing slots; from 0.3 the commit queue) | back off |
| `Invalid { field, reason }` | NEX-1004 | 0.1 | a value breaks its rule | fix the input |
| `KeyUnavailable` | NEX-1005 | 0.1 | a key cannot be read | restore the key or its source |
| `Locked` | NEX-1006 | 0.1 | another owner holds the directory | stop it, or use another directory |
| `Corrupt { what, at }` | NEX-1007 | 0.1 | stored data failed a check | restore from a backup |
| `Storage { what, source }` | NEX-1008 | 0.1 | the operating system refused, or a write could not be made durable | check the disk; restart |
| `SnapshotTooOld` | NEX-1009 | 0.3 | a `db.read` outlived its limit | read again |
| `Restricted { what }` | NEX-1010 | 0.4 | a reference rule refuses a delete | remove the references first |
| `Sealed` | NEX-1011 | 0.7 | the auth engine was sealed after a security event | an operator unseals it |

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
