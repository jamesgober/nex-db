<h1 align="center">
    <b>nex-db</b>
    <br>
    <sub><sup>EMBEDDED DATABASE</sup></sub>
</h1>

<div align="center">
    <a href="https://github.com/jamesgober/nex-db/actions"><img alt="CI" src="https://github.com/jamesgober/nex-db/actions/workflows/ci.yml/badge.svg"></a>
</div>

<br>

**nex-db** is an embedded database for Rust. Engines run side by side on one core: one commit log, one catalog, and one sequence of commits shared by every engine, so a commit that touches several engines is atomic. Every operation is typed; there is no query string to build or inject.

The engines in this version are an auth engine (accounts, password hashing, sessions), which stores tokens and identifiers only as keyed digests and passwords only as Argon2id hashes, and a content engine (entities and the routes they are served at).

MSRV is 1.85 (Rust 2024 edition). `#![forbid(unsafe_code)]`.

## Example

```rust,no_run
use nex_db::{Entity, SessionSpec, SignIn, Validation};

fn main() -> nex_db::Result<()> {
    let db = nex_db::open("data/site")?;

    // Sign up: an account and a profile page in one commit.
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

    // Sign in, and check the session on each request.
    if let SignIn::Success { token, .. } =
        db.auth().sign_in("ann@example.com", "correct horse battery staple", SessionSpec::web())?
    {
        assert!(matches!(db.auth().validate(&token)?, Validation::Valid(s) if s.account() == account));
    }

    // Serve the profile page.
    if let Some(route) = db.content().resolve("example.com", "/u/ann")? {
        let _page = db.content().get(route.entity())?;
    }
    Ok(())
}
```

`examples/site.rs` runs the same flow, reopens the database, and can stop without closing it to show that everything comes back:

```text
cargo run --example site
cargo run --example site -- --crash
cargo run --example site
```

## Guarantees

- A commit that returned `Ok` survives a crash of the process at any point; a commit that did not return never appears in part. `tests/kill.rs` kills a writing process at random points and checks every reopen.
- Every state change is applied from the bytes written to the log, by the same code after a commit and during recovery.
- A failed log write or sync stops all further commits; it is never retried.
- A missing key file or a damaged log keeps the database closed. Only an unfinished last record, which never returned `Ok`, is cut.
- A revoked session never validates again.

## Status

Version 0.3: the core and the auth engine. The API through 1.0 is in [`docs/API.md`](./docs/API.md); file formats and the API may still change before 1.0, each change recorded in the plan. The plan is in [`dev/PLAN.md`](./dev/PLAN.md) and the schedule in [`dev/ROADMAP.md`](./dev/ROADMAP.md).

## Documentation

- [`docs/API.md`](./docs/API.md): the public API through 1.0, with the version each item arrives in.
- [`docs/LOG_FORMAT.md`](./docs/LOG_FORMAT.md): the bytes of a commit log record.
- [`docs/FILE_FORMATS.md`](./docs/FILE_FORMATS.md): the database directory and its files.

## License

Licensed under either of

- Apache License, Version 2.0: [LICENSE-APACHE](./LICENSE-APACHE)
- MIT License: [LICENSE-MIT](./LICENSE-MIT)

at your option.

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
