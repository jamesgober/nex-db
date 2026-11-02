//! A small site on nex-db: sign up, sign in, validate a session, resolve a
//! profile page, and reopen.
//!
//! ```text
//! cargo run --example site                 # run the whole flow
//! cargo run --example site -- --crash      # stop without closing the database
//! cargo run --example site                 # everything from the last run is back
//! cargo run --example site -- <directory>  # use another database directory
//! ```
//!
//! The database lives in the system temporary directory unless a directory
//! is given.

use std::{env, path::PathBuf, process::ExitCode, time::SystemTime};

use nex_db::{Database, Entity, Error, SessionSpec, SignIn, Validation, Value};

const SITE: &str = "example.com";
const EMAIL: &str = "ann@example.com";
const HANDLE: &str = "ann";
const PASSWORD: &str = "correct horse battery staple";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> nex_db::Result<()> {
    let mut crash = false;
    let mut dir = env::temp_dir().join("nex-db-site-example");
    for arg in env::args().skip(1) {
        if arg == "--crash" {
            crash = true;
        } else {
            dir = PathBuf::from(arg);
        }
    }
    let profile_path = format!("/u/{HANDLE}");

    println!("database: {}", dir.display());
    let db = Database::open(&dir)?;

    // Sign up: the account (auth engine) and the profile page (content
    // engine) in one commit. Either both exist afterwards or neither does.
    let password = db.auth().hash_password(PASSWORD)?;
    let signed_up = db.commit(|tx| {
        let account = tx.auth().create_account(EMAIL, &password)?;
        let rid = tx.content().create(
            Entity::new("profile")
                .field("account", account)
                .field("display_name", "Ann")
                .site(SITE)
                .path(profile_path.as_str()),
        )?;
        Ok((account, rid))
    });
    match signed_up {
        Ok((account, rid)) => println!("signed up {EMAIL}: account {account}, profile {rid}"),
        Err(Error::AlreadyExists { .. }) => {
            println!("{EMAIL} is already signed up (from an earlier run)");
        }
        Err(err) => return Err(err),
    }

    // Sign in: the password is checked inside the auth engine.
    let token = match db.auth().sign_in(EMAIL, PASSWORD, SessionSpec::web())? {
        SignIn::Success { account, token } => {
            println!("signed in: account {account}");
            token
        }
        _ => {
            println!("sign-in failed");
            return Ok(());
        }
    };
    match db
        .auth()
        .sign_in(EMAIL, "wrong password", SessionSpec::web())?
    {
        SignIn::Failed => println!("a wrong password fails"),
        _ => println!("unexpected: a wrong password signed in"),
    }

    // Validate the session, as every signed-in request would.
    let session = report_validation(&db, &token)?;

    // Resolve the profile page, as every page request would.
    let rid = report_route(&db, &profile_path)?;

    if crash {
        println!("stopping without closing the database; run again without --crash");
        std::process::exit(0);
    }

    // Reopen: everything is read back from disk.
    drop(db);
    let db = Database::open(&dir)?;
    println!("reopened");
    let again = report_validation(&db, &token)?;
    let rid_again = report_route(&db, &profile_path)?;
    if again == session && rid_again == rid {
        println!("after reopening, the session and the profile are back");
    } else {
        println!("unexpected: state changed across reopening");
    }

    // Sign out: a revoked session never validates again.
    let _ = db.auth().revoke(&token)?;
    println!("signed out: {:?}", db.auth().validate(&token)?);
    Ok(())
}

fn report_validation(
    db: &Database,
    token: &nex_db::Token,
) -> nex_db::Result<Option<nex_db::Session>> {
    let check = db.auth().validate(token)?;
    match check {
        Validation::Valid(session) => {
            let days = session
                .expires_at()
                .duration_since(SystemTime::now())
                .map_or(0, |left| left.as_secs() / 86_400);
            println!(
                "session valid: account {}, expires in {days} days",
                session.account()
            );
        }
        other => println!("session not valid: {other:?}"),
    }
    Ok(check.session())
}

fn report_route(db: &Database, path: &str) -> nex_db::Result<Option<nex_db::Rid>> {
    let Some(route) = db.content().resolve(SITE, path)? else {
        println!("{SITE}{path}: not found");
        return Ok(None);
    };
    let name = db.content().get(route.entity())?.and_then(|entry| {
        entry
            .field("display_name")
            .and_then(Value::as_text)
            .map(str::to_owned)
    });
    println!(
        "{SITE}{path} -> profile {} (revision {}), display name {:?}",
        route.entity(),
        route.revision(),
        name.unwrap_or_default()
    );
    Ok(Some(route.entity()))
}
