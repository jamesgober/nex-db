//! # nex_db
//!
//! An embedded database. Engines run side by side on one core: one commit
//! log, one catalog, and one sequence of commits shared by every engine, so a
//! commit that touches several engines is atomic. Every operation is typed;
//! there is no query string to build or inject.
//!
//! The engines in this version are an auth engine (accounts, password
//! hashing, sessions), whose credentials and session tokens are stored only
//! as hashes and digests, and a content engine (entities and the routes they
//! are served at).
//!
//! ## Tier 1
//!
//! ```no_run
//! # #[cfg(all(feature = "auth", feature = "content"))]
//! # fn main() -> nex_db::Result<()> {
//! use nex_db::{Entity, SessionSpec, SignIn, Validation};
//!
//! let db = nex_db::open("data/site")?;
//!
//! // Sign up: an account (auth) and a profile page (content) in one commit.
//! let password = db.auth().hash_password("correct horse battery staple")?;
//! let account = db.commit(|tx| {
//!     let account = tx.auth().create_account("ann@example.com", &password)?;
//!     tx.content().create(
//!         Entity::new("profile")
//!             .field("account", account)
//!             .field("display_name", "Ann")
//!             .site("example.com")
//!             .path("/u/ann"),
//!     )?;
//!     Ok(account)
//! })?;
//!
//! // Sign in, then check the session on each request.
//! if let SignIn::Success { token, .. } =
//!     db.auth().sign_in("ann@example.com", "correct horse battery staple", SessionSpec::web())?
//! {
//!     assert!(matches!(db.auth().validate(&token)?, Validation::Valid(s) if s.account() == account));
//! }
//!
//! // Serve the profile page.
//! if let Some(route) = db.content().resolve("example.com", "/u/ann")? {
//!     let page = db.content().get(route.entity())?;
//!     # let _ = page;
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(all(feature = "auth", feature = "content")))]
//! # fn main() {}
//! ```
//!
//! ## Guarantees
//!
//! - A commit that returned `Ok` survives a crash of the process at any
//!   point; a commit that did not return never appears in part.
//! - Every state change is applied from the bytes written to the log, by the
//!   same code after a commit and during recovery.
//! - A failed log write or sync stops all further commits; it is never
//!   retried.
//! - A missing key or a damaged log keeps the database closed.
//! - A revoked session never validates again.
//!
//! ## Features
//!
//! | Feature | Default | Enables |
//! |---|---|---|
//! | `auth` | yes | the auth engine |
//! | `content` | yes | the content engine |
//!
//! ## Status
//!
//! Version 0.1: the first working build. The file formats and the API change
//! before 1.0.

#![doc(html_root_url = "https://docs.rs/nex-db")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

#[cfg(feature = "auth")]
mod auth;
#[cfg(feature = "content")]
mod content;
mod core;
mod db;
mod engine;
mod error;
mod ids;

#[cfg(feature = "auth")]
#[cfg_attr(docsrs, doc(cfg(feature = "auth")))]
pub use crate::auth::{
    Auth, AuthTx,
    token::Token,
    types::{HashedPassword, RevokeReason, Session, SessionSpec, SignIn, Validation},
};
#[cfg(feature = "content")]
#[cfg_attr(docsrs, doc(cfg(feature = "content")))]
pub use crate::content::{
    Content, ContentTx,
    entity::{DEFAULT_SITE, Entity, Entry, RouteEntry, RouteKind, Value},
};
pub use crate::{
    db::{Database, Transaction, open},
    error::{Error, Result},
    ids::{AccountId, Rid},
};

// Every Rust example in docs/API.md runs as a doctest.
#[cfg(all(doctest, feature = "auth", feature = "content"))]
#[doc = include_str!("../docs/API.md")]
struct ApiDoc;

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn test_version_has_three_numeric_parts() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.parse::<u64>().is_ok()));
    }

    #[test]
    fn test_version_matches_cargo_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }
}
