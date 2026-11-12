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
//! // Put a page and get it back.
//! let id = db.content().put(Entity::new("page").field("title", "Hello").path("/hello"))?;
//! let page = db.content().get(id)?;
//!
//! // Sign a user up and in.
//! let account = db.auth().sign_up("ann@example.com", "correct horse battery staple")?;
//! let signed_in = db.auth().sign_in("ann@example.com", "correct horse battery staple", SessionSpec::web())?;
//!
//! // On each request: check the session cookie, then find the page at the path.
//! if let SignIn::Success { token, .. } = signed_in {
//!     assert!(matches!(db.auth().validate(&token)?, Validation::Valid(s) if s.account() == account));
//! }
//! if let Some(route) = db.content().resolve(nex_db::DEFAULT_SITE, "/hello")? {
//!     assert_eq!(route.entity(), id);
//! }
//! # let _ = page;
//! # Ok(())
//! # }
//! # #[cfg(not(all(feature = "auth", feature = "content")))]
//! # fn main() {}
//! ```
//!
//! ## One commit across engines
//!
//! ```no_run
//! # #[cfg(all(feature = "auth", feature = "content"))]
//! # fn main() -> nex_db::Result<()> {
//! use nex_db::Entity;
//!
//! let db = nex_db::open("data/site")?;
//!
//! // An account (auth) and its profile page (content): both or neither.
//! let password = db.auth().hash_password("correct horse battery staple")?;
//! db.commit(|tx| {
//!     let account = tx.auth().create_account("ann@example.com", &password)?;
//!     tx.content().put(
//!         Entity::new("profile")
//!             .field("account", account)
//!             .site("example.com")
//!             .path("/u/ann"),
//!     )?;
//!     Ok(())
//! })?;
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
//! | `split-auth` | no | the auth engine in a process of its own (`AuthMode::separate_process`) |
//!
//! ## Status
//!
//! Version 0.8, before 1.0: the file formats and the API may still change,
//! each change recorded in the changelog with how to migrate. The API
//! through 1.0 is in `docs/API.md`.

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
mod backup;
#[cfg(feature = "content")]
mod content;
mod core;
mod db;
mod engine;
mod error;
mod feed;
#[cfg(any(fuzzing, test))]
#[doc(hidden)]
pub mod fuzz;
mod ids;
#[cfg(feature = "auth")]
#[cfg(feature = "metrics")]
#[cfg_attr(docsrs, doc(cfg(feature = "metrics")))]
pub mod metrics;
mod observe;
mod replica;
#[cfg(feature = "auth")]
mod table;
mod wheel;

#[cfg(feature = "split-auth")]
#[cfg_attr(docsrs, doc(cfg(feature = "split-auth")))]
pub use crate::auth::split::serve_auth_process;
#[cfg(feature = "auth")]
#[cfg_attr(docsrs, doc(cfg(feature = "auth")))]
pub use crate::auth::{
    Auth, AuthRead, AuthTx,
    keys::{ApiKey, ApiKeyCheck, ApiKeyId},
    mode::AuthMode,
    realm::RealmPolicy,
    recovery::RecoveryCodes,
    roles::{Account, Role, RoleId},
    token::Token,
    types::{
        HashedPassword, PasswordCheck, Purpose, RevokeReason, Session, SessionId, SessionInfo,
        SessionSpec, SignIn, Standing, Validation,
    },
};
#[cfg(feature = "mfa")]
#[cfg_attr(docsrs, doc(cfg(feature = "mfa")))]
pub use crate::auth::{
    passkey::{
        PasskeyAssertion, PasskeyChallenge, PasskeyId, PasskeyInfo, PasskeyRegistration,
        RelyingParty,
    },
    totp::TotpEnrollment,
};
#[cfg(feature = "content")]
#[cfg_attr(docsrs, doc(cfg(feature = "content")))]
pub use crate::content::{
    Content, ContentRead, ContentTx, Stream,
    entity::{
        Action, DEFAULT_SITE, Entity, Entry, Patch, RevisionInfo, RouteEntry, RouteKind, Status,
        Value, Visibility,
    },
    lists::{Cursor, Listing, Page},
    locale::{Locale, SpaceSpec},
    search::{Hit, Hits, Search},
    types::{FieldType, Rule, Type},
};
#[cfg(feature = "split-auth")]
#[doc(hidden)]
pub use crate::core::keys::root_keys_loaded;
pub use crate::{
    backup::{BackupInfo, RestorePoint, restore},
    core::keys::Keys,
    db::{Builder, CollectionInfo, CollectionKind, Database, Read, Transaction, open},
    error::{Error, Result},
    feed::{Change, Feed, Position},
    ids::{AccountId, EntityId},
    observe::{CommitInfo, Health, Observer, SecurityEvent},
    replica::{Replica, open_replica},
};

#[cfg(feature = "auth")]
#[allow(deprecated)]
#[doc(hidden)]
pub use crate::auth::types::Login;
#[allow(deprecated)]
#[doc(hidden)]
pub use crate::ids::Rid;

// Every Rust example in docs/API.md runs as a doctest.
#[cfg(all(doctest, feature = "auth", feature = "content"))]
#[doc = include_str!("../docs/API.md")]
struct ApiDoc;

// The README's examples compile as doctests.
#[cfg(all(doctest, feature = "auth", feature = "content"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoc;

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
