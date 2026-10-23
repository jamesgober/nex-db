//! # nex_db
//!
//! An embedded database. Engines run side by side on one core: one commit
//! log, one catalog, and one read snapshot shared by every engine, so a
//! commit that touches several engines is atomic. Every operation is typed;
//! there is no query string to build or inject.
//!
//! The first engines are an auth engine (sessions, credentials, tokens,
//! roles), kept sealed under its own keys and files, and a content engine
//! (pages, translations, routes).
//!
//! ## Tier 1
//!
//! ```
//! println!("nex-db {}", nex_db::VERSION);
//! ```
//!
//! The Tier 1 entry points arrive with the first engines:
//!
//! ```text
//! let db = nex_db::open("data/site")?;
//! let check = db.auth().validate(&token)?;
//! let route = db.content().resolve("example.com", "/blog/hello")?;
//! let account = db.commit(|tx| { /* typed operations on several engines */ })?;
//! ```
//!
//! ## Status
//!
//! Scaffold. No functional code yet.

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
        clippy::dbg_macro
    )
)]

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
