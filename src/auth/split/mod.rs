//! Split auth: the auth engines in a process of their own.
//!
//! The application process keeps the core (the one commit log, the
//! catalog, snapshots) and the other engines. The auth process holds every
//! auth key and all auth state: it loads the root key itself, opens the
//! realms' stores, and seals and opens the auth sections of the log. The
//! application stores and replays those sections as ciphertext, so a
//! commit that touches auth and content is still one record of one log.
//!
//! The application starts the auth process from its own program (see
//! [`serve_auth_process`]) and talks to it over the child's standard input
//! and output: nothing else can connect to that pipe. On the application's
//! side, [`RemoteAuth`] stands in for each realm's engine (the core calls
//! it as it calls any engine) and [`RemoteStaged`] for a transaction's auth
//! part, which lives in the auth process until the commit attempt ends.
//!
//! The auth process going away, or a malformed frame, fails closed: every
//! auth call returns [`Error::Storage`] and the database stops writes, as
//! after a failed log sync.

mod channel;
mod child;
mod remote;
mod wire;

use std::sync::Weak;

pub(crate) use self::{
    channel::Channel,
    remote::{RemoteAuth, RemoteStaged},
};
use crate::error::Result;

/// The environment variable that makes a program the auth process.
pub(crate) const ENV: &str = "NEX_DB_AUTH_PROCESS";

/// Message kinds. Each request names its realm (collection) first, except
/// the hello and the password hashing, which are the process's.
pub(crate) mod op {
    pub(crate) const HELLO: u16 = 1;
    pub(crate) const HOST: u16 = 2;
    pub(crate) const APPLY: u16 = 3;
    pub(crate) const DURABLE: u16 = 4;
    pub(crate) const CHECKPOINT: u16 = 5;
    /// No response.
    pub(crate) const RECLAIM: u16 = 6;
    pub(crate) const BACKUP: u16 = 7;

    pub(crate) const VALIDATE: u16 = 10;
    pub(crate) const HASH: u16 = 11;
    /// No response.
    pub(crate) const FORGET_HASH: u16 = 12;
    pub(crate) const CHECK: u16 = 13;
    pub(crate) const CLEAR_FAILURES: u16 = 14;
    pub(crate) const COUNT_FAILURE: u16 = 15;
    pub(crate) const NEEDS_SECOND_FACTOR: u16 = 16;
    pub(crate) const ACCOUNT_VIEW: u16 = 17;
    pub(crate) const ACCOUNT_NAMED: u16 = 18;
    pub(crate) const SESSIONS: u16 = 19;
    pub(crate) const API_KEY_CHECK: u16 = 20;
    #[cfg(feature = "mfa")]
    pub(crate) const PASSKEYS: u16 = 21;
    pub(crate) const POLICY: u16 = 22;

    pub(crate) const TX_VALIDATE_READS: u16 = 40;
    pub(crate) const TX_SEAL: u16 = 41;
    /// No response.
    pub(crate) const TX_RELEASE: u16 = 42;

    /// Transaction operations: one per [`AuthTx`](crate::AuthTx) method.
    pub(crate) const CREATE_ACCOUNT: u16 = 50;
    pub(crate) const ISSUE_SESSION: u16 = 51;
    pub(crate) const SINGLE_USE_TOKEN: u16 = 52;
    pub(crate) const STAGE_SINGLE_USE: u16 = 53;
    pub(crate) const STAGE_CHALLENGE: u16 = 54;
    pub(crate) const REDEEM: u16 = 55;
    pub(crate) const REVOKE_ALL: u16 = 56;
    pub(crate) const ROTATE: u16 = 57;
    pub(crate) const SET_STANDING: u16 = 58;
    pub(crate) const ERASE_ACCOUNT: u16 = 59;
    pub(crate) const REAPPLY: u16 = 60;
    pub(crate) const SET_PASSWORD: u16 = 61;
    pub(crate) const ADD_IDENTIFIER: u16 = 62;
    pub(crate) const REMOVE_IDENTIFIER: u16 = 63;
    pub(crate) const DEFINE_ROLE: u16 = 64;
    pub(crate) const ASSIGN_ROLES: u16 = 65;
    pub(crate) const LOCK_OUT: u16 = 66;
    pub(crate) const NEW_RECOVERY_CODES: u16 = 67;
    pub(crate) const USE_RECOVERY_CODE: u16 = 68;
    pub(crate) const CREATE_API_KEY: u16 = 69;
    pub(crate) const REVOKE_API_KEY: u16 = 70;
    pub(crate) const REVOKE_SESSION: u16 = 71;
    pub(crate) const REVOKE: u16 = 72;
    #[cfg(feature = "mfa")]
    pub(crate) const ADD_TOTP: u16 = 80;
    #[cfg(feature = "mfa")]
    pub(crate) const CONFIRM_TOTP: u16 = 81;
    #[cfg(feature = "mfa")]
    pub(crate) const CHECK_TOTP: u16 = 82;
    #[cfg(feature = "mfa")]
    pub(crate) const REMOVE_TOTP: u16 = 83;
    #[cfg(feature = "mfa")]
    pub(crate) const PASSKEY_REGISTRATION: u16 = 84;
    #[cfg(feature = "mfa")]
    pub(crate) const PASSKEY_SIGN_IN: u16 = 85;
    #[cfg(feature = "mfa")]
    pub(crate) const ADD_PASSKEY: u16 = 86;
    #[cfg(feature = "mfa")]
    pub(crate) const REMOVE_PASSKEY: u16 = 87;
    #[cfg(feature = "mfa")]
    pub(crate) const COMPLETE_PASSKEY: u16 = 88;
    #[cfg(feature = "mfa")]
    pub(crate) const COMPLETE_SECOND_FACTOR: u16 = 89;

    /// True for a transaction operation.
    pub(crate) fn is_tx(op: u16) -> bool {
        (50..100).contains(&op)
    }
}

/// A password hash the auth process holds, named by a random handle. The
/// auth process forgets it when this is dropped, and after ten minutes in
/// any case.
pub(crate) struct HashHandle {
    pub(crate) id: [u8; 16],
    pub(crate) channel: Weak<Channel>,
}

impl Drop for HashHandle {
    fn drop(&mut self) {
        if let Some(channel) = self.channel.upgrade() {
            let id = self.id;
            channel.send(op::FORGET_HASH, |w| {
                w.bytes(&id);
                Ok(())
            });
        }
    }
}

/// Start the auth process for the database in `dir` and open its default
/// realm: it loads the root key from `keys` itself.
pub(crate) fn start(
    program: Option<&std::path::Path>,
    dir: &std::path::Path,
    keys: &crate::core::keys::Keys,
    new_database: bool,
    max_sessions: usize,
) -> Result<std::sync::Arc<Channel>> {
    let dir = remote::utf8(dir)?;
    let (kind, name) = keys.wire()?;
    Channel::start(program, |w| {
        wire::put_str(w, dir)?;
        w.u8(kind);
        if let Some(name) = name {
            wire::put_str(w, name)?;
        }
        wire::put_bool(w, new_database);
        w.u64(max_sessions as u64);
        Ok(())
    })
}

/// Serve as the auth process when this process was started as one; call it
/// first thing in `main`.
///
/// A database opened with
/// [`AuthMode::separate_process`](crate::AuthMode::separate_process) starts
/// the running program again as its auth process. In that process this
/// call serves the database's auth engines until the database closes (or
/// its process ends), then returns `Ok(true)`: `main` should then return.
/// In any other process it returns `Ok(false)` at once and does nothing.
///
/// ```no_run
/// fn main() -> nex_db::Result<()> {
///     if nex_db::serve_auth_process()? {
///         return Ok(());
///     }
///     let db = nex_db::Database::builder("data/site")
///         .auth(nex_db::AuthMode::separate_process())
///         .open()?;
///     # let _ = db;
///     Ok(())
/// }
/// ```
///
/// # Errors
///
/// [`Error::Storage`](crate::Error::Storage) when the channel to the
/// application fails before the database is opened. Errors after that are
/// the application's to see.
pub fn serve_auth_process() -> Result<bool> {
    if std::env::var_os(ENV).is_none() {
        return Ok(false);
    }
    child::serve()?;
    Ok(true)
}
