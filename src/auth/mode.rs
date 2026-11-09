//! Where the auth engine runs.

/// Where the auth engine runs: in the application's process (the default),
/// or, with the `split-auth` feature, in a process of its own. Give it to
/// [`Builder::auth`](crate::Builder::auth).
///
/// ```
/// let mode = nex_db::AuthMode::embedded();
/// assert_eq!(mode, nex_db::AuthMode::default());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthMode(pub(crate) Mode);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Mode {
    #[default]
    Embedded,
    /// The program to start, or the running one.
    #[cfg(feature = "split-auth")]
    Separate(Option<std::path::PathBuf>),
}

impl AuthMode {
    /// The auth engine in this process. The default.
    #[must_use]
    pub const fn embedded() -> AuthMode {
        AuthMode(Mode::Embedded)
    }

    /// The auth engine in a process of its own, started from the running
    /// program: the application process then holds no auth key, no session,
    /// and no password hash, and reaches them over a pipe to that process.
    /// The program's `main` must call
    /// [`serve_auth_process`](crate::serve_auth_process) before anything
    /// else. Calls are the same as in the embedded mode, and a database
    /// opens in either mode.
    #[cfg(feature = "split-auth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "split-auth")))]
    #[must_use]
    pub const fn separate_process() -> AuthMode {
        AuthMode(Mode::Separate(None))
    }

    /// As [`separate_process`](Self::separate_process), started from
    /// `program` instead of the running program. Its `main` calls
    /// [`serve_auth_process`](crate::serve_auth_process) the same way.
    #[cfg(feature = "split-auth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "split-auth")))]
    #[must_use]
    pub fn separate_process_program(program: impl Into<std::path::PathBuf>) -> AuthMode {
        AuthMode(Mode::Separate(Some(program.into())))
    }
}
