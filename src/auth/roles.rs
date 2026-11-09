//! Roles, the realm's policy, and the account view.
//!
//! A role is a name, a set of permission names, and the roles it inherits.
//! The policy is every role of the realm, kept in memory and replaced as a
//! whole on each change (it is small: at most [`MAX_ROLES`] roles). An
//! account holds role ids; [`Policy::allows`] resolves inheritance.

use std::{collections::HashSet, fmt, time::SystemTime};

use super::types::Standing;
use crate::{
    core::{
        codec::{Reader, Writer},
        record::Seq,
    },
    error::{Error, Result},
    ids::AccountId,
};

/// Most roles a realm defines.
pub(crate) const MAX_ROLES: usize = 256;
/// Most permissions one role grants directly.
const MAX_PERMISSIONS: usize = 64;
/// Most roles one role inherits, and one account holds.
pub(crate) const MAX_ROLES_PER: usize = 64;
/// Longest role or permission name, in bytes.
const MAX_NAME: usize = 64;
/// Format of the stored policy.
const POLICY_FORMAT: u8 = 1;

/// A role's id within its realm, given by [`define_role`](crate::Auth::define_role).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleId(pub(crate) u32);

impl RoleId {
    /// The id as a number, for storing in the application's own records.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// A role id from [`get`](Self::get).
    #[must_use]
    pub const fn from_u32(id: u32) -> RoleId {
        RoleId(id)
    }
}

impl fmt::Display for RoleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A role: a name, the permissions it grants, and the roles it inherits.
///
/// ```
/// use nex_db::Role;
///
/// let editor = Role::new("editor").permission("post.publish");
/// assert_eq!(editor.name(), "editor");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Role {
    pub(crate) name: String,
    pub(crate) permissions: Vec<String>,
    pub(crate) inherits: Vec<RoleId>,
}

impl Role {
    /// A role named `name` (1 to 64 bytes) with no permissions yet.
    pub fn new(name: impl Into<String>) -> Role {
        Role {
            name: name.into(),
            permissions: Vec::new(),
            inherits: Vec::new(),
        }
    }

    /// Grant `permission` (1 to 64 bytes; at most 64 per role).
    pub fn permission(mut self, permission: impl Into<String>) -> Role {
        self.permissions.push(permission.into());
        self
    }

    /// Inherit every permission of `role`, which must already be defined.
    pub fn inherits(mut self, role: RoleId) -> Role {
        self.inherits.push(role);
        self
    }

    /// The role's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The permissions the role grants itself, without inherited ones.
    pub fn permissions(&self) -> impl Iterator<Item = &str> {
        self.permissions.iter().map(String::as_str)
    }

    /// The roles this one inherits.
    #[must_use]
    pub fn inherited(&self) -> &[RoleId] {
        &self.inherits
    }

    pub(crate) fn check(&self) -> Result<()> {
        if !valid_name(&self.name) {
            return Err(Error::invalid("role name", "must be 1 to 64 bytes"));
        }
        if self.permissions.len() > MAX_PERMISSIONS || self.inherits.len() > MAX_ROLES_PER {
            return Err(Error::invalid(
                "role",
                "at most 64 permissions and 64 inherited roles",
            ));
        }
        if !self.permissions.iter().all(|p| valid_name(p)) {
            return Err(Error::invalid("permission name", "must be 1 to 64 bytes"));
        }
        Ok(())
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME && !name.chars().any(char::is_control)
}

/// Every role of a realm, in id order (a role's id is its index).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    roles: Vec<Role>,
}

impl Policy {
    /// The policy with `role` added, and the new role's id.
    pub(crate) fn with(&self, role: Role) -> Result<(Policy, RoleId)> {
        role.check()?;
        if self.roles.len() >= MAX_ROLES {
            return Err(Error::invalid("role", "a realm has at most 256 roles"));
        }
        if self.named(&role.name).is_some() {
            return Err(Error::AlreadyExists { what: "role" });
        }
        // Inheriting only defined roles keeps the graph free of cycles.
        if role.inherits.iter().any(|r| self.get(*r).is_none()) {
            return Err(Error::invalid(
                "role",
                "inherits a role that is not defined",
            ));
        }
        let id = RoleId(self.roles.len() as u32);
        let mut next = self.clone();
        next.roles.push(role);
        Ok((next, id))
    }

    pub(crate) fn get(&self, id: RoleId) -> Option<&Role> {
        self.roles.get(id.0 as usize)
    }

    pub(crate) fn named(&self, name: &str) -> Option<RoleId> {
        self.roles
            .iter()
            .position(|r| r.name == name)
            .map(|i| RoleId(i as u32))
    }

    /// True when any of `roles`, or a role they inherit, grants `permission`.
    pub(crate) fn allows(&self, roles: &[RoleId], permission: &str) -> bool {
        let mut seen = HashSet::new();
        let mut todo: Vec<RoleId> = roles.to_vec();
        while let Some(id) = todo.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(role) = self.get(id) else {
                continue;
            };
            if role.permissions.iter().any(|p| p == permission) {
                return true;
            }
            todo.extend_from_slice(&role.inherits);
        }
        false
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u8(POLICY_FORMAT);
        w.u16(self.roles.len() as u16);
        for role in &self.roles {
            w.str16(&role.name)?;
            w.u16(role.permissions.len() as u16);
            for p in &role.permissions {
                w.str16(p)?;
            }
            w.u16(role.inherits.len() as u16);
            for r in &role.inherits {
                w.u32(r.0);
            }
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8], seq: Seq) -> Result<Policy> {
        let mut r = Reader::new(bytes, "the role policy", seq);
        if r.u8()? != POLICY_FORMAT {
            return Err(Error::corrupt("the role policy", seq));
        }
        let count = usize::from(r.u16()?);
        let mut roles = Vec::with_capacity(count.min(MAX_ROLES));
        for _ in 0..count {
            let name = r.str16()?.to_owned();
            let permissions = (0..r.u16()?)
                .map(|_| r.str16().map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            let inherits = (0..r.u16()?)
                .map(|_| r.u32().map(RoleId))
                .collect::<Result<Vec<_>>>()?;
            roles.push(Role {
                name,
                permissions,
                inherits,
            });
        }
        r.finish()?;
        Ok(Policy { roles })
    }
}

/// An account as [`Auth::account`](crate::Auth::account) returns it: never
/// a credential, never an identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub(crate) id: AccountId,
    pub(crate) created_at: SystemTime,
    pub(crate) standing: Standing,
    pub(crate) roles: Vec<RoleId>,
}

impl Account {
    /// The account's id.
    #[must_use]
    pub fn id(&self) -> AccountId {
        self.id
    }

    /// When the account was created.
    #[must_use]
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Its standing now (a lock-out or suspension that ran out reads as
    /// [`Standing::Active`]).
    #[must_use]
    pub fn standing(&self) -> Standing {
        self.standing
    }

    /// The roles assigned to it.
    #[must_use]
    pub fn roles(&self) -> &[RoleId] {
        &self.roles
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_resolves_inheritance_and_round_trips() {
        let p = Policy::default();
        let (p, member) = p.with(Role::new("member").permission("post.read")).unwrap();
        let (p, author) = p
            .with(
                Role::new("author")
                    .permission("post.write")
                    .inherits(member),
            )
            .unwrap();
        let (p, editor) = p
            .with(
                Role::new("editor")
                    .permission("post.publish")
                    .inherits(author),
            )
            .unwrap();
        assert!(p.allows(&[editor], "post.read"));
        assert!(p.allows(&[author], "post.write"));
        assert!(!p.allows(&[author], "post.publish"));
        assert!(!p.allows(&[], "post.read"));
        assert_eq!(p.named("editor"), Some(editor));
        assert_eq!(Policy::decode(&p.encode().unwrap(), 0).unwrap(), p);
    }

    #[test]
    fn test_policy_refuses_bad_roles() {
        let (p, _) = Policy::default().with(Role::new("a")).unwrap();
        assert!(matches!(
            p.with(Role::new("a")),
            Err(Error::AlreadyExists { what: "role" })
        ));
        assert!(p.with(Role::new("")).is_err());
        assert!(p.with(Role::new("b").inherits(RoleId(9))).is_err());
        assert!(p.with(Role::new("c").permission("x".repeat(65))).is_err());
    }
}
