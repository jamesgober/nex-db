//! Entities: what the content engine stores.

use std::{
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    core::codec::{Reader, Writer},
    error::{Error, Result},
    ids::{AccountId, Rid},
};

/// The site an entity's path belongs to when [`Entity::site`] is not called.
pub const DEFAULT_SITE: &str = "default";

const MAX_NAME: usize = 64;
const MAX_SITE: usize = 253;
const MAX_PATH: usize = 2048;
const MAX_FIELDS: usize = 256;
const MAX_TEXT: usize = 1024 * 1024;

/// Stored entity record format.
const RECORD_FORMAT: u8 = 1;

const TAG_TEXT: u8 = 1;
const TAG_INT: u8 = 2;
const TAG_BOOL: u8 = 3;
const TAG_ACCOUNT: u8 = 4;
const TAG_ENTITY: u8 = 5;

/// A field value.
///
/// ```
/// use nex_db::Value;
/// assert_eq!(Value::from("Ann").as_text(), Some("Ann"));
/// assert_eq!(Value::from(42_i64).as_int(), Some(42));
/// assert_eq!(Value::from(true).as_bool(), Some(true));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// UTF-8 text, at most 1 MiB.
    Text(String),
    /// A signed 64-bit integer.
    Int(i64),
    /// A boolean.
    Bool(bool),
    /// A reference to an account. An opaque id: the content engine never
    /// reads the auth engine.
    Account(AccountId),
    /// A reference to another entity.
    Entity(Rid),
}

impl Value {
    /// The text, when this is [`Value::Text`].
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The integer, when this is [`Value::Int`].
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// The boolean, when this is [`Value::Bool`].
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// The account, when this is [`Value::Account`].
    #[must_use]
    pub const fn as_account(&self) -> Option<AccountId> {
        match self {
            Value::Account(v) => Some(*v),
            _ => None,
        }
    }

    /// The entity, when this is [`Value::Entity`].
    #[must_use]
    pub const fn as_entity(&self) -> Option<Rid> {
        match self {
            Value::Entity(v) => Some(*v),
            _ => None,
        }
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Text(v.to_owned())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Text(v)
    }
}

impl From<&String> for Value {
    fn from(v: &String) -> Self {
        Value::Text(v.clone())
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Int(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<AccountId> for Value {
    fn from(v: AccountId) -> Self {
        Value::Account(v)
    }
}

impl From<Rid> for Value {
    fn from(v: Rid) -> Self {
        Value::Entity(v)
    }
}

/// A new entity, built before it is created.
///
/// ```
/// use nex_db::{AccountId, Entity};
/// # let account = AccountId::from_bytes([1; 16]);
/// let profile = Entity::new("profile")
///     .field("account", account)
///     .field("display_name", "Ann")
///     .site("example.com")
///     .path("/u/ann");
/// # let _ = profile;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    kind: String,
    site: Option<String>,
    path: Option<String>,
    fields: Vec<(String, Value)>,
}

impl Entity {
    /// A new entity of type `kind` (for example `"profile"` or `"post"`).
    #[must_use]
    pub fn new(kind: impl Into<String>) -> Self {
        Entity {
            kind: kind.into(),
            site: None,
            path: None,
            fields: Vec::new(),
        }
    }

    /// Set the field `name` to `value`.
    #[must_use]
    pub fn field(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.fields.push((name.into(), value.into()));
        self
    }

    /// The site the entity's path belongs to (default [`DEFAULT_SITE`]).
    #[must_use]
    pub fn site(mut self, site: impl Into<String>) -> Self {
        self.site = Some(site.into());
        self
    }

    /// The path the entity is served at, starting with `/`. The path must be
    /// unused on its site; [`Content::resolve`](crate::Content::resolve)
    /// finds the entity by it.
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub(crate) fn site_name(&self) -> &str {
        self.site.as_deref().unwrap_or(DEFAULT_SITE)
    }

    pub(crate) fn route_path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Check every rule and return the stored record for `rid`.
    pub(crate) fn encode(&self, rid: Rid, created_ms: u64) -> Result<Vec<u8>> {
        check_name("type", &self.kind)?;
        let site = self.site_name();
        if site.is_empty()
            || site.len() > MAX_SITE
            || site.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(Error::invalid(
                "site",
                "must be 1 to 253 bytes without spaces",
            ));
        }
        if let Some(path) = &self.path {
            if !path.starts_with('/')
                || path.len() > MAX_PATH
                || path.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(Error::invalid(
                    "path",
                    "must start with '/', be at most 2048 bytes, and hold no spaces",
                ));
            }
        }
        if self.fields.len() > MAX_FIELDS {
            return Err(Error::invalid("fields", "at most 256 per entity"));
        }
        let mut names = HashSet::with_capacity(self.fields.len());
        for (name, value) in &self.fields {
            check_name("field name", name)?;
            if !names.insert(name.as_str()) {
                return Err(Error::invalid("field name", "appears twice"));
            }
            if let Value::Text(text) = value {
                if text.len() > MAX_TEXT {
                    return Err(Error::invalid("field value", "text over 1 MiB"));
                }
            }
        }

        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u8(RECORD_FORMAT);
        w.bytes(rid.as_bytes());
        w.u64(created_ms);
        w.u32(1);
        w.str16(&self.kind)?;
        w.str16(site)?;
        w.str16(self.path.as_deref().unwrap_or(""))?;
        w.u16(self.fields.len() as u16);
        for (name, value) in &self.fields {
            w.str16(name)?;
            match value {
                Value::Text(text) => {
                    w.u8(TAG_TEXT);
                    w.bytes32(text.as_bytes())?;
                }
                Value::Int(v) => {
                    w.u8(TAG_INT);
                    w.i64(*v);
                }
                Value::Bool(v) => {
                    w.u8(TAG_BOOL);
                    w.u8(u8::from(*v));
                }
                Value::Account(v) => {
                    w.u8(TAG_ACCOUNT);
                    w.bytes(v.as_bytes());
                }
                Value::Entity(v) => {
                    w.u8(TAG_ENTITY);
                    w.bytes(v.as_bytes());
                }
            }
        }
        Ok(out)
    }
}

fn check_name(what: &'static str, name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(
            what,
            "must be 1 to 64 ASCII letters, digits, '_' or '-'",
        ))
    }
}

/// A stored entity, as [`Content::get`](crate::Content::get) returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    rid: Rid,
    kind: String,
    created_ms: u64,
    revision: u32,
    site: String,
    path: Option<String>,
    fields: Vec<(String, Value)>,
}

impl Entry {
    /// Decode a stored record. `at` locates it in errors.
    pub(crate) fn decode(bytes: &[u8], at: u64) -> Result<Entry> {
        let mut r = Reader::new(bytes, "an entity record", at);
        if r.u8()? != RECORD_FORMAT {
            return Err(Error::corrupt("an entity record format", at));
        }
        let rid = Rid::from_bytes(r.fixed()?);
        let created_ms = r.u64()?;
        let revision = r.u32()?;
        let kind = r.str16()?.to_owned();
        let site = r.str16()?.to_owned();
        let path = Some(r.str16()?.to_owned()).filter(|p| !p.is_empty());
        let count = r.u16()?;
        let mut fields = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let name = r.str16()?.to_owned();
            let value = match r.u8()? {
                TAG_TEXT => {
                    let bytes = r.bytes32()?;
                    let text = std::str::from_utf8(bytes)
                        .map_err(|_| Error::corrupt("an entity text field", at))?;
                    Value::Text(text.to_owned())
                }
                TAG_INT => Value::Int(r.i64()?),
                TAG_BOOL => match r.u8()? {
                    0 => Value::Bool(false),
                    1 => Value::Bool(true),
                    _ => return Err(Error::corrupt("an entity bool field", at)),
                },
                TAG_ACCOUNT => Value::Account(AccountId::from_bytes(r.fixed()?)),
                TAG_ENTITY => Value::Entity(Rid::from_bytes(r.fixed()?)),
                _ => return Err(Error::corrupt("an entity field type", at)),
            };
            fields.push((name, value));
        }
        r.finish()?;
        Ok(Entry {
            rid,
            kind,
            created_ms,
            revision,
            site,
            path,
            fields,
        })
    }

    /// The entity's record id.
    #[must_use]
    pub const fn rid(&self) -> Rid {
        self.rid
    }

    /// The entity's type.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The revision number; 1 for a new entity.
    #[must_use]
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// When the entity was created.
    #[must_use]
    pub fn created_at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.created_ms)
    }

    /// The site and path the entity is served at, if it has a path.
    #[must_use]
    pub fn route(&self) -> Option<(&str, &str)> {
        self.path.as_deref().map(|p| (self.site.as_str(), p))
    }

    /// The value of field `name`.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Every field, in the order they were set.
    pub fn fields(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.fields.iter().map(|(n, v)| (n.as_str(), v))
    }
}

/// What a route resolves to. A small `Copy` value.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// The path serves the entity.
    Page,
}

/// A resolved route, as [`Content::resolve`](crate::Content::resolve) returns
/// it. Resolving allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEntry {
    pub(crate) entity: Rid,
    pub(crate) revision: u32,
    pub(crate) kind: RouteKind,
}

impl RouteEntry {
    /// The entity the path names.
    #[must_use]
    pub const fn entity(&self) -> Rid {
        self.entity
    }

    /// The entity revision the route serves, for cache keys.
    #[must_use]
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// What the route resolves to.
    #[must_use]
    pub const fn kind(&self) -> RouteKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> Rid {
        Rid::from_bytes([9; 16])
    }

    #[test]
    fn test_encode_decode_round_trips_every_value_kind() {
        let account = AccountId::from_bytes([1; 16]);
        let entity = Entity::new("profile")
            .field("name", "Ann")
            .field("age", 40_i64)
            .field("public", true)
            .field("account", account)
            .field("parent", rid())
            .site("example.com")
            .path("/u/ann");
        let bytes = entity.encode(rid(), 5).unwrap();
        let entry = Entry::decode(&bytes, 0).unwrap();
        assert_eq!(entry.rid(), rid());
        assert_eq!(entry.kind(), "profile");
        assert_eq!(entry.revision(), 1);
        assert_eq!(entry.route(), Some(("example.com", "/u/ann")));
        assert_eq!(entry.field("name").and_then(Value::as_text), Some("Ann"));
        assert_eq!(entry.field("age").and_then(Value::as_int), Some(40));
        assert_eq!(entry.field("public").and_then(Value::as_bool), Some(true));
        assert_eq!(
            entry.field("account").and_then(Value::as_account),
            Some(account)
        );
        assert_eq!(
            entry.field("parent").and_then(Value::as_entity),
            Some(rid())
        );
        assert_eq!(entry.fields().count(), 5);
        assert_eq!(entry.created_at(), UNIX_EPOCH + Duration::from_millis(5));
    }

    #[test]
    fn test_encode_without_path_has_no_route_and_default_site() {
        let bytes = Entity::new("note").encode(rid(), 0).unwrap();
        let entry = Entry::decode(&bytes, 0).unwrap();
        assert_eq!(entry.route(), None);
        assert_eq!(entry.site, DEFAULT_SITE);
    }

    #[test]
    fn test_encode_rejects_bad_input() {
        let bad = [
            Entity::new(""),
            Entity::new("has space"),
            Entity::new("p").path("no-slash"),
            Entity::new("p").path("/has space"),
            Entity::new("p").site(""),
            Entity::new("p").field("dup", 1_i64).field("dup", 2_i64),
            Entity::new("p").field("bad name", 1_i64),
            Entity::new("p").field("big", "x".repeat(MAX_TEXT + 1)),
        ];
        for entity in bad {
            assert!(
                matches!(entity.encode(rid(), 0), Err(Error::Invalid { .. })),
                "{entity:?}"
            );
        }
    }

    #[test]
    fn test_decode_every_truncation_is_corrupt() {
        let bytes = Entity::new("p")
            .field("a", "b")
            .path("/x")
            .encode(rid(), 0)
            .unwrap();
        for len in 0..bytes.len() {
            assert!(Entry::decode(&bytes[..len], 0).is_err(), "prefix {len}");
        }
    }
}
