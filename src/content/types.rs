//! Content types: what a space declares about the entities it holds.
//!
//! A type names its fields and their kinds; a value of the wrong kind is
//! refused when it is saved. A unique field's published values are unique
//! within the space. A singleton type has at most one entity. A reference
//! field's rule says what deleting the entity it refers to does. Fields a
//! type does not declare are stored as they are. A type is only ever
//! extended: a redefinition keeps every field it had, with the same kind.

use std::collections::{HashMap, HashSet};

use super::{
    entity::{Body, Head, Value},
    locale::Locale,
};
use crate::{
    core::codec::{Reader, Writer},
    error::{Error, Result},
    ids::Rid,
};

/// Format of the stored types.
const TYPES_FORMAT: u8 = 1;
/// Most types a space declares.
const MAX_TYPES: usize = 256;
/// Most fields a type declares.
const MAX_TYPE_FIELDS: usize = 256;

const FLAG_UNIQUE: u8 = 1;
/// Bits 1 and 2 of a field's flags: its reference rule (0 for none).
const RULE_SHIFT: u8 = 1;
const RULE_MASK: u8 = 0b110;

/// What deleting an entity does to a field referring to it, for
/// [`Type::reference`]. A field no rule is declared for restricts.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// The delete is refused with [`Error::Restricted`] while the field
    /// refers to the entity.
    Restrict,
    /// The field is removed from the referring entity: from its drafts, and
    /// from a published body by publishing a new revision without it.
    Detach,
    /// The referring entity is deleted too.
    Cascade,
}

impl Rule {
    fn bits(self) -> u8 {
        let code = match self {
            Rule::Restrict => 1,
            Rule::Detach => 2,
            Rule::Cascade => 3,
        };
        code << RULE_SHIFT
    }

    fn of(flags: u8) -> Option<Rule> {
        match (flags & RULE_MASK) >> RULE_SHIFT {
            1 => Some(Rule::Restrict),
            2 => Some(Rule::Detach),
            3 => Some(Rule::Cascade),
            _ => None,
        }
    }
}

/// The kind of value a declared field holds.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// [`Value::Text`].
    Text,
    /// [`Value::Int`].
    Int,
    /// [`Value::Bool`].
    Bool,
    /// [`Value::Account`].
    Account,
    /// [`Value::Entity`].
    Entity,
}

impl FieldType {
    fn code(self) -> u8 {
        match self {
            FieldType::Text => 1,
            FieldType::Int => 2,
            FieldType::Bool => 3,
            FieldType::Account => 4,
            FieldType::Entity => 5,
        }
    }

    fn of(code: u8, at: u64) -> Result<FieldType> {
        Ok(match code {
            1 => FieldType::Text,
            2 => FieldType::Int,
            3 => FieldType::Bool,
            4 => FieldType::Account,
            5 => FieldType::Entity,
            _ => return Err(Error::corrupt("a field type", at)),
        })
    }

    fn holds(self, value: &Value) -> bool {
        matches!(
            (self, value),
            (FieldType::Text, Value::Text(_))
                | (FieldType::Int, Value::Int(_))
                | (FieldType::Bool, Value::Bool(_))
                | (FieldType::Account, Value::Account(_))
                | (FieldType::Entity, Value::Entity(_))
        )
    }
}

/// A content type, for [`Content::define`](crate::Content::define).
///
/// ```
/// use nex_db::{FieldType, Type};
/// let post = Type::new("post")
///     .field("title", FieldType::Text)
///     .field("slug", FieldType::Text)
///     .unique();
/// # let _ = post;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Type {
    pub(crate) name: String,
    pub(crate) singleton: bool,
    pub(crate) fields: Vec<(String, FieldType, u8)>,
}

impl Type {
    /// A type named `name` (as [`Entity::new`](crate::Entity::new) takes it).
    pub fn new(name: impl Into<String>) -> Type {
        Type {
            name: name.into(),
            singleton: false,
            fields: Vec::new(),
        }
    }

    /// At most one entity of this type in the space: site settings,
    /// navigation.
    pub fn singleton(mut self) -> Type {
        self.singleton = true;
        self
    }

    /// Declare field `name` holding values of `kind`.
    pub fn field(mut self, name: impl Into<String>, kind: FieldType) -> Type {
        self.fields.push((name.into(), kind, 0));
        self
    }

    /// Declare field `name` as a reference to another entity
    /// ([`FieldType::Entity`]) and what deleting that entity does.
    ///
    /// ```
    /// use nex_db::{Rule, Type};
    /// let post = Type::new("post")
    ///     .reference("author", Rule::Restrict)
    ///     .reference("hero", Rule::Detach);
    /// assert_eq!(post.rule("hero"), Some(Rule::Detach));
    /// ```
    pub fn reference(mut self, name: impl Into<String>, rule: Rule) -> Type {
        self.fields
            .push((name.into(), FieldType::Entity, rule.bits()));
        self
    }

    /// The rule declared for reference field `name`, if any.
    #[must_use]
    pub fn rule(&self, name: &str) -> Option<Rule> {
        self.fields
            .iter()
            .find(|(n, _, _)| n == name)
            .and_then(|(_, _, f)| Rule::of(*f))
    }

    /// The field declared last: its published values are unique within the
    /// space.
    pub fn unique(mut self) -> Type {
        if let Some(last) = self.fields.last_mut() {
            last.2 |= FLAG_UNIQUE;
        }
        self
    }

    /// The type's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Each declared field, its kind, and whether it is unique.
    pub fn fields(&self) -> impl Iterator<Item = (&str, FieldType, bool)> {
        self.fields
            .iter()
            .map(|(n, k, f)| (n.as_str(), *k, f & FLAG_UNIQUE != 0))
    }

    fn unique_fields(&self) -> impl Iterator<Item = &str> {
        self.fields
            .iter()
            .filter(|(_, _, f)| f & FLAG_UNIQUE != 0)
            .map(|(n, _, _)| n.as_str())
    }
}

/// Every type of a space.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Types {
    types: Vec<Type>,
}

impl Types {
    pub(crate) fn get(&self, name: &str) -> Option<&Type> {
        self.types.iter().find(|t| t.name == name)
    }

    /// The types with `next` defined: added, or an existing type extended.
    pub(crate) fn with(&self, next: Type) -> Result<Types> {
        if next.fields.len() > MAX_TYPE_FIELDS {
            return Err(Error::invalid("type", "at most 256 fields"));
        }
        let mut names = HashSet::new();
        for (name, _, _) in &next.fields {
            if !names.insert(name.as_str()) {
                return Err(Error::invalid("type", "declares a field twice"));
            }
        }
        if let Some(old) = self.get(&next.name) {
            // A reference rule may change; a unique flag stays.
            for (name, kind, flags) in &old.fields {
                let unique = flags & FLAG_UNIQUE;
                let kept = next
                    .fields
                    .iter()
                    .any(|(n, k, f)| n == name && k == kind && f & unique == unique);
                if !kept {
                    return Err(Error::invalid(
                        "type",
                        "a redefinition keeps every field, kind, and flag it had",
                    ));
                }
            }
            if old.singleton && !next.singleton {
                return Err(Error::invalid("type", "stays a singleton"));
            }
        } else if self.types.len() >= MAX_TYPES {
            return Err(Error::invalid("types", "a space has at most 256"));
        }
        let mut out = self.clone();
        out.types.retain(|t| t.name != next.name);
        out.types.push(next);
        Ok(out)
    }

    /// What deleting an entity does to field `field` of an entity of
    /// `kind` that refers to it: the declared rule, else
    /// [`Rule::Restrict`].
    pub(crate) fn rule(&self, kind: &str, field: &str) -> Rule {
        self.get(kind)
            .and_then(|t| t.rule(field))
            .unwrap_or(Rule::Restrict)
    }

    /// Refuse a declared field of `kind` holding a value of another kind.
    pub(crate) fn check(&self, kind: &str, body: &Body) -> Result<()> {
        let Some(ty) = self.get(kind) else {
            return Ok(());
        };
        for (name, value) in &body.fields {
            if let Some((_, want, _)) = ty.fields.iter().find(|(n, _, _)| n == name) {
                if !want.holds(value) {
                    return Err(Error::invalid(
                        "field value",
                        "not the kind its type declares",
                    ));
                }
            }
        }
        Ok(())
    }

    /// True when type `kind` declares a unique field.
    pub(crate) fn has_unique(&self, kind: &str) -> bool {
        self.get(kind)
            .is_some_and(|t| t.unique_fields().next().is_some())
    }

    /// The unique keys `body`, a body of an entity of `kind`, takes when it
    /// is published.
    pub(crate) fn unique_keys(&self, kind: &str, body: &Body) -> Vec<Vec<u8>> {
        let Some(ty) = self.get(kind) else {
            return Vec::new();
        };
        let mut keys = Vec::new();
        for field in ty.unique_fields() {
            if let Some((_, value)) = body.fields.iter().find(|(n, _)| n == field) {
                keys.push(unique_key(kind, field, value));
            }
        }
        keys
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u8(TYPES_FORMAT);
        w.u16(self.types.len() as u16);
        for ty in &self.types {
            w.str16(&ty.name)?;
            w.u8(u8::from(ty.singleton));
            w.u16(ty.fields.len() as u16);
            for (name, kind, flags) in &ty.fields {
                w.str16(name)?;
                w.u8(kind.code());
                w.u8(*flags);
            }
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8], at: u64) -> Result<Types> {
        let mut r = Reader::new(bytes, "the content types", at);
        if r.u8()? != TYPES_FORMAT {
            return Err(Error::corrupt("the content types format", at));
        }
        let mut types = Vec::new();
        for _ in 0..r.u16()? {
            let name = r.str16()?.to_owned();
            let singleton = r.u8()? == 1;
            let mut fields = Vec::new();
            for _ in 0..r.u16()? {
                let field = r.str16()?.to_owned();
                let kind = FieldType::of(r.u8()?, at)?;
                let flags = r.u8()?;
                if flags & !(FLAG_UNIQUE | RULE_MASK) != 0
                    || (Rule::of(flags).is_some() && kind != FieldType::Entity)
                {
                    return Err(Error::corrupt("a field's flags", at));
                }
                fields.push((field, kind, flags));
            }
            types.push(Type {
                name,
                singleton,
                fields,
            });
        }
        r.finish()?;
        Ok(Types { types })
    }
}

/// The key a unique value takes: type, field, and the value's bytes.
pub(crate) fn unique_key(kind: &str, field: &str, value: &Value) -> Vec<u8> {
    let mut key = Vec::with_capacity(kind.len() + field.len() + 24);
    key.push(b'u');
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    key.extend_from_slice(field.as_bytes());
    key.push(0);
    match value {
        Value::Text(t) => {
            key.push(1);
            key.extend_from_slice(t.as_bytes());
        }
        Value::Int(v) => {
            key.push(2);
            key.extend_from_slice(&v.to_be_bytes());
        }
        Value::Bool(v) => key.extend_from_slice(&[3, u8::from(*v)]),
        Value::Account(a) => {
            key.push(4);
            key.extend_from_slice(a.as_bytes());
        }
        Value::Entity(r) => {
            key.push(5);
            key.extend_from_slice(r.as_bytes());
        }
    }
    key
}

/// The unique keys one published locale of an entity holds: its locale,
/// the revision they were read from, and the keys.
type Held = (Locale, u32, Vec<Vec<u8>>);

/// Derived indexes over the heads that types need: unique values of
/// published bodies, and the entity of each singleton type.
#[derive(Debug, Default)]
pub(crate) struct TypeIndex {
    unique: HashMap<Vec<u8>, Rid>,
    /// Each entity's unique keys by published locale, to drop them when it
    /// changes and to keep them while its published revision does not.
    held: HashMap<Rid, Vec<Held>>,
    /// Entities by type, counted, with one of them.
    kinds: HashMap<String, (usize, Rid)>,
    known: HashSet<Rid>,
}

impl TypeIndex {
    /// Place `head` as it now is. `published` reads the body of one of its
    /// published revisions; it is called only for a type with a unique
    /// field, and only for a locale whose published revision changed.
    pub(crate) fn update(
        &mut self,
        types: &Types,
        head: &Head,
        mut published: impl FnMut(Locale, u32) -> Result<Body>,
    ) -> Result<()> {
        if self.known.insert(head.rid) {
            let entry = self.kinds.entry(head.kind.clone()).or_insert((0, head.rid));
            entry.0 += 1;
        }
        let old = self.held.remove(&head.rid).unwrap_or_default();
        let mut next = Vec::new();
        if types.has_unique(&head.kind) {
            for variant in &head.variants {
                let Some(p) = &variant.published else {
                    continue;
                };
                let kept = old
                    .iter()
                    .find(|(l, n, _)| *l == variant.locale && *n == p.revision);
                let keys = match kept {
                    Some((_, _, keys)) => keys.clone(),
                    None => types.unique_keys(&head.kind, &published(variant.locale, p.revision)?),
                };
                next.push((variant.locale, p.revision, keys));
            }
        }
        self.release(head.rid, old);
        for (_, _, keys) in &next {
            for key in keys {
                let _ = self.unique.insert(key.clone(), head.rid);
            }
        }
        if !next.is_empty() {
            let _ = self.held.insert(head.rid, next);
        }
        Ok(())
    }

    fn release(&mut self, rid: Rid, held: Vec<Held>) {
        for key in held.into_iter().flat_map(|(_, _, keys)| keys) {
            if self.unique.get(&key) == Some(&rid) {
                let _ = self.unique.remove(&key);
            }
        }
    }

    /// Forget `rid`: it was deleted.
    pub(crate) fn remove(&mut self, rid: Rid, kind: &str) {
        let held = self.held.remove(&rid).unwrap_or_default();
        self.release(rid, held);
        if self.known.remove(&rid) {
            if let Some(entry) = self.kinds.get_mut(kind) {
                entry.0 = entry.0.saturating_sub(1);
                if entry.0 == 0 {
                    let _ = self.kinds.remove(kind);
                }
            }
        }
    }

    /// The published entity holding unique `key`, if any.
    pub(crate) fn holder(&self, key: &[u8]) -> Option<Rid> {
        self.unique.get(key).copied()
    }

    /// How many entities of `kind` exist, and one of them.
    pub(crate) fn count(&self, kind: &str) -> (usize, Option<Rid>) {
        self.kinds
            .get(kind)
            .map_or((0, None), |(n, rid)| (*n, Some(*rid)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_types_round_trip_and_only_grow() {
        let types = Types::default()
            .with(
                Type::new("post")
                    .field("title", FieldType::Text)
                    .field("slug", FieldType::Text)
                    .unique(),
            )
            .unwrap();
        assert_eq!(Types::decode(&types.encode().unwrap(), 0).unwrap(), types);
        let grown = types
            .with(
                Type::new("post")
                    .field("title", FieldType::Text)
                    .field("slug", FieldType::Text)
                    .unique()
                    .field("words", FieldType::Int),
            )
            .unwrap();
        assert_eq!(grown.get("post").unwrap().fields().count(), 3);
        assert!(
            types
                .with(Type::new("post").field("title", FieldType::Int))
                .is_err()
        );
        assert!(
            types
                .with(
                    Type::new("post")
                        .field("title", FieldType::Text)
                        .field("slug", FieldType::Text)
                )
                .is_err()
        );
        assert!(
            Types::default()
                .with(
                    Type::new("x")
                        .field("a", FieldType::Int)
                        .field("a", FieldType::Int)
                )
                .is_err()
        );
    }

    #[test]
    fn test_reference_rules_round_trip_and_may_change() {
        let types = Types::default()
            .with(Type::new("post").reference("author", Rule::Cascade))
            .unwrap();
        assert_eq!(Types::decode(&types.encode().unwrap(), 0).unwrap(), types);
        assert_eq!(types.rule("post", "author"), Rule::Cascade);
        assert_eq!(types.rule("post", "other"), Rule::Restrict);
        assert_eq!(types.rule("page", "author"), Rule::Restrict);
        let changed = types
            .with(Type::new("post").reference("author", Rule::Detach))
            .unwrap();
        assert_eq!(changed.rule("post", "author"), Rule::Detach);
        // Dropping the field is still refused.
        assert!(types.with(Type::new("post")).is_err());
    }

    #[test]
    fn test_check_refuses_a_declared_field_of_the_wrong_kind() {
        let types = Types::default()
            .with(Type::new("post").field("words", FieldType::Int))
            .unwrap();
        let body = |v: Value| Body {
            path: None,
            fields: vec![("words".into(), v)],
        };
        assert!(types.check("post", &body(Value::Int(3))).is_ok());
        assert!(types.check("post", &body(Value::Text("3".into()))).is_err());
        // Undeclared types and fields are stored as they are.
        assert!(types.check("page", &body(Value::Text("3".into()))).is_ok());
    }
}
