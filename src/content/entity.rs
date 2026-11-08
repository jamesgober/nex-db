//! Entities: what the content engine stores.

use std::{collections::HashSet, time::SystemTime};

use super::locale::Locale;
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

/// Stored entity record format of 0.1 to 0.3: one published revision.
const RECORD_FORMAT: u8 = 1;
/// Stored entity record format of builds before 0.4.0 was released: as
/// [`HEAD_FORMAT`] without the references of published bodies. Read only.
const HEAD_FORMAT_2: u8 = 2;
/// As [`HEAD_FORMAT`] without authors, parent, and order: builds before
/// 0.4.0 was released. Read only.
const HEAD_FORMAT_3: u8 = 3;
/// Stored entity record format from 0.4: per locale, the working draft
/// and what is published, with the entities the published body refers to;
/// then the authors, the parent, and the order among its siblings.
const HEAD_FORMAT: u8 = 4;
/// Most authors one entity has.
pub(crate) const MAX_AUTHORS: usize = 16;
/// Most locales one entity has.
const MAX_VARIANTS: usize = 64;
/// Format of a stored revision.
const REVISION_FORMAT: u8 = 1;
/// Format of a stored route.
const ROUTE_FORMAT: u8 = 1;
/// Longest revision message, in bytes.
const MAX_MESSAGE: usize = 1024;

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
    locale: Option<Locale>,
    fields: Vec<(String, Value)>,
    authors: Vec<AccountId>,
    parent: Option<Rid>,
    order: i64,
}

impl Entity {
    /// A new entity of type `kind` (for example `"profile"` or `"post"`).
    #[must_use]
    pub fn new(kind: impl Into<String>) -> Self {
        Entity {
            kind: kind.into(),
            site: None,
            path: None,
            locale: None,
            fields: Vec::new(),
            authors: Vec::new(),
            parent: None,
            order: 0,
        }
    }

    /// Add `account` to the entity's authors, in order (at most 16).
    /// Authors are shared by every locale; listings filter by them
    /// ([`Listing::by_author`](crate::Listing::by_author)).
    #[must_use]
    pub fn author(mut self, account: AccountId) -> Self {
        if !self.authors.contains(&account) {
            self.authors.push(account);
        }
        self
    }

    /// The entity's parent, for page trees and menus
    /// ([`Content::children`](crate::Content::children)). The parent is a
    /// reference: it cannot be deleted while it has children.
    #[must_use]
    pub fn parent(mut self, parent: Rid) -> Self {
        self.parent = Some(parent);
        self
    }

    /// The entity's place among its parent's children, lowest first
    /// (default 0; ties go by record id).
    #[must_use]
    pub fn order(mut self, order: i64) -> Self {
        self.order = order;
        self
    }

    /// The locale the entity is written in (default: the space's default
    /// locale). Translations into other locales are added with
    /// [`translate`](crate::ContentTx::translate).
    #[must_use]
    pub fn locale(mut self, locale: Locale) -> Self {
        self.locale = Some(locale);
        self
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

    pub(crate) fn kind_name(&self) -> &str {
        &self.kind
    }

    pub(crate) fn site_name(&self) -> &str {
        self.site.as_deref().unwrap_or(DEFAULT_SITE)
    }

    /// Check every rule and return the new entity's head: a draft in its
    /// locale (or `default_locale`) with nothing published.
    pub(crate) fn into_head(
        self,
        rid: Rid,
        created_ms: u64,
        default_locale: Locale,
    ) -> Result<Head> {
        check_name("type", &self.kind)?;
        let site = self.site_name().to_owned();
        if site.is_empty()
            || site.len() > MAX_SITE
            || site.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(Error::invalid(
                "site",
                "must be 1 to 253 bytes without spaces",
            ));
        }
        if self.authors.len() > MAX_AUTHORS {
            return Err(Error::invalid("authors", "at most 16"));
        }
        let body = Body {
            path: self.path,
            fields: self.fields,
        };
        body.check()?;
        Ok(Head {
            authors: self.authors,
            parent: self.parent,
            order: self.order,
            rid,
            kind: self.kind,
            site,
            created_ms,
            updated_ms: created_ms,
            status: Status::Draft,
            visibility: Visibility::Public,
            last_revision: 0,
            first_published_ms: 0,
            variants: vec![Variant {
                locale: self.locale.unwrap_or(default_locale),
                draft: body,
                source: 0,
                published: None,
            }],
            gone: Vec::new(),
        })
    }

    /// The record 0.1 to 0.3 stored for `rid` (tests read it back).
    #[cfg(test)]
    pub(crate) fn encode_v1(&self, rid: Rid, created_ms: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u8(RECORD_FORMAT);
        w.bytes(rid.as_bytes());
        w.u64(created_ms);
        w.u32(1);
        w.str16(&self.kind)?;
        w.str16(self.site_name())?;
        w.str16(self.path.as_deref().unwrap_or(""))?;
        write_fields(&mut w, &self.fields)?;
        Ok(out)
    }
}

fn check_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > MAX_PATH
        || path.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(Error::invalid(
            "path",
            "must start with '/', be at most 2048 bytes, and hold no spaces",
        ));
    }
    Ok(())
}

fn write_fields(w: &mut Writer<'_>, fields: &[(String, Value)]) -> Result<()> {
    w.u16(fields.len() as u16);
    for (name, value) in fields {
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
    Ok(())
}

fn read_fields(r: &mut Reader<'_>, at: u64) -> Result<Vec<(String, Value)>> {
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
    Ok(fields)
}

/// Changes to an entity's working draft, for
/// [`save_draft`](crate::ContentTx::save_draft).
///
/// ```
/// use nex_db::Patch;
/// let patch = Patch::new().set("title", "Hello again").remove("subtitle");
/// # let _ = patch;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct Patch {
    set: Vec<(String, Value)>,
    remove: Vec<String>,
    path: Option<Option<String>>,
}

impl Patch {
    /// No changes yet.
    pub fn new() -> Patch {
        Patch::default()
    }

    /// Set field `name` to `value`.
    pub fn set(mut self, name: impl Into<String>, value: impl Into<Value>) -> Patch {
        self.set.push((name.into(), value.into()));
        self
    }

    /// Remove field `name`.
    pub fn remove(mut self, name: impl Into<String>) -> Patch {
        self.remove.push(name.into());
        self
    }

    /// Serve the draft at `path` once it is published.
    pub fn path(mut self, path: impl Into<String>) -> Patch {
        self.path = Some(Some(path.into()));
        self
    }

    /// Serve the draft at no path once it is published.
    pub fn no_path(mut self) -> Patch {
        self.path = Some(None);
        self
    }

    pub(crate) fn apply(self, body: &mut Body) -> Result<()> {
        for name in &self.remove {
            body.fields.retain(|(n, _)| n != name);
        }
        for (name, value) in self.set {
            match body.fields.iter_mut().find(|(n, _)| *n == name) {
                Some(slot) => slot.1 = value,
                None => body.fields.push((name, value)),
            }
        }
        if let Some(path) = self.path {
            body.path = path;
        }
        body.check()
    }
}

/// An entity's editable part: its path and fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Body {
    pub(crate) path: Option<String>,
    pub(crate) fields: Vec<(String, Value)>,
}

impl Body {
    /// The entities the body's fields refer to, in field order.
    pub(crate) fn refs(&self) -> impl Iterator<Item = Rid> + '_ {
        self.fields.iter().filter_map(|(_, v)| match v {
            Value::Entity(rid) => Some(*rid),
            _ => None,
        })
    }

    /// Drop every field referring to `target`; true when one was dropped.
    pub(crate) fn detach(&mut self, target: Rid) -> bool {
        let before = self.fields.len();
        self.fields.retain(|(_, v)| *v != Value::Entity(target));
        before != self.fields.len()
    }

    /// The names of the fields referring to `target`.
    pub(crate) fn fields_referring(&self, target: Rid) -> impl Iterator<Item = &str> + '_ {
        self.fields
            .iter()
            .filter(move |(_, v)| *v == Value::Entity(target))
            .map(|(n, _)| n.as_str())
    }

    fn check(&self) -> Result<()> {
        if let Some(path) = &self.path {
            check_path(path)?;
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
        Ok(())
    }
}

/// Where an entity is in its life.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// Being written; not published.
    Draft,
    /// Waiting for review; not published.
    Review,
    /// Published.
    Published,
    /// Taken down and kept.
    Archived,
    /// In the trash.
    Trashed,
}

impl Status {
    fn code(self) -> u8 {
        match self {
            Status::Draft => 1,
            Status::Review => 2,
            Status::Published => 3,
            Status::Archived => 4,
            Status::Trashed => 5,
        }
    }

    fn of(code: u8, at: u64) -> Result<Status> {
        Ok(match code {
            1 => Status::Draft,
            2 => Status::Review,
            3 => Status::Published,
            4 => Status::Archived,
            5 => Status::Trashed,
            _ => return Err(Error::corrupt("an entity status", at)),
        })
    }
}

/// Who may see a published entity. The application decides who counts as a
/// member and whom a private page is for; nex-db only stores the mark.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// Everyone.
    Public,
    /// Signed-in members.
    Members,
    /// Only the people the application allows.
    Private,
}

impl Visibility {
    fn code(self) -> u8 {
        match self {
            Visibility::Public => 1,
            Visibility::Members => 2,
            Visibility::Private => 3,
        }
    }

    fn of(code: u8, at: u64) -> Result<Visibility> {
        Ok(match code {
            1 => Visibility::Public,
            2 => Visibility::Members,
            3 => Visibility::Private,
            _ => return Err(Error::corrupt("an entity visibility", at)),
        })
    }
}

/// What is published of one locale of an entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Published {
    pub(crate) revision: u32,
    pub(crate) at_ms: u64,
    pub(crate) path: Option<String>,
    /// The entities the published body refers to, sorted, each once.
    pub(crate) refs: Vec<Rid>,
}

/// `refs` sorted, each once.
pub(crate) fn ref_set(refs: impl Iterator<Item = Rid>) -> Vec<Rid> {
    let mut out: Vec<Rid> = refs.collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// One locale of an entity: its working draft and what is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Variant {
    pub(crate) locale: Locale,
    pub(crate) draft: Body,
    /// For a translation, the revision of the entity's own locale it was
    /// translated from; 0 for the entity's own locale.
    pub(crate) source: u32,
    pub(crate) published: Option<Published>,
}

/// What the store keeps per entity: its identity, and per locale its
/// working draft and what is published (a published body is a stored
/// revision). The first variant is the entity's own locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Head {
    pub(crate) rid: Rid,
    pub(crate) kind: String,
    pub(crate) site: String,
    pub(crate) created_ms: u64,
    pub(crate) updated_ms: u64,
    pub(crate) status: Status,
    pub(crate) visibility: Visibility,
    /// The newest revision number of any locale; 0 before the first.
    pub(crate) last_revision: u32,
    pub(crate) first_published_ms: u64,
    pub(crate) variants: Vec<Variant>,
    /// Paths the entity was served at when it was trashed, now gone (410),
    /// with the locale each served.
    pub(crate) gone: Vec<(Locale, String)>,
    /// Its authors, in order, shared by every locale.
    pub(crate) authors: Vec<AccountId>,
    /// Its parent in the page tree.
    pub(crate) parent: Option<Rid>,
    /// Its place among its parent's children.
    pub(crate) order: i64,
}

impl Head {
    /// The entity's own locale.
    pub(crate) fn base(&self) -> &Variant {
        // A head always has its own locale: decode refuses one without.
        &self.variants[0]
    }

    pub(crate) fn variant(&self, locale: Locale) -> Option<&Variant> {
        self.variants.iter().find(|v| v.locale == locale)
    }

    pub(crate) fn variant_mut(&mut self, locale: Locale) -> Option<&mut Variant> {
        self.variants.iter_mut().find(|v| v.locale == locale)
    }

    /// Add `locale` with `draft`, translated from revision `source`.
    pub(crate) fn add_variant(&mut self, locale: Locale, draft: Body, source: u32) -> Result<()> {
        if self.variants.len() >= MAX_VARIANTS {
            return Err(Error::invalid("entity", "has 64 locales already"));
        }
        self.variants.push(Variant {
            locale,
            draft,
            source,
            published: None,
        });
        Ok(())
    }

    /// True when any locale is published.
    pub(crate) fn is_published(&self) -> bool {
        self.variants.iter().any(|v| v.published.is_some())
    }

    /// Every entity the head refers to: from each locale's draft and
    /// published body, sorted, each once.
    pub(crate) fn refs(&self) -> Vec<Rid> {
        ref_set(
            self.variants
                .iter()
                .flat_map(|v| {
                    v.draft
                        .refs()
                        .chain(v.published.iter().flat_map(|p| p.refs.iter().copied()))
                })
                .chain(self.parent),
        )
    }

    /// When any locale was last published; 0 when none is.
    pub(crate) fn last_published_ms(&self) -> u64 {
        self.variants
            .iter()
            .filter_map(|v| v.published.as_ref().map(|p| p.at_ms))
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u8(HEAD_FORMAT);
        w.bytes(self.rid.as_bytes());
        w.u64(self.created_ms);
        w.u64(self.updated_ms);
        w.str16(&self.kind)?;
        w.str16(&self.site)?;
        w.u8(self.status.code());
        w.u8(self.visibility.code());
        w.u32(self.last_revision);
        w.u64(self.first_published_ms);
        w.u8(self.variants.len() as u8);
        for v in &self.variants {
            v.locale.write(&mut w);
            w.u32(v.source);
            match &v.published {
                Some(p) => {
                    w.u32(p.revision);
                    w.u64(p.at_ms);
                    w.str16(p.path.as_deref().unwrap_or(""))?;
                    w.u16(p.refs.len() as u16);
                    for rid in &p.refs {
                        w.bytes(rid.as_bytes());
                    }
                }
                None => {
                    w.u32(0);
                    w.u64(0);
                    w.str16("")?;
                    w.u16(0);
                }
            }
            w.str16(v.draft.path.as_deref().unwrap_or(""))?;
            write_fields(&mut w, &v.draft.fields)?;
        }
        w.u16(self.gone.len() as u16);
        for (locale, path) in &self.gone {
            locale.write(&mut w);
            w.str16(path)?;
        }
        w.u8(self.authors.len() as u8);
        for account in &self.authors {
            w.bytes(account.as_bytes());
        }
        match self.parent {
            Some(parent) => {
                w.u8(1);
                w.bytes(parent.as_bytes());
            }
            None => w.u8(0),
        }
        w.i64(self.order);
        Ok(out)
    }

    /// Decode a stored head. A record from 0.1 to 0.3 reads as an entity in
    /// [`Locale::EN`] published at revision 1, its draft the same; its body
    /// is the record's own (see [`is_legacy`](Self::is_legacy)).
    pub(crate) fn decode(bytes: &[u8], at: u64) -> Result<Head> {
        let mut r = Reader::new(bytes, "an entity record", at);
        match r.u8()? {
            RECORD_FORMAT => {
                let rid = Rid::from_bytes(r.fixed()?);
                let created_ms = r.u64()?;
                let revision = r.u32()?;
                let kind = r.str16()?.to_owned();
                let site = r.str16()?.to_owned();
                let path = Some(r.str16()?.to_owned()).filter(|p| !p.is_empty());
                let fields = read_fields(&mut r, at)?;
                r.finish()?;
                Ok(Head {
                    rid,
                    kind,
                    site,
                    created_ms,
                    updated_ms: created_ms,
                    status: Status::Published,
                    visibility: Visibility::Public,
                    last_revision: revision,
                    first_published_ms: created_ms,
                    variants: vec![Variant {
                        locale: Locale::EN,
                        published: Some(Published {
                            revision,
                            at_ms: created_ms,
                            path: path.clone(),
                            refs: Vec::new(),
                        }),
                        draft: Body { path, fields },
                        source: 0,
                    }],
                    gone: Vec::new(),
                    authors: Vec::new(),
                    parent: None,
                    order: 0,
                }
                .with_draft_refs())
            }
            format @ (HEAD_FORMAT_2 | HEAD_FORMAT_3 | HEAD_FORMAT) => {
                let rid = Rid::from_bytes(r.fixed()?);
                let created_ms = r.u64()?;
                let updated_ms = r.u64()?;
                let kind = r.str16()?.to_owned();
                let site = r.str16()?.to_owned();
                let status = Status::of(r.u8()?, at)?;
                let visibility = Visibility::of(r.u8()?, at)?;
                let last_revision = r.u32()?;
                let first_published_ms = r.u64()?;
                let count = r.u8()?;
                if count == 0 {
                    return Err(Error::corrupt("an entity without a locale", at));
                }
                let mut variants = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let locale = Locale::read(&mut r, at)?;
                    let source = r.u32()?;
                    let revision = r.u32()?;
                    let published_ms = r.u64()?;
                    let published_path = Some(r.str16()?.to_owned()).filter(|p| !p.is_empty());
                    let mut refs = Vec::new();
                    if format != HEAD_FORMAT_2 {
                        for _ in 0..r.u16()? {
                            refs.push(Rid::from_bytes(r.fixed()?));
                        }
                    }
                    let draft_path = Some(r.str16()?.to_owned()).filter(|p| !p.is_empty());
                    let fields = read_fields(&mut r, at)?;
                    variants.push(Variant {
                        locale,
                        draft: Body {
                            path: draft_path,
                            fields,
                        },
                        source,
                        published: (revision != 0).then_some(Published {
                            revision,
                            at_ms: published_ms,
                            path: published_path,
                            refs,
                        }),
                    });
                }
                let mut gone = Vec::new();
                for _ in 0..r.u16()? {
                    let locale = Locale::read(&mut r, at)?;
                    gone.push((locale, r.str16()?.to_owned()));
                }
                let mut authors = Vec::new();
                let mut parent = None;
                let mut order = 0;
                if format == HEAD_FORMAT {
                    let count = usize::from(r.u8()?);
                    if count > MAX_AUTHORS {
                        return Err(Error::corrupt("an entity's authors", at));
                    }
                    for _ in 0..count {
                        authors.push(AccountId::from_bytes(r.fixed()?));
                    }
                    parent = match r.u8()? {
                        0 => None,
                        1 => Some(Rid::from_bytes(r.fixed()?)),
                        _ => return Err(Error::corrupt("an entity's parent", at)),
                    };
                    order = r.i64()?;
                }
                r.finish()?;
                let head = Head {
                    authors,
                    parent,
                    order,
                    rid,
                    kind,
                    site,
                    created_ms,
                    updated_ms,
                    status,
                    visibility,
                    last_revision,
                    first_published_ms,
                    variants,
                    gone,
                };
                Ok(if format == HEAD_FORMAT_2 {
                    head.with_draft_refs()
                } else {
                    head
                })
            }
            _ => Err(Error::corrupt("an entity record format", at)),
        }
    }

    /// For a format that does not store the references of published
    /// bodies: take them from the drafts.
    fn with_draft_refs(mut self) -> Head {
        for v in &mut self.variants {
            let refs = ref_set(v.draft.refs());
            if let Some(p) = &mut v.published {
                p.refs = refs;
            }
        }
        self
    }

    /// True for a record stored by 0.1 to 0.3, whose published body is its
    /// draft (there is no stored revision).
    pub(crate) fn is_legacy(bytes: &[u8]) -> bool {
        bytes.first() == Some(&RECORD_FORMAT)
    }

    /// True for a record of a format whose references are in the store
    /// (format 3 on).
    pub(crate) fn is_current(bytes: &[u8]) -> bool {
        matches!(bytes.first(), Some(&(HEAD_FORMAT_3 | HEAD_FORMAT)))
    }

    /// The entry a reader sees for `body` of `locale` at `revision`;
    /// `asked` is the locale the reader asked for, when another was served.
    pub(crate) fn entry(
        &self,
        locale: Locale,
        revision: u32,
        body: Body,
        asked: Option<Locale>,
    ) -> Entry {
        let published_ms = self
            .variant(locale)
            .and_then(|v| v.published.as_ref())
            .map_or(0, |p| p.at_ms);
        Entry {
            rid: self.rid,
            kind: self.kind.clone(),
            created_ms: self.created_ms,
            updated_ms: self.updated_ms,
            revision,
            site: self.site.clone(),
            path: body.path,
            fields: body.fields,
            status: self.status,
            visibility: self.visibility,
            published_ms,
            first_published_ms: self.first_published_ms,
            locale,
            fallback: asked.filter(|a| *a != locale),
            authors: self.authors.clone(),
            parent: self.parent,
            order: self.order,
        }
    }
}

/// A fixed revision: the body as it was, when, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Revision {
    pub(crate) locale: Locale,
    pub(crate) at_ms: u64,
    pub(crate) message: String,
    pub(crate) body: Body,
}

impl Revision {
    pub(crate) fn new(locale: Locale, at_ms: u64, message: &str, body: Body) -> Result<Revision> {
        if message.len() > MAX_MESSAGE {
            return Err(Error::invalid("revision message", "at most 1024 bytes"));
        }
        Ok(Revision {
            locale,
            at_ms,
            message: message.to_owned(),
            body,
        })
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u8(REVISION_FORMAT);
        self.locale.write(&mut w);
        w.u64(self.at_ms);
        w.str16(&self.message)?;
        w.str16(self.body.path.as_deref().unwrap_or(""))?;
        write_fields(&mut w, &self.body.fields)?;
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8], at: u64) -> Result<Revision> {
        let mut r = Reader::new(bytes, "an entity revision", at);
        if r.u8()? != REVISION_FORMAT {
            return Err(Error::corrupt("an entity revision format", at));
        }
        let locale = Locale::read(&mut r, at)?;
        let at_ms = r.u64()?;
        let message = r.str16()?.to_owned();
        let path = Some(r.str16()?.to_owned()).filter(|p| !p.is_empty());
        let fields = read_fields(&mut r, at)?;
        r.finish()?;
        Ok(Revision {
            locale,
            at_ms,
            message,
            body: Body { path, fields },
        })
    }
}

/// A revision as [`revisions`](crate::Content::revisions) lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionInfo {
    pub(crate) number: u32,
    pub(crate) locale: Locale,
    pub(crate) at_ms: u64,
    pub(crate) message: String,
}

impl RevisionInfo {
    /// The revision number, from 1.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// The locale it is in.
    #[must_use]
    pub const fn locale(&self) -> Locale {
        self.locale
    }

    /// When it was recorded.
    #[must_use]
    pub fn at(&self) -> SystemTime {
        crate::core::time_of(self.at_ms)
    }

    /// The message it was recorded with.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Encode a route as stored.
pub(crate) fn encode_route(entry: &RouteEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(26);
    let mut w = Writer::new(&mut out);
    w.u8(ROUTE_FORMAT);
    match entry.kind {
        RouteKind::Page => {
            w.u8(1);
            w.u16(0);
            w.bytes(entry.entity.as_bytes());
        }
        RouteKind::Redirect { to, status } => {
            w.u8(2);
            w.u16(status);
            w.bytes(to.as_bytes());
        }
        RouteKind::Gone => {
            w.u8(3);
            w.u16(0);
            w.bytes(entry.entity.as_bytes());
        }
    }
    w.bytes(entry.entity.as_bytes());
    w.u32(entry.revision);
    w.u8(entry.visibility.code());
    entry.locale.write(&mut w);
    out
}

pub(crate) fn decode_route(bytes: &[u8], at: u64) -> Result<RouteEntry> {
    let mut r = Reader::new(bytes, "a route record", at);
    if r.u8()? != ROUTE_FORMAT {
        return Err(Error::corrupt("a route record format", at));
    }
    let kind = r.u8()?;
    let status = r.u16()?;
    let target = Rid::from_bytes(r.fixed()?);
    let entity = Rid::from_bytes(r.fixed()?);
    let revision = r.u32()?;
    let visibility = Visibility::of(r.u8()?, at)?;
    let locale = Locale::read(&mut r, at)?;
    r.finish()?;
    let kind = match kind {
        1 => RouteKind::Page,
        2 => RouteKind::Redirect { to: target, status },
        3 => RouteKind::Gone,
        _ => return Err(Error::corrupt("a route kind", at)),
    };
    Ok(RouteEntry {
        entity,
        revision,
        kind,
        visibility,
        locale,
    })
}

pub(crate) fn check_name(what: &'static str, name: &str) -> Result<()> {
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

/// An entity as a reader sees it: the published revision from
/// [`Content::get`](crate::Content::get), or the working draft from
/// [`Content::draft`](crate::Content::draft).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    rid: Rid,
    kind: String,
    created_ms: u64,
    updated_ms: u64,
    revision: u32,
    site: String,
    path: Option<String>,
    fields: Vec<(String, Value)>,
    status: Status,
    visibility: Visibility,
    published_ms: u64,
    first_published_ms: u64,
    locale: Locale,
    fallback: Option<Locale>,
    authors: Vec<AccountId>,
    parent: Option<Rid>,
    order: i64,
}

impl Entry {
    /// The entity's authors, in order.
    #[must_use]
    pub fn authors(&self) -> &[AccountId] {
        &self.authors
    }

    /// The entity's parent in the page tree, if it has one.
    #[must_use]
    pub const fn parent(&self) -> Option<Rid> {
        self.parent
    }

    /// The entity's place among its parent's children.
    #[must_use]
    pub const fn order(&self) -> i64 {
        self.order
    }

    /// The locale of this entry.
    #[must_use]
    pub const fn locale(&self) -> Locale {
        self.locale
    }

    /// The locale asked for, when it had nothing published and this
    /// entry's locale was served in its place.
    #[must_use]
    pub const fn fallback(&self) -> Option<Locale> {
        self.fallback
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

    /// The revision number: the one published, or for a draft the newest
    /// recorded (0 before the first).
    #[must_use]
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// Where the entity is in its life.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }

    /// Who may see it when published.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// When the entity last changed.
    #[must_use]
    pub fn updated_at(&self) -> SystemTime {
        crate::core::time_of(self.updated_ms)
    }

    /// When the published revision was published, if one is.
    #[must_use]
    pub fn published_at(&self) -> Option<SystemTime> {
        (self.published_ms != 0).then(|| crate::core::time_of(self.published_ms))
    }

    /// When the entity was first published, if ever.
    #[must_use]
    pub fn first_published_at(&self) -> Option<SystemTime> {
        (self.first_published_ms != 0).then(|| crate::core::time_of(self.first_published_ms))
    }

    /// When the entity was created.
    #[must_use]
    pub fn created_at(&self) -> SystemTime {
        crate::core::time_of(self.created_ms)
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
    /// The path moved: answer `status` (301 when an entity's path changed)
    /// with the current path of the entity `to`, which
    /// [`Entry::route`] gives.
    Redirect {
        /// The entity the path now belongs to.
        to: Rid,
        /// The HTTP status: 301, 302, 307, or 308.
        status: u16,
    },
    /// The entity is gone for good: answer 410.
    Gone,
}

/// A resolved route, as [`Content::resolve`](crate::Content::resolve) returns
/// it. Resolving allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteEntry {
    pub(crate) entity: Rid,
    pub(crate) revision: u32,
    pub(crate) kind: RouteKind,
    pub(crate) visibility: Visibility,
    pub(crate) locale: Locale,
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

    /// Who may see the page. For anything but [`Visibility::Public`] the
    /// application checks the session before serving it.
    #[must_use]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// The locale the path serves.
    #[must_use]
    pub const fn locale(&self) -> Locale {
        self.locale
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> Rid {
        Rid::from_bytes([9; 16])
    }

    #[test]
    fn test_head_round_trips_every_value_kind() {
        let account = AccountId::from_bytes([1; 16]);
        let entity = Entity::new("profile")
            .field("name", "Ann")
            .field("age", 40_i64)
            .field("public", true)
            .field("account", account)
            .field("parent", rid())
            .site("example.com")
            .path("/u/ann");
        let mut head = entity.into_head(rid(), 5, Locale::EN).unwrap();
        head.variants[0].published = Some(Published {
            revision: 2,
            at_ms: 6,
            path: Some("/u/ann".into()),
            refs: vec![rid()],
        });
        let fr = Locale::new("fr").unwrap();
        head.add_variant(fr, head.variants[0].draft.clone(), 2)
            .unwrap();
        head.last_revision = 3;
        head.authors = vec![account];
        head.parent = Some(Rid::from_bytes([4; 16]));
        head.order = -7;
        head.first_published_ms = 4;
        let back = Head::decode(&head.encode().unwrap(), 0).unwrap();
        assert_eq!(back, head);
        let entry = back.entry(Locale::EN, 2, back.base().draft.clone(), Some(fr));
        assert_eq!(entry.fallback(), Some(fr));
        assert_eq!(back.variant(fr).map(|v| v.source), Some(2));
        assert_eq!(entry.rid(), rid());
        assert_eq!(entry.kind(), "profile");
        assert_eq!(entry.revision(), 2);
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
        assert_eq!(entry.created_at(), crate::core::time_of(5));
        assert_eq!(entry.published_at(), Some(crate::core::time_of(6)));
    }

    #[test]
    fn test_old_record_reads_as_published_revision_one() {
        let bytes = Entity::new("note")
            .field("a", "b")
            .path("/n")
            .encode_v1(rid(), 7)
            .unwrap();
        assert!(Head::is_legacy(&bytes));
        let head = Head::decode(&bytes, 0).unwrap();
        assert_eq!(head.status, Status::Published);
        assert_eq!(head.base().published.as_ref().map(|p| p.revision), Some(1));
        assert_eq!(head.base().draft.path.as_deref(), Some("/n"));
        assert_eq!(head.base().locale, Locale::EN);
        assert_eq!(head.site, DEFAULT_SITE);
    }

    #[test]
    fn test_into_head_rejects_bad_input() {
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
            let shown = format!("{entity:?}");
            assert!(
                matches!(
                    entity.into_head(rid(), 0, Locale::EN),
                    Err(Error::Invalid { .. })
                ),
                "{shown}"
            );
        }
    }

    #[test]
    fn test_patch_sets_removes_and_moves() {
        let mut body = Body {
            path: Some("/a".into()),
            fields: vec![("x".into(), Value::Int(1)), ("y".into(), Value::Int(2))],
        };
        Patch::new()
            .set("x", 5_i64)
            .set("z", "new")
            .remove("y")
            .path("/b")
            .apply(&mut body)
            .unwrap();
        assert_eq!(body.path.as_deref(), Some("/b"));
        assert_eq!(
            body.fields,
            vec![
                ("x".into(), Value::Int(5)),
                ("z".into(), Value::Text("new".into()))
            ]
        );
        assert!(Patch::new().path("bad").apply(&mut body).is_err());
    }

    #[test]
    fn test_revision_and_route_round_trip_and_truncations_are_corrupt() {
        let rev = Revision::new(
            Locale::EN,
            9,
            "first",
            Body {
                path: Some("/x".into()),
                fields: vec![("a".into(), Value::Bool(true))],
            },
        )
        .unwrap();
        let bytes = rev.encode().unwrap();
        assert_eq!(Revision::decode(&bytes, 0).unwrap(), rev);
        for len in 0..bytes.len() {
            assert!(Revision::decode(&bytes[..len], 0).is_err(), "prefix {len}");
        }
        for kind in [
            RouteKind::Page,
            RouteKind::Redirect {
                to: Rid::from_bytes([3; 16]),
                status: 301,
            },
            RouteKind::Gone,
        ] {
            let entry = RouteEntry {
                entity: rid(),
                revision: 4,
                kind,
                visibility: Visibility::Members,
                locale: Locale::EN,
            };
            assert_eq!(decode_route(&encode_route(&entry), 0).unwrap(), entry);
        }
        let head = Entity::new("p")
            .path("/x")
            .into_head(rid(), 0, Locale::EN)
            .unwrap();
        let bytes = head.encode().unwrap();
        for len in 0..bytes.len() {
            assert!(Head::decode(&bytes[..len], 0).is_err(), "prefix {len}");
        }
    }
}
