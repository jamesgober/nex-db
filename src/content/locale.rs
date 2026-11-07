//! Locales and a space's locale settings.

use std::fmt;

use crate::{
    core::codec::{Reader, Writer},
    error::{Error, Result},
};

/// Longest locale tag, in bytes.
const MAX_LOCALE: usize = 15;
/// Longest fallback chain.
const MAX_CHAIN: usize = 8;
/// Most locales with their own fallback chain.
const MAX_CHAINS: usize = 64;
/// Format of stored space settings.
const SPACE_FORMAT: u8 = 1;

/// A locale such as `en`, `fr`, or `fr-CA`: a small `Copy` tag.
///
/// ```
/// use nex_db::Locale;
/// let l = Locale::new("FR-ca")?;
/// assert_eq!(l.as_str(), "fr-CA");
/// # Ok::<(), nex_db::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Locale {
    len: u8,
    bytes: [u8; MAX_LOCALE],
}

impl Locale {
    /// English, the default locale of a space that sets none.
    pub const EN: Locale = Locale {
        len: 2,
        bytes: *b"en\0\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    /// A locale from its tag: a 2 or 3 letter language, then subtags of 2
    /// to 8 letters or digits, joined by `-`; at most 15 bytes. Written in
    /// the usual case: language lower, a 2-letter region upper, a 4-letter
    /// script title case.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `tag` is not such a tag.
    pub fn new(tag: &str) -> Result<Locale> {
        let bad = || Error::invalid("locale", "must be like en, fr-CA, or zh-Hant");
        if tag.is_empty() || tag.len() > MAX_LOCALE {
            return Err(bad());
        }
        let mut out = [0u8; MAX_LOCALE];
        let mut at = 0;
        for (i, part) in tag.split('-').enumerate() {
            let ok = if i == 0 {
                (2..=3).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_alphabetic())
            } else {
                (2..=8).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_alphanumeric())
            };
            if !ok {
                return Err(bad());
            }
            if i > 0 {
                out[at] = b'-';
                at += 1;
            }
            for (j, b) in part.bytes().enumerate() {
                // A 2-letter region is upper case; a 4-letter script starts
                // with a capital; everything else is lower case.
                let upper = i > 0 && (part.len() == 2 || (part.len() == 4 && j == 0));
                out[at] = if upper {
                    b.to_ascii_uppercase()
                } else {
                    b.to_ascii_lowercase()
                };
                at += 1;
            }
        }
        Ok(Locale {
            len: at as u8,
            bytes: out,
        })
    }

    /// The tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only ASCII is ever stored.
        std::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }

    pub(crate) fn write(&self, w: &mut Writer<'_>) {
        w.u8(self.len);
        w.bytes(&self.bytes[..usize::from(self.len)]);
    }

    pub(crate) fn read(r: &mut Reader<'_>, at: u64) -> Result<Locale> {
        let len = usize::from(r.u8()?);
        let bytes = r.take(len)?;
        let text = std::str::from_utf8(bytes).map_err(|_| Error::corrupt("a stored locale", at))?;
        Locale::new(text).map_err(|_| Error::corrupt("a stored locale", at))
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Locale({})", self.as_str())
    }
}

/// A space's settings: its default locale and fallback chains.
///
/// ```
/// use nex_db::{Locale, SpaceSpec};
/// let (en, fr, fr_ca) = (Locale::new("en")?, Locale::new("fr")?, Locale::new("fr-CA")?);
/// let spec = SpaceSpec::new(en).fallback(fr_ca, &[fr, en])?;
/// # let _ = spec;
/// # Ok::<(), nex_db::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct SpaceSpec {
    pub(crate) default_locale: Locale,
    pub(crate) chains: Vec<(Locale, Vec<Locale>)>,
}

impl Default for SpaceSpec {
    fn default() -> Self {
        SpaceSpec::new(Locale::EN)
    }
}

impl SpaceSpec {
    /// Settings with `default_locale` and no fallback chains.
    pub fn new(default_locale: Locale) -> SpaceSpec {
        SpaceSpec {
            default_locale,
            chains: Vec::new(),
        }
    }

    /// When `locale` has no published revision, try `chain` in order, then
    /// the entity's own locale. Replaces an earlier chain of `locale`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a chain longer than 8, or past 64 chains.
    pub fn fallback(mut self, locale: Locale, chain: &[Locale]) -> Result<SpaceSpec> {
        if chain.len() > MAX_CHAIN {
            return Err(Error::invalid("fallback chain", "at most 8 locales"));
        }
        self.chains.retain(|(l, _)| *l != locale);
        if self.chains.len() >= MAX_CHAINS {
            return Err(Error::invalid("fallback chains", "at most 64"));
        }
        self.chains.push((locale, chain.to_vec()));
        Ok(self)
    }

    /// The space's default locale.
    #[must_use]
    pub fn default_locale(&self) -> Locale {
        self.default_locale
    }

    /// The locales to try for `locale`, in order: it, then its chain.
    pub(crate) fn order(&self, locale: Locale) -> impl Iterator<Item = Locale> + '_ {
        let chain = self
            .chains
            .iter()
            .find(|(l, _)| *l == locale)
            .map(|(_, c)| c.as_slice())
            .unwrap_or(&[]);
        std::iter::once(locale).chain(chain.iter().copied())
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut w = Writer::new(&mut out);
        w.u8(SPACE_FORMAT);
        self.default_locale.write(&mut w);
        w.u8(self.chains.len() as u8);
        for (locale, chain) in &self.chains {
            locale.write(&mut w);
            w.u8(chain.len() as u8);
            for l in chain {
                l.write(&mut w);
            }
        }
        out
    }

    pub(crate) fn decode(bytes: &[u8], at: u64) -> Result<SpaceSpec> {
        let mut r = Reader::new(bytes, "the space settings", at);
        if r.u8()? != SPACE_FORMAT {
            return Err(Error::corrupt("the space settings format", at));
        }
        let default_locale = Locale::read(&mut r, at)?;
        let mut chains = Vec::new();
        for _ in 0..r.u8()? {
            let locale = Locale::read(&mut r, at)?;
            let chain = (0..r.u8()?)
                .map(|_| Locale::read(&mut r, at))
                .collect::<Result<Vec<_>>>()?;
            chains.push((locale, chain));
        }
        r.finish()?;
        Ok(SpaceSpec {
            default_locale,
            chains,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locale_normalizes_and_refuses_junk() {
        assert_eq!(Locale::new("EN").unwrap(), Locale::EN);
        assert_eq!(Locale::new("zh-hant-tw").unwrap().as_str(), "zh-Hant-TW");
        assert_eq!(Locale::new("es-419").unwrap().as_str(), "es-419");
        for bad in [
            "",
            "e",
            "english",
            "en_",
            "en-",
            "en--us",
            "fr-CA-x-toolongsubtag",
            "é",
        ] {
            assert!(Locale::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_space_spec_round_trips_and_orders_fallbacks() {
        let l = |t| Locale::new(t).unwrap();
        let spec = SpaceSpec::new(l("en"))
            .fallback(l("fr-CA"), &[l("fr"), l("en")])
            .unwrap();
        assert_eq!(SpaceSpec::decode(&spec.encode(), 0).unwrap(), spec);
        let order: Vec<Locale> = spec.order(l("fr-CA")).collect();
        assert_eq!(order, [l("fr-CA"), l("fr"), l("en")]);
        assert_eq!(spec.order(l("de")).collect::<Vec<_>>(), [l("de")]);
    }
}
