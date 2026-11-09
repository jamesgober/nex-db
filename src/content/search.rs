//! The text index: the published bodies of each locale, word by word.
//!
//! Derived, like the listing index: rebuilt from the entity heads and their
//! published revisions at open, and updated as commits apply. Only fields
//! a type declares searchable are indexed, each with its weight. Words are
//! runs of letters and digits, lowercased; each Han, kana, or other CJK
//! ideograph is a word of its own. English locales drop common stopwords
//! and stem with the Porter algorithm; other locales keep words as they
//! are. A query matches entities holding every one of its words, ranked by
//! BM25 over the weighted fields.

use std::{
    collections::HashMap,
    sync::{PoisonError, RwLock},
};

use super::{
    entity::{Body, Head, Value},
    lists::MAX_PAGE,
    locale::Locale,
    types::Types,
};
use crate::{
    error::{Error, Result},
    ids::Rid,
};

/// Longest word indexed, in bytes; longer runs are skipped.
const MAX_WORD: usize = 64;
/// Longest query, in bytes.
const MAX_QUERY: usize = 1024;
/// Most distinct words in one query.
const MAX_QUERY_WORDS: usize = 16;
/// Hits in a page when no limit is set.
const DEFAULT_HITS: usize = 10;
/// BM25 parameters.
const K1: f64 = 1.2;
const B: f64 = 0.75;

/// A text search, for [`Content::search`](crate::Content::search).
///
/// ```
/// use nex_db::Search;
/// let query = Search::new("rust tips").kind("post").limit(20);
/// # let _ = query;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Search {
    text: String,
    kind: Option<String>,
    site: Option<String>,
    term: Option<Rid>,
    limit: usize,
    offset: usize,
}

impl Search {
    /// Entities holding every word of `text` (at most 1,024 bytes and 16
    /// distinct words) in a searchable field.
    pub fn new(text: impl Into<String>) -> Search {
        Search {
            text: text.into(),
            kind: None,
            site: None,
            term: None,
            limit: DEFAULT_HITS,
            offset: 0,
        }
    }

    /// Only entities of type `kind`.
    pub fn kind(mut self, kind: impl Into<String>) -> Search {
        self.kind = Some(kind.into());
        self
    }

    /// Only entities of `site`.
    pub fn site(mut self, site: impl Into<String>) -> Search {
        self.site = Some(site.into());
        self
    }

    /// Only entities whose published body refers to `term`.
    pub fn term(mut self, term: Rid) -> Search {
        self.term = Some(term);
        self
    }

    /// At most `n` hits (1 to 1,000; default 10).
    pub fn limit(mut self, n: usize) -> Search {
        self.limit = n.clamp(1, MAX_PAGE);
        self
    }

    /// Skip the first `n` hits, for the pages after the first.
    pub fn offset(mut self, n: usize) -> Search {
        self.offset = n;
        self
    }
}

/// One entity a search found.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Hit {
    rid: Rid,
    score: f32,
}

impl Hit {
    /// The entity.
    #[must_use]
    pub const fn rid(&self) -> Rid {
        self.rid
    }

    /// Its BM25 score: higher is a better match. Scores compare within one
    /// search only.
    #[must_use]
    pub const fn score(&self) -> f32 {
        self.score
    }
}

/// The hits of one search, best first.
#[derive(Debug, Clone, PartialEq)]
pub struct Hits {
    items: Vec<Hit>,
    total: usize,
}

impl Hits {
    /// The hits of this page.
    #[must_use]
    pub fn items(&self) -> &[Hit] {
        &self.items
    }

    /// The hits, owned.
    #[must_use]
    pub fn into_items(self) -> Vec<Hit> {
        self.items
    }

    /// How many entities matched, on every page.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }
}

/// One indexed published body.
#[derive(Debug)]
struct Doc {
    revision: u32,
    kind: String,
    site: String,
    refs: Vec<Rid>,
    /// Its weighted length.
    len: f64,
    /// Its words, each once.
    words: Vec<Box<str>>,
}

/// The index of one locale.
#[derive(Debug, Default)]
struct Shelf {
    /// Each word's entities and weighted counts.
    words: HashMap<Box<str>, HashMap<Rid, f32>>,
    docs: HashMap<Rid, Doc>,
    total_len: f64,
}

impl Shelf {
    fn remove(&mut self, rid: Rid) {
        let Some(doc) = self.docs.remove(&rid) else {
            return;
        };
        self.total_len -= doc.len;
        for word in &doc.words {
            if let Some(postings) = self.words.get_mut(word) {
                let _ = postings.remove(&rid);
                if postings.is_empty() {
                    let _ = self.words.remove(word);
                }
            }
        }
    }

    fn insert(&mut self, rid: Rid, doc: Doc, counts: HashMap<Box<str>, f32>) {
        self.total_len += doc.len;
        for (word, count) in counts {
            let _ = self.words.entry(word).or_default().insert(rid, count);
        }
        let _ = self.docs.insert(rid, doc);
    }
}

/// Published bodies by locale, word by word.
#[derive(Debug, Default)]
pub(crate) struct SearchIndex {
    shelves: RwLock<HashMap<Locale, Shelf>>,
}

/// What one locale of an entity indexes: its revision, document, and
/// weighted word counts.
type Indexed = (Locale, Doc, HashMap<Box<str>, f32>);

impl SearchIndex {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Place `head` as it now is. `published` reads the body of one of its
    /// published revisions; it is called only for a type with searchable
    /// fields, and only for a locale whose published revision changed
    /// (all of them when `fresh`, after the searchable fields changed).
    pub(crate) fn update(
        &self,
        types: &Types,
        head: &Head,
        fresh: bool,
        mut published: impl FnMut(Locale, u32) -> Result<Body>,
    ) -> Result<()> {
        let fields = types.searchable(&head.kind);
        let held: Vec<(Locale, u32)> = {
            let shelves = self.shelves.read().unwrap_or_else(PoisonError::into_inner);
            shelves
                .iter()
                .filter_map(|(l, s)| s.docs.get(&head.rid).map(|d| (*l, d.revision)))
                .collect()
        };
        let mut next: Vec<Indexed> = Vec::new();
        let mut keep: Vec<Locale> = Vec::new();
        if !fields.is_empty() {
            for variant in &head.variants {
                let Some(p) = &variant.published else {
                    continue;
                };
                if !fresh && held.contains(&(variant.locale, p.revision)) {
                    keep.push(variant.locale);
                    continue;
                }
                let body = published(variant.locale, p.revision)?;
                let english = is_english(variant.locale);
                let mut counts: HashMap<Box<str>, f32> = HashMap::new();
                let mut len = 0.0;
                for (name, weight) in fields {
                    let Some((_, value)) = body.fields.iter().find(|(n, _)| n == name) else {
                        continue;
                    };
                    let weight = f32::from(*weight);
                    for text in texts(value) {
                        words(text, english, |word| {
                            *counts.entry(word.into()).or_default() += weight;
                            len += f64::from(weight);
                        });
                    }
                }
                let doc = Doc {
                    revision: p.revision,
                    kind: head.kind.clone(),
                    site: head.site.clone(),
                    refs: p.refs.clone(),
                    len,
                    words: counts.keys().cloned().collect(),
                };
                next.push((variant.locale, doc, counts));
            }
        }
        let mut shelves = self.shelves.write().unwrap_or_else(PoisonError::into_inner);
        for (locale, shelf) in shelves.iter_mut() {
            if !keep.contains(locale) {
                shelf.remove(head.rid);
            }
        }
        for (locale, doc, counts) in next {
            shelves
                .entry(locale)
                .or_default()
                .insert(head.rid, doc, counts);
        }
        shelves.retain(|_, s| !s.docs.is_empty());
        Ok(())
    }

    /// Forget `rid`: it was deleted.
    pub(crate) fn remove(&self, rid: Rid) {
        let mut shelves = self.shelves.write().unwrap_or_else(PoisonError::into_inner);
        for shelf in shelves.values_mut() {
            shelf.remove(rid);
        }
        shelves.retain(|_, s| !s.docs.is_empty());
    }

    /// The entities of `locale` matching `query`, best first.
    pub(crate) fn search(&self, locale: Locale, query: &Search) -> Result<Hits> {
        if query.text.len() > MAX_QUERY {
            return Err(Error::invalid("search", "at most 1,024 bytes"));
        }
        let mut wanted: Vec<String> = Vec::new();
        words(&query.text, is_english(locale), |w| {
            if !wanted.iter().any(|x| x == w) {
                wanted.push(w.to_owned());
            }
        });
        if wanted.len() > MAX_QUERY_WORDS {
            return Err(Error::invalid("search", "at most 16 words"));
        }
        let empty = Hits {
            items: Vec::new(),
            total: 0,
        };
        if wanted.is_empty() {
            return Ok(empty);
        }
        let shelves = self.shelves.read().unwrap_or_else(PoisonError::into_inner);
        let Some(shelf) = shelves.get(&locale) else {
            return Ok(empty);
        };
        let mut postings = Vec::with_capacity(wanted.len());
        for word in &wanted {
            match shelf.words.get(word.as_str()) {
                Some(p) => postings.push(p),
                None => return Ok(empty),
            }
        }
        // The rarest word first: its entities are the candidates.
        postings.sort_by_key(|p| p.len());
        let n = shelf.docs.len() as f64;
        let avg = (shelf.total_len / n).max(f64::MIN_POSITIVE);
        let idf: Vec<f64> = postings
            .iter()
            .map(|p| {
                let df = p.len() as f64;
                (1.0 + (n - df + 0.5) / (df + 0.5)).ln()
            })
            .collect();
        let mut hits: Vec<Hit> = Vec::new();
        for rid in postings[0].keys() {
            let Some(doc) = shelf.docs.get(rid) else {
                continue;
            };
            if query.kind.as_deref().is_some_and(|k| k != doc.kind)
                || query.site.as_deref().is_some_and(|s| s != doc.site)
                || query.term.is_some_and(|t| !doc.refs.contains(&t))
            {
                continue;
            }
            let mut score = 0.0;
            let mut all = true;
            for (p, idf) in postings.iter().zip(&idf) {
                let Some(tf) = p.get(rid) else {
                    all = false;
                    break;
                };
                let tf = f64::from(*tf);
                score += idf * tf * (K1 + 1.0) / (tf + K1 * (1.0 - B + B * doc.len / avg));
            }
            if all {
                hits.push(Hit {
                    rid: *rid,
                    score: score as f32,
                });
            }
        }
        hits.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.rid.cmp(&b.rid)));
        let total = hits.len();
        let items = hits
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();
        Ok(Hits { items, total })
    }
}

/// The text values of `value`: a text, or the texts of a list.
fn texts(value: &Value) -> impl Iterator<Item = &str> {
    let (one, list) = match value {
        Value::Text(t) => (Some(t.as_str()), &[][..]),
        Value::List(values) => (None, values.as_slice()),
        _ => (None, &[][..]),
    };
    one.into_iter().chain(list.iter().filter_map(|v| match v {
        Value::Text(t) => Some(t.as_str()),
        _ => None,
    }))
}

fn is_english(locale: Locale) -> bool {
    let tag = locale.as_str();
    tag == "en" || tag.starts_with("en-")
}

/// A Han, kana, or other CJK ideograph: a word of its own.
fn is_ideograph(c: char) -> bool {
    matches!(
        u32::from(c),
        0x3040..=0x30FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x2FFFF
    )
}

/// English words too common to index (the stopwords most search engines
/// use).
const STOPWORDS: [&str; 33] = [
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "if", "in", "into", "is", "it",
    "no", "not", "of", "on", "or", "such", "that", "the", "their", "then", "there", "these",
    "they", "this", "to", "was", "will", "with",
];

/// Hand each word of `text` to `out`: lowercased, and for English without
/// stopwords and stemmed.
fn words(text: &str, english: bool, mut out: impl FnMut(&str)) {
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut dyn FnMut(&str)| {
        if !word.is_empty() && word.len() <= MAX_WORD {
            if english {
                if !STOPWORDS.contains(&word.as_str()) {
                    out(&stem(word));
                }
            } else {
                out(word);
            }
        }
        word.clear();
    };
    for c in text.chars() {
        if is_ideograph(c) {
            flush(&mut word, &mut out);
            word.push(c);
            flush(&mut word, &mut out);
        } else if c.is_alphanumeric() {
            word.extend(c.to_lowercase());
        } else {
            flush(&mut word, &mut out);
        }
    }
    flush(&mut word, &mut out);
}

/// The Porter stem of an English word (lowercase); a word with anything
/// but ASCII letters is kept as it is.
pub(crate) fn stem(word: &str) -> String {
    if word.len() <= 2 || !word.bytes().all(|b| b.is_ascii_lowercase()) {
        return word.to_owned();
    }
    let mut p = Porter {
        b: word.as_bytes().to_vec(),
        k: word.len() as isize - 1,
        j: 0,
    };
    p.step1ab();
    if p.k > 0 {
        p.step1c();
        p.step2();
        p.step3();
        p.step4();
        p.step5();
    }
    p.b.truncate((p.k + 1) as usize);
    // Only ASCII letters went in.
    String::from_utf8(p.b).unwrap_or_default()
}

/// The Porter (1980) stemmer, after its author's reference version: `b`
/// holds the word through index `k`; `j` marks the end of a stem.
struct Porter {
    b: Vec<u8>,
    k: isize,
    j: isize,
}

impl Porter {
    fn at(&self, i: isize) -> u8 {
        self.b[i as usize]
    }

    fn cons(&self, i: isize) -> bool {
        match self.at(i) {
            b'a' | b'e' | b'i' | b'o' | b'u' => false,
            b'y' => i == 0 || !self.cons(i - 1),
            _ => true,
        }
    }

    /// The measure of the stem through `j`: its vowel-consonant sequences.
    fn m(&self) -> usize {
        let (mut n, mut i, j) = (0, 0, self.j);
        loop {
            if i > j {
                return n;
            }
            if !self.cons(i) {
                break;
            }
            i += 1;
        }
        i += 1;
        loop {
            loop {
                if i > j {
                    return n;
                }
                if self.cons(i) {
                    break;
                }
                i += 1;
            }
            i += 1;
            n += 1;
            loop {
                if i > j {
                    return n;
                }
                if !self.cons(i) {
                    break;
                }
                i += 1;
            }
            i += 1;
        }
    }

    fn vowel_in_stem(&self) -> bool {
        (0..=self.j).any(|i| !self.cons(i))
    }

    fn double_cons(&self, j: isize) -> bool {
        j >= 1 && self.at(j) == self.at(j - 1) && self.cons(j)
    }

    /// Consonant, vowel, consonant ending at `i`, the last not w, x, or y.
    fn cvc(&self, i: isize) -> bool {
        if i < 2 || !self.cons(i) || self.cons(i - 1) || !self.cons(i - 2) {
            return false;
        }
        !matches!(self.at(i), b'w' | b'x' | b'y')
    }

    fn ends(&mut self, s: &[u8]) -> bool {
        let len = s.len() as isize;
        if len > self.k + 1 {
            return false;
        }
        if &self.b[(self.k + 1 - len) as usize..=self.k as usize] != s {
            return false;
        }
        self.j = self.k - len;
        true
    }

    fn set_to(&mut self, s: &[u8]) {
        self.b.truncate((self.j + 1) as usize);
        self.b.extend_from_slice(s);
        self.k = self.j + s.len() as isize;
    }

    fn r(&mut self, s: &[u8]) {
        if self.m() > 0 {
            self.set_to(s);
        }
    }

    /// The first suffix of `rules` the word ends with takes its
    /// replacement when the stem's measure is above 0.
    fn replace_first(&mut self, rules: &[(&[u8], &[u8])]) {
        for (suffix, with) in rules {
            if self.ends(suffix) {
                self.r(with);
                return;
            }
        }
    }

    fn step1ab(&mut self) {
        if self.at(self.k) == b's' {
            if self.ends(b"sses") {
                self.k -= 2;
            } else if self.ends(b"ies") {
                self.set_to(b"i");
            } else if self.at(self.k - 1) != b's' {
                self.k -= 1;
            }
        }
        if self.ends(b"eed") {
            if self.m() > 0 {
                self.k -= 1;
            }
        } else if (self.ends(b"ed") || self.ends(b"ing")) && self.vowel_in_stem() {
            self.k = self.j;
            if self.ends(b"at") {
                self.set_to(b"ate");
            } else if self.ends(b"bl") {
                self.set_to(b"ble");
            } else if self.ends(b"iz") {
                self.set_to(b"ize");
            } else if self.double_cons(self.k) {
                if !matches!(self.at(self.k), b'l' | b's' | b'z') {
                    self.k -= 1;
                }
            } else if self.m() == 1 && self.cvc(self.k) {
                self.set_to(b"e");
            }
        }
    }

    fn step1c(&mut self) {
        if self.ends(b"y") && self.vowel_in_stem() {
            let k = self.k as usize;
            self.b[k] = b'i';
        }
    }

    fn step2(&mut self) {
        if self.k < 1 {
            return;
        }
        let rules: &[(&[u8], &[u8])] = match self.at(self.k - 1) {
            b'a' => &[(b"ational", b"ate"), (b"tional", b"tion")],
            b'c' => &[(b"enci", b"ence"), (b"anci", b"ance")],
            b'e' => &[(b"izer", b"ize")],
            b'l' => &[
                (b"bli", b"ble"),
                (b"alli", b"al"),
                (b"entli", b"ent"),
                (b"eli", b"e"),
                (b"ousli", b"ous"),
            ],
            b'o' => &[(b"ization", b"ize"), (b"ation", b"ate"), (b"ator", b"ate")],
            b's' => &[
                (b"alism", b"al"),
                (b"iveness", b"ive"),
                (b"fulness", b"ful"),
                (b"ousness", b"ous"),
            ],
            b't' => &[(b"aliti", b"al"), (b"iviti", b"ive"), (b"biliti", b"ble")],
            b'g' => &[(b"logi", b"log")],
            _ => return,
        };
        self.replace_first(rules);
    }

    fn step3(&mut self) {
        let rules: &[(&[u8], &[u8])] = match self.at(self.k) {
            b'e' => &[(b"icate", b"ic"), (b"ative", b""), (b"alize", b"al")],
            b'i' => &[(b"iciti", b"ic")],
            b'l' => &[(b"ical", b"ic"), (b"ful", b"")],
            b's' => &[(b"ness", b"")],
            _ => return,
        };
        self.replace_first(rules);
    }

    fn step4(&mut self) {
        if self.k < 1 {
            return;
        }
        let suffixes: &[&[u8]] = match self.at(self.k - 1) {
            b'a' => &[b"al"],
            b'c' => &[b"ance", b"ence"],
            b'e' => &[b"er"],
            b'i' => &[b"ic"],
            b'l' => &[b"able", b"ible"],
            b'n' => &[b"ant", b"ement", b"ment", b"ent"],
            b'o' => {
                let ion =
                    self.ends(b"ion") && self.j >= 0 && matches!(self.at(self.j), b's' | b't');
                if !ion && !self.ends(b"ou") {
                    return;
                }
                &[]
            }
            b's' => &[b"ism"],
            b't' => &[b"ate", b"iti"],
            b'u' => &[b"ous"],
            b'v' => &[b"ive"],
            b'z' => &[b"ize"],
            _ => return,
        };
        if !suffixes.is_empty() && !suffixes.iter().any(|s| self.ends(s)) {
            return;
        }
        if self.m() > 1 {
            self.k = self.j;
        }
    }

    fn step5(&mut self) {
        self.j = self.k;
        if self.at(self.k) == b'e' {
            let a = self.m();
            if a > 1 || (a == 1 && !self.cvc(self.k - 1)) {
                self.k -= 1;
            }
        }
        if self.at(self.k) == b'l' && self.double_cons(self.k) && self.m() > 1 {
            self.k -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_porter_stems_match_the_reference() {
        for (word, want) in [
            ("caresses", "caress"),
            ("ponies", "poni"),
            ("ties", "ti"),
            ("cats", "cat"),
            ("feed", "feed"),
            ("agreed", "agre"),
            ("plastered", "plaster"),
            ("motoring", "motor"),
            ("sing", "sing"),
            ("conflated", "conflat"),
            ("troubled", "troubl"),
            ("sized", "size"),
            ("hopping", "hop"),
            ("tanned", "tan"),
            ("falling", "fall"),
            ("hissing", "hiss"),
            ("fizzed", "fizz"),
            ("failing", "fail"),
            ("filing", "file"),
            ("happy", "happi"),
            ("relational", "relat"),
            ("conditional", "condit"),
            ("generalization", "gener"),
            ("running", "run"),
            ("connections", "connect"),
            ("hopefulness", "hope"),
            ("electrical", "electr"),
            ("adjustable", "adjust"),
            ("controlling", "control"),
            ("rolled", "roll"),
            ("probate", "probat"),
            ("rate", "rate"),
            ("cease", "ceas"),
            ("as", "as"),
        ] {
            assert_eq!(stem(word), want, "{word}");
        }
        assert_eq!(stem("naïve"), "naïve");
    }

    #[test]
    fn test_words_fold_case_split_ideographs_and_drop_stopwords() {
        let mut got = Vec::new();
        words("The Running-Dogs of 東京, ÉTÉ", true, |w| {
            got.push(w.to_owned())
        });
        assert_eq!(got, ["run", "dog", "東", "京", "été"]);
        got.clear();
        words("the running", false, |w| got.push(w.to_owned()));
        assert_eq!(got, ["the", "running"]);
    }
}
