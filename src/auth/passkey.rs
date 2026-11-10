//! Passkeys (WebAuthn), feature `mfa`: the relying party's half.
//!
//! The browser's `navigator.credentials` calls run in the application's
//! page; nex-db makes the challenges, checks what comes back (the client
//! data, the authenticator data, and the signature), and keeps each
//! credential's public key and signature counter. Signatures are checked by
//! crypt-io (`ES256`, `EdDSA`, `RS256`).

use std::fmt;

use crypt_io::Zeroizing;

use crate::{
    error::{Error, Result},
    ids::AccountId,
};

/// Format of a stored passkey record.
const FORMAT: u8 = 1;
/// Longest client data accepted, in bytes.
const MAX_CLIENT_DATA: usize = 4096;
/// Longest credential id accepted (WebAuthn allows up to 1,023 bytes).
const MAX_CREDENTIAL_ID: usize = 1023;

/// Authenticator data flags.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// The site passkeys belong to: its RP ID (a domain, `example.com`) and
/// the origins its pages are served from (`https://example.com`).
///
/// ```
/// use nex_db::RelyingParty;
/// let rp = RelyingParty::new("example.com", "https://example.com")
///     .origin("https://www.example.com")
///     .require_user_verification();
/// # let _ = rp;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct RelyingParty {
    pub(crate) id: String,
    pub(crate) origins: Vec<String>,
    pub(crate) user_verification: bool,
}

impl RelyingParty {
    /// The site with RP ID `id`, served from `origin`.
    pub fn new(id: impl Into<String>, origin: impl Into<String>) -> RelyingParty {
        RelyingParty {
            id: id.into(),
            origins: vec![origin.into()],
            user_verification: false,
        }
    }

    /// Another origin the site is served from.
    pub fn origin(mut self, origin: impl Into<String>) -> RelyingParty {
        self.origins.push(origin.into());
        self
    }

    /// Refuse a passkey use the authenticator did not verify the user for
    /// (a PIN or biometric), not only their presence.
    pub fn require_user_verification(mut self) -> RelyingParty {
        self.user_verification = true;
        self
    }
}

/// A challenge for the browser, from
/// [`passkey_registration`](crate::Auth::passkey_registration) or
/// [`passkey_sign_in`](crate::Auth::passkey_sign_in): pass its bytes as
/// the `challenge` of `navigator.credentials.create` or `.get`. It works
/// once, within five minutes.
pub struct PasskeyChallenge {
    pub(crate) bytes: Zeroizing<[u8; 32]>,
}

impl PasskeyChallenge {
    /// The challenge's 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// The challenge in base64url without padding, as pages usually carry
    /// it.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        base64url_encode(&self.bytes[..])
    }
}

impl fmt::Debug for PasskeyChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasskeyChallenge").finish_non_exhaustive()
    }
}

/// What `navigator.credentials.create` returned, for
/// [`add_passkey`](crate::Auth::add_passkey): the response's
/// `clientDataJSON` and `getAuthenticatorData()`, as bytes.
#[derive(Debug, Clone, Copy)]
pub struct PasskeyRegistration<'a> {
    pub(crate) client_data_json: &'a [u8],
    pub(crate) authenticator_data: &'a [u8],
}

impl<'a> PasskeyRegistration<'a> {
    /// The registration response's parts.
    #[must_use]
    pub const fn new(client_data_json: &'a [u8], authenticator_data: &'a [u8]) -> Self {
        PasskeyRegistration {
            client_data_json,
            authenticator_data,
        }
    }
}

/// What `navigator.credentials.get` returned, for
/// [`verify_passkey`](crate::Auth::verify_passkey): the credential's
/// `rawId`, and the response's `clientDataJSON`, `authenticatorData`, and
/// `signature`, as bytes.
#[derive(Debug, Clone, Copy)]
pub struct PasskeyAssertion<'a> {
    pub(crate) credential_id: &'a [u8],
    pub(crate) client_data_json: &'a [u8],
    pub(crate) authenticator_data: &'a [u8],
    pub(crate) signature: &'a [u8],
}

impl<'a> PasskeyAssertion<'a> {
    /// The assertion's parts.
    #[must_use]
    pub const fn new(
        credential_id: &'a [u8],
        client_data_json: &'a [u8],
        authenticator_data: &'a [u8],
        signature: &'a [u8],
    ) -> Self {
        PasskeyAssertion {
            credential_id,
            client_data_json,
            authenticator_data,
            signature,
        }
    }
}

/// The id of a stored passkey, for listing and removing it: a keyed digest
/// of the credential id, not the credential id itself. Its text form is 32
/// hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PasskeyId(pub(crate) [u8; 16]);

impl fmt::Debug for PasskeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PasskeyId({self})")
    }
}

impl fmt::Display for PasskeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for PasskeyId {
    type Err = Error;

    fn from_str(text: &str) -> Result<PasskeyId> {
        let bad = || Error::invalid("passkey id", "not 32 hex digits");
        if text.len() != 32 {
            return Err(bad());
        }
        let mut id = [0; 16];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2).ok_or_else(bad)?, 16)
                .map_err(|_| bad())?;
        }
        Ok(PasskeyId(id))
    }
}

/// One passkey of an account, as [`passkeys`](crate::Auth::passkeys)
/// lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    pub(crate) id: PasskeyId,
    pub(crate) created_ms: u64,
    pub(crate) last_used_ms: u64,
}

impl PasskeyInfo {
    /// The passkey's id.
    #[must_use]
    pub const fn id(&self) -> PasskeyId {
        self.id
    }

    /// When it was added.
    #[must_use]
    pub fn created_at(&self) -> std::time::SystemTime {
        crate::core::time_of(self.created_ms)
    }

    /// When it last signed in, if ever.
    #[must_use]
    pub fn last_used_at(&self) -> Option<std::time::SystemTime> {
        (self.last_used_ms != 0).then(|| crate::core::time_of(self.last_used_ms))
    }
}

/// A stored passkey: whose it is, its COSE public key, its signature
/// counter, and its times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasskeyRecord {
    pub(crate) account: AccountId,
    pub(crate) cose_key: Vec<u8>,
    pub(crate) sign_count: u32,
    pub(crate) created_ms: u64,
    pub(crate) last_used_ms: u64,
}

impl PasskeyRecord {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40 + self.cose_key.len());
        out.push(FORMAT);
        out.extend_from_slice(self.account.as_bytes());
        out.extend_from_slice(&self.sign_count.to_le_bytes());
        out.extend_from_slice(&self.created_ms.to_le_bytes());
        out.extend_from_slice(&self.last_used_ms.to_le_bytes());
        out.extend_from_slice(&self.cose_key);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<PasskeyRecord> {
        let corrupt = || Error::corrupt("a passkey record", 0);
        if bytes.len() < 37 || bytes[0] != FORMAT {
            return Err(corrupt());
        }
        let u64_at = |at: usize| {
            let mut b = [0; 8];
            b.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(b)
        };
        let mut account = [0; 16];
        account.copy_from_slice(&bytes[1..17]);
        let mut count = [0; 4];
        count.copy_from_slice(&bytes[17..21]);
        Ok(PasskeyRecord {
            account: AccountId::from_bytes(account),
            sign_count: u32::from_le_bytes(count),
            created_ms: u64_at(21),
            last_used_ms: u64_at(29),
            cose_key: bytes[37..].to_vec(),
        })
    }
}

/// What the client data says.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientData {
    pub(crate) kind: String,
    pub(crate) challenge: Vec<u8>,
    pub(crate) origin: String,
    pub(crate) cross_origin: bool,
}

/// Check client data against what the relying party expects: its type
/// (`webauthn.create` or `webauthn.get`), an origin of the site, and not
/// cross-origin. Returns the challenge it carries.
pub(crate) fn check_client_data(
    rp: &RelyingParty,
    json: &[u8],
    kind: &str,
) -> Option<Zeroizing<[u8; 32]>> {
    let data = parse_client_data(json)?;
    if data.kind != kind || data.cross_origin || !rp.origins.contains(&data.origin) {
        return None;
    }
    let mut challenge = Zeroizing::new([0; 32]);
    if data.challenge.len() != 32 {
        return None;
    }
    challenge.copy_from_slice(&data.challenge);
    Some(challenge)
}

/// The authenticator data's parts.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthData<'a> {
    pub(crate) rp_id_hash: &'a [u8],
    pub(crate) flags: u8,
    pub(crate) sign_count: u32,
    /// For a registration: the credential id and its COSE public key.
    pub(crate) credential: Option<(&'a [u8], &'a [u8])>,
}

/// Parse authenticator data (WebAuthn section 6.1). Attested credential
/// data with extensions after it is refused: the key's end cannot be told
/// without a CBOR reader, and registrations rarely carry extensions.
pub(crate) fn parse_auth_data(bytes: &[u8]) -> Option<AuthData<'_>> {
    if bytes.len() < 37 {
        return None;
    }
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    let credential = if flags & FLAG_AT != 0 {
        if flags & FLAG_ED != 0 {
            return None;
        }
        let rest = bytes.get(37..)?;
        let id_len = usize::from(u16::from_be_bytes([*rest.get(16)?, *rest.get(17)?]));
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID {
            return None;
        }
        let id = rest.get(18..18 + id_len)?;
        let key = rest.get(18 + id_len..)?;
        if key.is_empty() {
            return None;
        }
        Some((id, key))
    } else {
        if bytes.len() != 37 && flags & FLAG_ED == 0 {
            return None;
        }
        None
    };
    Some(AuthData {
        rp_id_hash: &bytes[..32],
        flags,
        sign_count,
        credential,
    })
}

/// True when `data`'s flags satisfy `rp`: the user was present, and
/// verified when the relying party requires it.
pub(crate) fn flags_ok(rp: &RelyingParty, data: &AuthData<'_>) -> bool {
    data.flags & FLAG_UP != 0 && (!rp.user_verification || data.flags & FLAG_UV != 0)
}

fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let symbols = chunk.len() + 1;
        for i in 0..symbols {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// Decode base64url, with or without padding; `None` for anything else.
fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    // Leftover bits must be zero (a canonical encoding).
    (buffer & ((1 << bits) - 1) == 0).then_some(out)
}

/// A small, strict reader for the client data: a JSON object whose `type`,
/// `challenge`, and `origin` are strings and `crossOrigin` a boolean;
/// other members are skipped. A repeated member, or anything that is not
/// JSON, gives `None`.
fn parse_client_data(json: &[u8]) -> Option<ClientData> {
    if json.len() > MAX_CLIENT_DATA {
        return None;
    }
    let mut r = Json { bytes: json, at: 0 };
    let (mut kind, mut challenge, mut origin, mut cross) = (None, None, None, None);
    r.expect(b'{')?;
    let mut first = true;
    loop {
        r.ws();
        if r.peek()? == b'}' {
            r.at += 1;
            break;
        }
        if !first {
            r.expect(b',')?;
        }
        first = false;
        let key = r.string()?;
        r.expect(b':')?;
        let slot = match key.as_str() {
            "type" => Some(&mut kind),
            "challenge" => Some(&mut challenge),
            "origin" => Some(&mut origin),
            _ => None,
        };
        match slot {
            Some(slot) => {
                if slot.is_some() {
                    return None;
                }
                *slot = Some(r.string()?);
            }
            None if key == "crossOrigin" => {
                if cross.is_some() {
                    return None;
                }
                cross = Some(r.boolean()?);
            }
            None => r.skip()?,
        }
    }
    r.ws();
    if r.at != json.len() {
        return None;
    }
    Some(ClientData {
        kind: kind?,
        challenge: base64url_decode(&challenge?)?,
        origin: origin?,
        cross_origin: cross.unwrap_or(false),
    })
}

struct Json<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Json<'_> {
    fn ws(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.bytes.get(self.at).copied()
    }

    fn expect(&mut self, b: u8) -> Option<()> {
        (self.peek()? == b).then(|| self.at += 1)
    }

    fn string(&mut self) -> Option<String> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            let b = *self.bytes.get(self.at)?;
            self.at += 1;
            match b {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let e = *self.bytes.get(self.at)?;
                    self.at += 1;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hex =
                                std::str::from_utf8(self.bytes.get(self.at..self.at + 4)?).ok()?;
                            self.at += 4;
                            char::from_u32(u32::from_str_radix(hex, 16).ok()?)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0..=0x1f => return None,
                _ => out.push(b),
            }
        }
    }

    fn boolean(&mut self) -> Option<bool> {
        self.ws();
        let rest = self.bytes.get(self.at..)?;
        if rest.starts_with(b"true") {
            self.at += 4;
            Some(true)
        } else if rest.starts_with(b"false") {
            self.at += 5;
            Some(false)
        } else {
            None
        }
    }

    /// Skip one value of any kind, nested at most 16 deep.
    fn skip(&mut self) -> Option<()> {
        self.skip_at(0)
    }

    fn skip_at(&mut self, depth: usize) -> Option<()> {
        if depth > 16 {
            return None;
        }
        match self.peek()? {
            b'"' => self.string().map(|_| ()),
            b'{' | b'[' => {
                let close = if self.peek()? == b'{' { b'}' } else { b']' };
                let object = close == b'}';
                self.at += 1;
                if self.peek()? == close {
                    self.at += 1;
                    return Some(());
                }
                loop {
                    if object {
                        let _ = self.string()?;
                        self.expect(b':')?;
                    }
                    self.skip_at(depth + 1)?;
                    match self.peek()? {
                        b',' => self.at += 1,
                        c if c == close => {
                            self.at += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b't' | b'f' => self.boolean().map(|_| ()),
            b'n' => {
                let rest = self.bytes.get(self.at..)?;
                rest.starts_with(b"null").then(|| self.at += 4)
            }
            b'-' | b'0'..=b'9' => {
                let start = self.at;
                while matches!(
                    self.bytes.get(self.at),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.at += 1;
                }
                (self.at > start).then_some(())
            }
            _ => None,
        }
    }
}

/// Runs this module's decoders on `data`, for fuzzing and tests. Errors are
/// expected; a panic, a hang, or an allocation the input asked for is a bug.
#[cfg(any(fuzzing, test))]
pub(crate) fn fuzz(data: &[u8]) {
    let _ = PasskeyRecord::decode(data);
    let _ = parse_auth_data(data);
    let _ = parse_client_data(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_data_is_read_strictly() {
        let rp = RelyingParty::new("example.com", "https://example.com");
        let challenge = [7u8; 32];
        let json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://example.com","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex","tokenBinding":{{"status":"present","id":[1,2.5,null,true]}}}}"#,
            base64url_encode(&challenge)
        );
        assert_eq!(
            *check_client_data(&rp, json.as_bytes(), "webauthn.get").unwrap(),
            challenge
        );
        assert!(check_client_data(&rp, json.as_bytes(), "webauthn.create").is_none());
        let other = RelyingParty::new("example.com", "https://evil.example");
        assert!(check_client_data(&other, json.as_bytes(), "webauthn.get").is_none());
        let cross = json.replace(r#""crossOrigin":false"#, r#""crossOrigin":true"#);
        assert!(check_client_data(&rp, cross.as_bytes(), "webauthn.get").is_none());
        let twice = json.replace(
            r#""type":"webauthn.get","#,
            r#""type":"webauthn.get","type":"webauthn.get","#,
        );
        assert!(parse_client_data(twice.as_bytes()).is_none());
        assert!(parse_client_data(b"{\"type\":\"x\"").is_none());
        assert!(parse_client_data(b"[]").is_none());
        let escaped = br#"{"type":"webauthn.get","challenge":"AA","origin":"https:\/\/abc"}"#;
        assert_eq!(parse_client_data(escaped).unwrap().origin, "https://abc");
    }

    #[test]
    fn test_base64url_round_trips() {
        for n in 0..40u8 {
            let bytes: Vec<u8> = (0..n).collect();
            assert_eq!(base64url_decode(&base64url_encode(&bytes)).unwrap(), bytes);
        }
        assert_eq!(base64url_decode("AQ==").unwrap(), vec![1]);
        assert!(base64url_decode("A+").is_none());
        assert!(base64url_decode("AR").is_none());
    }

    #[test]
    fn test_auth_data_parses_and_refuses_extensions() {
        let mut data = vec![9u8; 32];
        data.push(FLAG_UP);
        data.extend_from_slice(&5u32.to_be_bytes());
        let parsed = parse_auth_data(&data).unwrap();
        assert_eq!((parsed.flags, parsed.sign_count), (FLAG_UP, 5));
        assert!(parsed.credential.is_none());
        let mut reg = data.clone();
        reg[32] |= FLAG_AT;
        reg.extend_from_slice(&[0; 16]);
        reg.extend_from_slice(&3u16.to_be_bytes());
        reg.extend_from_slice(b"abc");
        reg.extend_from_slice(b"KEY");
        assert_eq!(
            parse_auth_data(&reg).unwrap().credential,
            Some((&b"abc"[..], &b"KEY"[..]))
        );
        let mut ext = reg.clone();
        ext[32] |= FLAG_ED;
        assert!(parse_auth_data(&ext).is_none());
        assert!(parse_auth_data(&data[..36]).is_none());
        let rp = RelyingParty::new("a", "b").require_user_verification();
        assert!(!flags_ok(&rp, &parsed));
        let record = PasskeyRecord {
            account: AccountId::from_bytes([1; 16]),
            cose_key: vec![1, 2, 3],
            sign_count: 4,
            created_ms: 5,
            last_used_ms: 6,
        };
        assert_eq!(PasskeyRecord::decode(&record.encode()).unwrap(), record);
    }
}
