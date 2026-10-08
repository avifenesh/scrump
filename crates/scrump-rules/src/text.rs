//! Hand-coded detectors for the text profile (`scrump --profile text`).
//!
//! Text from agent transcripts, tool output and config carries secrets in
//! shapes a prefix-anchored ruleset never sees: `password: swordfish`,
//! `Environment=API_TOKEN=…`, `--password x`, `Authorization: Bearer …`, a
//! bare base64 key body. The same shapes are everywhere in prose and code
//! as non-secrets (`multi-token prediction`, `max_tokens=4096`,
//! `token: expires`, `hadToken=false`), so each detector here pairs a wide
//! regex with a post filter that reads the key and the value.

use regex::bytes::Regex;
use scrump_core::{Detector, Replacement};
use std::sync::OnceLock;

/// The text profile's hand-coded detectors.
pub fn detectors() -> Vec<Box<dyn Detector>> {
    let mut v = KeyValueSecret::variants();
    v.extend(FlagSecret::variants());
    v.extend(DeclarationSecret::variants());
    v.push(Box::new(AuthHeader));
    v.push(Box::new(KeyBody));
    v
}

const MASK: &[u8] = b"*";

fn mask() -> Replacement {
    Replacement::Pattern(MASK.to_vec())
}

// ---- key = value ------------------------------------------------------------

/// `key = value`, `key: value`, `"key": "value"`, `\"key\":\"value\"`,
/// `cfg["key"] = "value"`, `key := value`, `key => value`. The value is the
/// hit; the key decides whether it is a credential. One detector per way of
/// quoting the value, so the hit is the text inside the quotes and the
/// output stays valid JSON, YAML or shell.
pub struct KeyValueSecret {
    id: &'static str,
    regex: &'static OnceLock<Regex>,
    value: &'static str,
}

/// The key part shared by every variant: it must carry a credential word,
/// so the leftmost match starts at the real key. In
/// `svc:2:Environment=API_TOKEN=x` neither `svc` nor `Environment` can
/// match and `API_TOKEN` does.
const KEY: &str = r#"(?i)(?:^|[^A-Za-z0-9])_?(?:[a-z0-9]+[_-]?)*(?:token|secret|password|passwd|passphrase|pass|pwd|api[_-]?key|private[_-]?key|access[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key|session[_-]?key|license[_-]?key|app[_-]?key|client[_-]?secret|auth|credentials?|cookie)(?:[_-]?[a-z0-9]+)*\\?["']?\]?[ \t]*(?::=|=>|[=:])[ \t]*"#;

static KV_DQ: OnceLock<Regex> = OnceLock::new();
static KV_SQ: OnceLock<Regex> = OnceLock::new();
static KV_ESC: OnceLock<Regex> = OnceLock::new();
static KV_BARE: OnceLock<Regex> = OnceLock::new();

const KV_VARIANTS: &[(&str, &OnceLock<Regex>, &str)] = &[
    // "value" with escapes kept whole
    (
        "text_key_value_secret_dq",
        &KV_DQ,
        r#""((?:\\.|[^"\\]){4,1000})""#,
    ),
    ("text_key_value_secret_sq", &KV_SQ, r#"'([^']{4,1000})'"#),
    // \"value\" inside a JSON string holding JSON
    (
        "text_key_value_secret_esc",
        &KV_ESC,
        r#"\\"((?:[^"\\]|\\[^"]){4,1000})\\""#,
    ),
    // bare value: stops at whitespace, quotes, & ; , } and a literal \n
    (
        "text_key_value_secret",
        &KV_BARE,
        r#"((?:[^\s'",}&;\\]|\\[^nrt"]){4,512})"#,
    ),
];

impl KeyValueSecret {
    pub fn variants() -> Vec<Box<dyn Detector>> {
        KV_VARIANTS
            .iter()
            .map(|(id, cell, value)| {
                Box::new(KeyValueSecret {
                    id,
                    regex: cell,
                    value,
                }) as Box<dyn Detector>
            })
            .collect()
    }
}

impl Detector for KeyValueSecret {
    fn id(&self) -> &str {
        self.id
    }
    fn pattern(&self) -> &Regex {
        self.regex
            .get_or_init(|| ascii_regex(&format!("{KEY}{}", self.value)))
    }
    fn capture_index(&self) -> Option<usize> {
        Some(1)
    }
    fn replacement(&self) -> Replacement {
        mask()
    }
    fn post_filter_with_context(&self, candidate: &[u8], before: &[u8], _after: &[u8]) -> bool {
        let Some((key, sep)) = key_before(tail(before)) else {
            return false;
        };
        value_is_secret(&key, sep, candidate)
    }
}

/// The last bytes of a context slice. Filters read only the end of the
/// text before a candidate; the whole prefix would make a scan quadratic.
fn tail(before: &[u8]) -> &[u8] {
    &before[before.len().saturating_sub(256)..]
}

/// Compile with Unicode off: these rules are ASCII shapes, and byte
/// classes make the scan several times faster on large text.
fn ascii_regex(pattern: &str) -> Regex {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|e| panic!("text rule regex {pattern}: {e}"))
}

// ---- --flag value -----------------------------------------------------------

/// `--password x`, `--db-password=x`, `--api-key "x"` style flags whose
/// name carries a credential word. One detector per way of quoting the
/// value. A value never starts with `-`, so `--verbose --password x` does
/// not take the next flag as the value.
pub struct FlagSecret {
    id: &'static str,
    regex: &'static OnceLock<Regex>,
    value: &'static str,
}

const FLAG: &str = r#"(?i)(?:^|[\s"'(])--?[a-z][a-z0-9_-]*[ =]+"#;

static FL_DQ: OnceLock<Regex> = OnceLock::new();
static FL_SQ: OnceLock<Regex> = OnceLock::new();
static FL_BARE: OnceLock<Regex> = OnceLock::new();

const FLAG_VARIANTS: &[(&str, &OnceLock<Regex>, &str)] = &[
    ("text_flag_secret_dq", &FL_DQ, r#""([^"]{4,1000})""#),
    ("text_flag_secret_sq", &FL_SQ, r#"'([^']{4,1000})'"#),
    ("text_flag_secret", &FL_BARE, r#"([^\s'"-][^\s'"]{3,511})"#),
];

impl FlagSecret {
    pub fn variants() -> Vec<Box<dyn Detector>> {
        FLAG_VARIANTS
            .iter()
            .map(|(id, cell, value)| {
                Box::new(FlagSecret {
                    id,
                    regex: cell,
                    value,
                }) as Box<dyn Detector>
            })
            .collect()
    }
}

impl Detector for FlagSecret {
    fn id(&self) -> &str {
        self.id
    }
    fn pattern(&self) -> &Regex {
        self.regex
            .get_or_init(|| ascii_regex(&format!("{FLAG}{}", self.value)))
    }
    fn capture_index(&self) -> Option<usize> {
        Some(1)
    }
    fn replacement(&self) -> Replacement {
        mask()
    }
    fn post_filter_with_context(&self, candidate: &[u8], before: &[u8], _after: &[u8]) -> bool {
        // before ends with `--flag `, `--flag=` or `--flag "`.
        let before = tail(before);
        let mut i = before.len();
        while i > 0 && matches!(before[i - 1], b' ' | b'\t' | b'=' | b'"' | b'\'') {
            i -= 1;
        }
        let end = i;
        while i > 0
            && (before[i - 1].is_ascii_alphanumeric() || matches!(before[i - 1], b'_' | b'-'))
        {
            i -= 1;
        }
        let flag = String::from_utf8_lossy(&before[i..end]);
        let name = flag.trim_start_matches('-');
        if !flag.starts_with('-') || name.is_empty() {
            return false;
        }
        value_is_secret(name, b'=', candidate)
    }
}

// ---- var password string = "x" ----------------------------------------------

/// Go and TypeScript declarations: `var password string = "x"`,
/// `const token: string = "x"`, `let apiKey = "x"`. One detector per way of
/// quoting the value.
pub struct DeclarationSecret {
    id: &'static str,
    regex: &'static OnceLock<Regex>,
    value: &'static str,
}

const DECL: &str =
    r#"(?i)\b(?:var|const|let)\s+[a-z_][a-z0-9_]*(?:\s+string|\s*:\s*string)?\s*=\s*"#;

static DE_DQ: OnceLock<Regex> = OnceLock::new();
static DE_SQ: OnceLock<Regex> = OnceLock::new();
static DE_BARE: OnceLock<Regex> = OnceLock::new();

const DECL_VARIANTS: &[(&str, &OnceLock<Regex>, &str)] = &[
    ("text_declaration_secret_dq", &DE_DQ, r#""([^"]{4,1000})""#),
    ("text_declaration_secret_sq", &DE_SQ, r#"'([^']{4,1000})'"#),
    ("text_declaration_secret", &DE_BARE, r#"([^\s'",;]{4,512})"#),
];

impl DeclarationSecret {
    pub fn variants() -> Vec<Box<dyn Detector>> {
        DECL_VARIANTS
            .iter()
            .map(|(id, cell, value)| {
                Box::new(DeclarationSecret {
                    id,
                    regex: cell,
                    value,
                }) as Box<dyn Detector>
            })
            .collect()
    }
}

impl Detector for DeclarationSecret {
    fn id(&self) -> &str {
        self.id
    }
    fn pattern(&self) -> &Regex {
        self.regex
            .get_or_init(|| ascii_regex(&format!("{DECL}{}", self.value)))
    }
    fn capture_index(&self) -> Option<usize> {
        Some(1)
    }
    fn replacement(&self) -> Replacement {
        mask()
    }
    fn post_filter_with_context(&self, candidate: &[u8], before: &[u8], _after: &[u8]) -> bool {
        // before ends with `name string = ` or `name: string = ` or `name = `,
        // then an opening quote for the quoted variants.
        let s = String::from_utf8_lossy(tail(before));
        let s = s
            .trim_end()
            .trim_end_matches(['"', '\''])
            .trim_end()
            .trim_end_matches('=')
            .trim_end();
        let s = s
            .strip_suffix("string")
            .map_or(s, |x| x.trim_end().trim_end_matches(':').trim_end());
        let name: String = s
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        value_is_secret(&name, b'=', candidate)
    }
}

// ---- Authorization headers --------------------------------------------------

/// `Bearer x`, `token x`, `Basic x`. Prose such as "token 36" or "Basic
/// principles" has no credential shape and is left alone.
pub struct AuthHeader;

impl Detector for AuthHeader {
    fn id(&self) -> &str {
        "text_auth_header"
    }
    fn pattern(&self) -> &Regex {
        static R: OnceLock<Regex> = OnceLock::new();
        R.get_or_init(|| {
            ascii_regex(
                r"(?i)\b(?:bearer|token|basic|apikey|api-key|digest)\s+([A-Za-z0-9._+/=-]{8,})",
            )
        })
    }
    fn capture_index(&self) -> Option<usize> {
        Some(1)
    }
    fn replacement(&self) -> Replacement {
        mask()
    }
    fn post_filter_with_context(&self, candidate: &[u8], before: &[u8], _after: &[u8]) -> bool {
        if already_masked(candidate) {
            return false;
        }
        let scheme = String::from_utf8_lossy(tail(before))
            .trim_end()
            .rsplit(|c: char| !c.is_ascii_alphabetic() && c != '-')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let v = candidate;
        let digit = v.iter().any(|b| b.is_ascii_digit());
        let letter = v.iter().any(|b| b.is_ascii_alphabetic());
        match scheme.as_str() {
            "basic" => {
                // base64 of user:pass has mixed case or digits; a word does not.
                let lower = v.iter().all(|b| !b.is_ascii_uppercase());
                let upper = v.iter().all(|b| !b.is_ascii_lowercase());
                v.len() >= 16
                    && (digit || !(lower || upper))
                    && v.iter().all(|b| {
                        b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'='
                    })
            }
            "bearer" | "apikey" | "api-key" => v.len() >= 20 || (digit && letter),
            "digest" => v.len() >= 16,
            _ => digit && letter,
        }
    }
}

// ---- bare key bodies --------------------------------------------------------

/// A base64 run of private-key-body length. One grep hit per line would
/// otherwise rebuild a key without its header. Paths, slugs, dated file
/// names and hex digests do not look random.
pub struct KeyBody;

impl Detector for KeyBody {
    fn id(&self) -> &str {
        "text_key_body"
    }
    fn pattern(&self) -> &Regex {
        static R: OnceLock<Regex> = OnceLock::new();
        R.get_or_init(|| ascii_regex(r"(?:sha[0-9]{3}-)?[A-Za-z0-9+/]{60,}={0,2}"))
    }
    fn replacement(&self) -> Replacement {
        mask()
    }
    fn post_filter(&self, candidate: &[u8]) -> bool {
        // npm integrity fields (sha512-...) are hashes, not keys.
        !candidate.starts_with(b"sha") && looks_random(candidate)
    }
}

// ---- shared judgement -------------------------------------------------------

/// The key that ends `before`, with the separator that followed it:
/// `Environment=API_TOKEN=` gives ("API_TOKEN", '='); `"password": "`
/// gives ("password", ':').
fn key_before(before: &[u8]) -> Option<(String, u8)> {
    let mut i = before.len();
    // Skip the opening quote or backslash of the value, spaces, and the
    // separator, remembering the separator.
    let mut sep = 0u8;
    while i > 0 {
        let b = before[i - 1];
        match b {
            b' ' | b'\t' | b'"' | b'\'' | b'\\' | b']' | b'>' => i -= 1,
            b'=' | b':' => {
                sep = b;
                i -= 1;
                // `:=` and `=>`
                if i > 0 && (before[i - 1] == b':' || before[i - 1] == b'=') {
                    i -= 1;
                }
                break;
            }
            _ => return None,
        }
    }
    if sep == 0 {
        return None;
    }
    while i > 0 && matches!(before[i - 1], b' ' | b'\t' | b'"' | b'\'' | b'\\' | b']') {
        i -= 1;
    }
    let end = i;
    while i > 0
        && (before[i - 1].is_ascii_alphanumeric() || before[i - 1] == b'_' || before[i - 1] == b'-')
    {
        i -= 1;
    }
    if i == end {
        return None;
    }
    Some((String::from_utf8_lossy(&before[i..end]).into_owned(), sep))
}

fn value_is_secret(key: &str, sep: u8, value: &[u8]) -> bool {
    if already_masked(value)
        || is_boolean(value)
        || is_var_ref(value)
        || is_code(value)
        || is_placeholder(value)
    {
        return false;
    }
    let bare = trim_quotes(value);
    let lk = key.to_ascii_lowercase().replace('-', "_");
    // Counts: tokens_per_second=12345, total_tokens: 4096, #new-token: 4096,
    // ms/token = 80.6. A short number under a token-named key is a count; a
    // run of 16 or more digits (api_token=4827193650284716) is a token.
    if lk.contains("token") && is_number(bare) && bare.len() < 16 {
        return false;
    }
    // *_tokens settings hold counts or names, not secrets, unless random.
    if lk.contains("tokens") && !looks_random(bare) {
        return false;
    }
    if !secret_key(key) && !key_shaped(key, bare) {
        return false;
    }
    // "token: expires", "PASS: Laya", "auth: scrypt" are labels in prose or
    // YAML, not credential fields.
    // An upper-case label (PASS:, FAIL:, STATUS:) names whatever word follows.
    if sep == b':'
        && is_plain_word(bare)
        && label_key(key)
        && (bare.len() <= 10 || key == key.to_ascii_uppercase())
    {
        return false;
    }
    true
}

fn trim_quotes(v: &[u8]) -> &[u8] {
    let mut s = v;
    while let Some((f, rest)) = s.split_first() {
        if matches!(f, b'"' | b'\'' | b'\\') {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((l, rest)) = s.split_last() {
        if matches!(l, b'"' | b'\'' | b'\\' | b'.' | b',' | b';' | b')' | b'`') {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn already_masked(v: &[u8]) -> bool {
    let b = trim_quotes(v);
    b.starts_with(b"[REDACTED]") || b.starts_with(&[MASK[0]; 4])
}

fn is_boolean(v: &[u8]) -> bool {
    matches!(
        String::from_utf8_lossy(trim_quotes(v))
            .to_ascii_lowercase()
            .as_str(),
        "true" | "false" | "null" | "none" | "nil" | "yes" | "no"
    )
}

/// `$VAR`, `${VAR}`, `$(cmd)`: a reference to a secret, not the secret.
fn is_var_ref(v: &[u8]) -> bool {
    let b = trim_quotes(v);
    if b.first() != Some(&b'$') {
        return false;
    }
    let rest = &b[1..];
    if rest.first() == Some(&b'(') {
        return true;
    }
    let name = rest.strip_prefix(b"{").unwrap_or(rest);
    let name = name.strip_suffix(b"}").unwrap_or(name);
    // ${X:-default}: the name part decides
    let name = match name.iter().position(|c| *c == b':') {
        Some(i) if rest.first() == Some(&b'{') => &name[..i],
        _ => name,
    };
    !name.is_empty()
        && (name[0].is_ascii_alphabetic() || name[0] == b'_')
        && name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && (name.iter().all(|c| !c.is_ascii_lowercase())
            || name.iter().all(|c| !c.is_ascii_uppercase()))
}

/// Code, not a value: identifier chains, calls, indexing and type names
/// (`process.env.X`, `getToken()`, `os.environ["X"]`, `string`, `Optional[str]`).
fn is_code(v: &[u8]) -> bool {
    let b = trim_quotes(v);
    let s = String::from_utf8_lossy(b);
    let s = s.trim_end_matches([';', ',']);
    if matches!(
        s,
        "string"
            | "number"
            | "str"
            | "bool"
            | "boolean"
            | "int"
            | "float"
            | "bytes"
            | "any"
            | "object"
            | "undefined"
            | "String"
            | "&str"
    ) || s.starts_with("Optional[")
        || s.starts_with("Option<")
    {
        return true;
    }
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let Some(first) = s.chars().next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    let body: String = s.chars().take_while(|c| ident(*c) || *c == '.').collect();
    let rest = &s[body.len()..];
    let dotted = body.contains('.')
        && !body.ends_with('.')
        && body
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(ident));
    // config.apiKey, getToken(), environ["X"]
    rest.starts_with('(') || rest.starts_with('[') || (dotted && rest.is_empty())
}

/// `<think>`, `<your-key-here>`, `...`: a placeholder, not a value.
fn is_placeholder(v: &[u8]) -> bool {
    let b = trim_quotes(v);
    (b.first() == Some(&b'<') && b.last() == Some(&b'>'))
        || b.iter().all(|c| *c == b'.' || *c == b'x' || *c == b'X')
}

fn is_number(v: &[u8]) -> bool {
    !v.is_empty()
        && v[0].is_ascii_digit()
        && v.iter().all(|c| {
            c.is_ascii_digit() || matches!(c, b'.' | b',' | b'_' | b'%') || c.is_ascii_lowercase()
        })
        && v.iter().filter(|c| c.is_ascii_lowercase()).count() <= 3
}

fn is_plain_word(v: &[u8]) -> bool {
    !v.is_empty() && v.iter().all(|c| c.is_ascii_alphabetic())
}

/// A key that reads as a label or a mode (PASS:, auth:, token:), not a field.
fn label_key(key: &str) -> bool {
    let lk = key.to_ascii_lowercase();
    if lk == "token"
        || lk.ends_with("_token")
        || lk.ends_with("-token")
        || matches!(lk.as_str(), "auth" | "pass" | "cookie")
    {
        return true;
    }
    key == key.to_ascii_uppercase() && !key.contains(['_', '-'])
}

const SECRET_WORDS: &[&str] = &[
    "token",
    "secret",
    "secrets",
    "password",
    "passwd",
    "passphrase",
    "pass",
    "pwd",
    "pw",
    "pgpass",
    "dbpass",
    "apikey",
    "api_key",
    "privatekey",
    "private_key",
    "clientsecret",
    "client_secret",
    "accesskey",
    "access_key",
    "cookie",
    "auth",
    "credential",
    "credentials",
];

/// Does the key name a credential? One of its segments is a secret word
/// (api_key, DB_PASSWORD, authToken, _authToken) or the segments run
/// together (dbpassword, GITHUBTOKEN), and no segment marks it as a
/// setting (token_url, password_file, max_tokens, tokenizer, bypass).
pub fn secret_key(key: &str) -> bool {
    // camelCase and kebab-case to snake: authToken -> auth_token, db-password -> db_password
    let mut snake = String::with_capacity(key.len() + 4);
    let orig = key.trim_start_matches(['-', '_']);
    let mut prev_lower = false;
    for c in orig.chars() {
        if c.is_ascii_uppercase() && prev_lower {
            snake.push('_');
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        snake.push(if c == '-' {
            '_'
        } else {
            c.to_ascii_lowercase()
        });
    }
    let k = snake.clone();
    if plain_key(&k) {
        return false;
    }
    let segs: Vec<&str> = snake
        .split(['_', '-', '.'])
        .filter(|s| !s.is_empty())
        .collect();
    for (i, seg) in segs.iter().enumerate() {
        if SECRET_WORDS.contains(seg) {
            return true;
        }
        if let Some(next) = segs.get(i + 1) {
            let joined = format!("{seg}_{next}");
            if SECRET_WORDS.contains(&joined.as_str()) {
                return true;
            }
        }
    }
    let flat: String = k
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | '.'))
        .collect();
    for w in [
        "token",
        "secret",
        "password",
        "passwd",
        "passphrase",
        "apikey",
        "privatekey",
        "authkey",
        "accesskey",
        "rootpass",
        "adminpass",
        "mysqlpwd",
    ] {
        if flat.contains(w) && !flat.contains("tokeniz") && !flat.contains("secretary") {
            return true;
        }
    }
    false
}

/// A key whose value is never a secret.
fn plain_key(k: &str) -> bool {
    for p in [
        "start_token",
        "end_token",
        "stop_token",
        "sep_token",
        "cls_token",
        "mask_token",
        "special_token",
        "next_page_token",
        "page_token",
        "max_token",
        "token_count",
        "tokenizer",
        "eos_token",
        "bos_token",
        "pad_token",
        "unk_token",
        "secretname",
        "secret_name",
        "secret_ref",
    ] {
        if k.contains(p) {
            return true;
        }
    }
    for suf in [
        "_url",
        "_uri",
        "_file",
        "_path",
        "_name",
        "_id",
        "_len",
        "_length",
        "_count",
        "_limit",
        "_ttl",
        "_expiry",
        "_expires",
        "_expires_at",
        "_type",
        "_method",
        "_mode",
        "_provider",
        "_endpoint",
        "_header",
        "_policy",
        "_budget",
        "_version",
        "_scheme",
        "_source",
        "_kind",
        "_format",
    ] {
        if k.ends_with(suf) {
            return true;
        }
    }
    false
}

/// A `*_key` setting holding key material: 20+ characters with a digit.
/// Object and cache keys are paths or colon-joined names and are skipped
/// unless the value is standard base64 of key length.
fn key_shaped(key: &str, v: &[u8]) -> bool {
    let k = key.to_ascii_lowercase();
    if !k.ends_with("key") {
        return false;
    }
    for p in [
        "primary",
        "cache",
        "sort",
        "foreign",
        "partition",
        "public",
        "pubkey",
        "ssh",
        "hot",
        "idempotency",
        "dedup",
        "row",
        "keyboard",
        "monkey",
        "turkey",
    ] {
        if k.contains(p) {
            return false;
        }
    }
    let b64 = v.len() >= 32
        && v.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'='));
    if (v.contains(&b'/') || v.contains(&b':')) && !b64 {
        return false;
    }
    v.len() >= 20 && v.iter().any(|c| c.is_ascii_digit())
}

/// Key material has about half of its letters upper case and several
/// digits, and does not split into plain words; paths, slugs, dated file
/// names and hex digests fail one of those.
pub fn looks_random(m: &[u8]) -> bool {
    let (mut up, mut lo, mut dg) = (0usize, 0usize, 0usize);
    for &c in m {
        if c.is_ascii_uppercase() {
            up += 1;
        } else if c.is_ascii_lowercase() {
            lo += 1;
        } else if c.is_ascii_digit() {
            dg += 1;
        }
    }
    if up == 0 || lo == 0 || dg < 3 {
        return false;
    }
    let ratio = up as f64 / (up + lo) as f64;
    if !(0.25..=0.75).contains(&ratio) {
        return false;
    }
    let segs: Vec<&[u8]> = m
        .split(|c| matches!(c, b'/' | b'-' | b'_' | b'+'))
        .filter(|s| !s.is_empty())
        .collect();
    let words = segs
        .iter()
        .filter(|s| {
            s.len() >= 4
                && s.iter().all(|c| c.is_ascii_alphabetic())
                && (s.iter().all(|c| !c.is_ascii_uppercase())
                    || s[1..].iter().all(|c| !c.is_ascii_uppercase()))
        })
        .count();
    !(segs.len() >= 3 && words * 2 >= segs.len())
}
