//! Run TruffleHog's `<provider>_test.go` corpora through scrump's detection
//! engine, then report per-provider and overall pass/fail.
//!
//! The TruffleHog test files follow a regular pattern:
//!
//! ```go
//! tests := []struct {
//!     name  string
//!     input string
//!     want  []string
//! }{
//!     { name: "...", input: `...`, want: []string{"...", "..."} },
//!     { name: "invalid pattern", input: `...`, want: nil },
//! }
//! ```
//!
//! We parse those `{...}` entries with a small, format-aware Go-source
//! tokenizer (raw strings, regular strings with escapes, matching braces);
//! then for each case we run scrump's engine over `input` and verify:
//!
//!   * positive cases: every expected substring appears in at least one
//!     scrump hit whose rule_id belongs to the provider's mapped set.
//!   * negative cases (`want: nil`): no scrump hit from any of the
//!     provider's mapped rule_ids fires anywhere in the input.
//!
//! Extra hits from unrelated rules (cross-provider matches) are tolerated,
//! consistent with how a real scrubber would behave.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use scrump_core::{Chunk, ChunkOrigin};
use scrump_detect::Engine;

// ---- providers -> our rule_ids ---------------------------------------------

/// Map TruffleHog detector → its test file + the scrump rule-ids we expect
/// to fire + a tolerance flag.
///
/// `tolerate_false_positives = true` is for providers where TruffleHog's
/// detector post-filters pattern matches via verification logic that
/// scrump deliberately does **not** mirror, since for a scrubber more
/// matches = better redaction (jwt HS-signed tokens: TruffleHog filters
/// them out because the secret can't be programmatically verified;
/// scrump still wants to redact them).
#[allow(dead_code)]
struct ProviderSpec {
    name: &'static str,
    test_path: &'static str,
    rule_ids: &'static [&'static str],
    tolerate_false_positives: bool,
}

// Providers + their rule_id mapping are loaded from the JSON manifest
// produced by `th-extract`; no static list lives here any more.

// ---- minimal Go-source tokenizer for the {name,input,want} blocks ---------

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Case {
    provider: String,
    name: String,
    input: String,
    /// `None` == `want: nil` (no matches expected).
    want: Option<Vec<String>>,
}

fn parse_provider(src: &str, provider: &str) -> Vec<Case> {
    let vars = extract_vars(src);

    // Locate the `tests := []struct {` block. We accept variations on
    // whitespace and on whether the struct field types are inlined.
    let Some(start) = src.find("tests := []struct") else {
        return Vec::new();
    };
    let after_struct = &src[start..];
    // Find `}{` which separates the struct decl from the slice literal.
    let Some(open_idx) = after_struct.find("}{") else {
        return Vec::new();
    };
    let cursor_start = start + open_idx + 2;
    let bytes = src.as_bytes();
    let mut cursor = cursor_start;
    let mut out = Vec::new();

    while cursor < bytes.len() {
        cursor = skip_ws_and_comments(bytes, cursor);
        if cursor >= bytes.len() {
            break;
        }
        match bytes[cursor] {
            b'{' => {
                let end = match_brace(bytes, cursor);
                if let Some(end) = end {
                    let entry = std::str::from_utf8(&bytes[cursor + 1..end]).unwrap_or("");
                    if let Some(case) = parse_case(entry, provider, &vars) {
                        out.push(case);
                    }
                    cursor = end + 1;
                } else {
                    break;
                }
            }
            b',' => cursor += 1,
            b'}' => break, // end of slice literal
            _ => cursor += 1,
        }
    }
    out
}

/// Extract top-level `var name = "..."`, `var name = ` ``...`` `, and `var (
/// name = "..." )` declarations as a name → resolved-string map.
///
/// Best-effort: we only honour assignments whose RHS is a single string or
/// raw string literal. Concatenations, function calls, and other identifiers
/// are skipped.
fn extract_vars(src: &str) -> HashMap<String, String> {
    let bytes = src.as_bytes();
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut i = 0;
    while i < bytes.len() {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            break;
        }
        // Match top-level `var` keyword at line start.
        if (i == 0 || bytes[i - 1] == b'\n') && bytes[i..].starts_with(b"var") {
            let after = i + 3;
            if after < bytes.len()
                && (bytes[after] == b' ' || bytes[after] == b'\t' || bytes[after] == b'(')
            {
                let mut j = skip_ws_and_comments(bytes, after);
                if j < bytes.len() && bytes[j] == b'(' {
                    // var ( ... ) block
                    let end = match_paren(bytes, j).unwrap_or(bytes.len());
                    let inner = std::str::from_utf8(&bytes[j + 1..end]).unwrap_or("");
                    parse_var_block(inner, &mut vars);
                    i = end + 1;
                    continue;
                } else {
                    // var name = <literal>
                    let name_start = j;
                    while j < bytes.len() && is_ident_byte(bytes[j]) {
                        j += 1;
                    }
                    let name = std::str::from_utf8(&bytes[name_start..j])
                        .unwrap_or("")
                        .to_string();
                    j = skip_ws_and_comments(bytes, j);
                    if j < bytes.len() && bytes[j] == b'=' {
                        j += 1;
                        j = skip_ws_and_comments(bytes, j);
                        if let Some(val) = read_literal(bytes, &mut j) {
                            vars.insert(name, val);
                        }
                    }
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    vars
}

fn parse_var_block(inner: &str, vars: &mut HashMap<String, String>) {
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            break;
        }
        if !is_ident_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let name_start = i;
        while i < bytes.len() && is_ident_byte(bytes[i]) {
            i += 1;
        }
        let name = std::str::from_utf8(&bytes[name_start..i])
            .unwrap_or("")
            .to_string();
        i = skip_ws_and_comments(bytes, i);
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            i = skip_ws_and_comments(bytes, i);
            if let Some(val) = read_literal(bytes, &mut i) {
                vars.insert(name, val);
            } else {
                // Skip rest of line.
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
        } else {
            // Not a simple assignment; skip line.
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        }
    }
}

fn match_paren(b: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            b'`' => {
                i += 1;
                while i < b.len() && b[i] != b'`' {
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Read either a raw-string literal, a quoted string literal, or `nil`.
/// Returns `None` for non-literals (identifiers, function calls, …).
fn read_literal(b: &[u8], i: &mut usize) -> Option<String> {
    if *i >= b.len() {
        return None;
    }
    if b[*i] == b'`' || b[*i] == b'"' {
        return read_string(b, i);
    }
    None
}

fn skip_ws_and_comments(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        match b[i] {
            ch if ch.is_ascii_whitespace() => i += 1,
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            _ => break,
        }
    }
    i
}

/// Find the closing `}` matching the `{` at `open`. Handles nested braces,
/// strings (`"..."`), and raw strings (`` `...` ``).
fn match_brace(b: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            b'`' => {
                i += 1;
                while i < b.len() && b[i] != b'`' {
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                i += 1;
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    None
}

fn parse_case(entry: &str, provider: &str, vars: &HashMap<String, String>) -> Option<Case> {
    let bytes = entry.as_bytes();
    let mut name = String::new();
    let mut input = String::new();
    let mut want: Option<Vec<String>> = Some(Vec::new());
    let mut have_want = false;

    let mut i = 0;
    while i < bytes.len() {
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() {
            break;
        }
        let name_start = i;
        while i < bytes.len() && bytes[i] != b':' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let field = std::str::from_utf8(&bytes[name_start..i]).unwrap_or("");
        i = skip_ws_and_comments(bytes, i);
        if i >= bytes.len() || bytes[i] != b':' {
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            continue;
        }
        i += 1;
        i = skip_ws_and_comments(bytes, i);

        match field {
            "name" => {
                name = read_concat_expr(bytes, &mut i, vars);
            }
            "input" => {
                input = read_concat_expr(bytes, &mut i, vars);
            }
            "want" => {
                have_want = true;
                want = read_want(bytes, &mut i, vars);
            }
            _ => {
                skip_value(bytes, &mut i);
            }
        }
        i = skip_ws_and_comments(bytes, i);
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
        }
    }

    if !have_want && input.is_empty() {
        return None;
    }
    Some(Case {
        provider: provider.into(),
        name,
        input,
        want,
    })
}

/// Read one or more values joined by `+` (Go string concatenation). Returns
/// the concatenated result. Stops at `,`, `}`, or end of bytes.
fn read_concat_expr(b: &[u8], i: &mut usize, vars: &HashMap<String, String>) -> String {
    let mut out = String::new();
    loop {
        *i = skip_ws_and_comments(b, *i);
        if *i >= b.len() || b[*i] == b',' || b[*i] == b'}' {
            break;
        }
        let before = *i;
        if let Some(v) = read_value(b, i, vars) {
            out.push_str(&v);
        } else {
            // Unresolvable token — stop here.
            *i = before;
            break;
        }
        *i = skip_ws_and_comments(b, *i);
        if *i < b.len() && b[*i] == b'+' {
            *i += 1;
            continue;
        }
        break;
    }
    out
}

/// Read a string literal, a raw string, an identifier (resolved via `vars`),
/// or a `fmt.Sprintf("format", args...)` call (resolved by substituting %s/%v
/// placeholders with the resolved positional args).
fn read_value(b: &[u8], i: &mut usize, vars: &HashMap<String, String>) -> Option<String> {
    *i = skip_ws_and_comments(b, *i);
    if *i >= b.len() {
        return None;
    }
    if b[*i] == b'`' || b[*i] == b'"' {
        return read_string(b, i);
    }
    if is_ident_byte(b[*i]) {
        // Could be a bare identifier OR a dotted call like `fmt.Sprintf(...)`.
        let start = *i;
        while *i < b.len() && (is_ident_byte(b[*i]) || b[*i] == b'.') {
            *i += 1;
        }
        let id = std::str::from_utf8(&b[start..*i]).unwrap_or("");
        let mut j = skip_ws_and_comments(b, *i);
        if j < b.len() && b[j] == b'(' {
            j += 1;
            let args = read_call_args(b, &mut j, vars);
            *i = j;
            return resolve_call(id, &args);
        }
        return vars.get(id).cloned();
    }
    None
}

fn read_call_args(b: &[u8], i: &mut usize, vars: &HashMap<String, String>) -> Vec<String> {
    let mut args = Vec::new();
    loop {
        *i = skip_ws_and_comments(b, *i);
        if *i >= b.len() || b[*i] == b')' {
            break;
        }
        if let Some(v) = read_value(b, i, vars) {
            args.push(v);
        } else {
            // Skip the unrecognised arg up to the next comma / closing paren.
            while *i < b.len() && b[*i] != b',' && b[*i] != b')' {
                *i += 1;
            }
        }
        *i = skip_ws_and_comments(b, *i);
        if *i < b.len() && b[*i] == b',' {
            *i += 1;
        }
    }
    if *i < b.len() && b[*i] == b')' {
        *i += 1;
    }
    args
}

fn resolve_call(name: &str, args: &[String]) -> Option<String> {
    match name {
        "fmt.Sprintf" | "Sprintf" => {
            let (fmt, rest) = args.split_first()?;
            Some(substitute_format(fmt, rest))
        }
        _ => None,
    }
}

fn substitute_format(fmt: &str, args: &[String]) -> String {
    let mut out = String::new();
    let chars: Vec<char> = fmt.chars().collect();
    let mut ai = 0;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '%' && i + 1 < chars.len() {
            // Skip flags / width / precision until we reach the verb.
            let mut j = i + 1;
            while j < chars.len() && "+-# 0123456789.".contains(chars[j]) {
                j += 1;
            }
            if j < chars.len() {
                match chars[j] {
                    's' | 'v' | 'q' | 'd' | 'x' | 'X' => {
                        if ai < args.len() {
                            out.push_str(&args[ai]);
                            ai += 1;
                        }
                    }
                    '%' => out.push('%'),
                    other => {
                        out.push('%');
                        out.push(other);
                    }
                }
                i = j + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn read_string(b: &[u8], i: &mut usize) -> Option<String> {
    if *i >= b.len() {
        return None;
    }
    match b[*i] {
        b'`' => {
            *i += 1;
            let start = *i;
            while *i < b.len() && b[*i] != b'`' {
                *i += 1;
            }
            let out = std::str::from_utf8(&b[start..*i]).ok()?.to_string();
            if *i < b.len() {
                *i += 1;
            }
            Some(out)
        }
        b'"' => {
            *i += 1;
            let mut s = String::new();
            while *i < b.len() && b[*i] != b'"' {
                if b[*i] == b'\\' && *i + 1 < b.len() {
                    match b[*i + 1] {
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        b'\\' => s.push('\\'),
                        b'"' => s.push('"'),
                        b'\'' => s.push('\''),
                        other => s.push(other as char),
                    }
                    *i += 2;
                } else {
                    s.push(b[*i] as char);
                    *i += 1;
                }
            }
            if *i < b.len() {
                *i += 1;
            }
            Some(s)
        }
        _ => None,
    }
}

fn read_want(b: &[u8], i: &mut usize, vars: &HashMap<String, String>) -> Option<Vec<String>> {
    *i = skip_ws_and_comments(b, *i);
    // Could be `nil` or `[]string{...}` or `nil,` etc.
    if b[*i..].starts_with(b"nil") {
        *i += 3;
        return None;
    }
    // Sometimes want is a bare identifier referencing []string variable.
    if is_ident_byte(b[*i]) {
        let start = *i;
        while *i < b.len() && is_ident_byte(b[*i]) {
            *i += 1;
        }
        let id = std::str::from_utf8(&b[start..*i]).unwrap_or("");
        if let Some(v) = vars.get(id) {
            return Some(vec![v.clone()]);
        }
    }
    // []string{...}
    while *i < b.len() && b[*i] != b'{' {
        *i += 1;
    }
    if *i >= b.len() {
        return Some(Vec::new());
    }
    let open = *i;
    let end = match_brace(b, open)?;
    let inner = std::str::from_utf8(&b[open + 1..end]).ok()?;
    let mut out = Vec::new();
    let bi = inner.as_bytes();
    let mut j = 0;
    while j < bi.len() {
        j = skip_ws_and_comments(bi, j);
        if j >= bi.len() {
            break;
        }
        if bi[j] == b',' {
            j += 1;
            continue;
        }
        // Each `[]string{…}` entry is a Go expression — possibly an
        // identifier, a fmt.Sprintf call, or a chain of those joined by
        // `+`. Concatenate until we hit a `,` or run out of bytes.
        let before = j;
        let mut entry = String::new();
        loop {
            j = skip_ws_and_comments(bi, j);
            if j >= bi.len() || bi[j] == b',' {
                break;
            }
            if let Some(v) = read_value(bi, &mut j, vars) {
                entry.push_str(&v);
            } else {
                // Couldn't resolve — bail out of this entry.
                j += 1;
                break;
            }
            j = skip_ws_and_comments(bi, j);
            if j < bi.len() && bi[j] == b'+' {
                j += 1;
                continue;
            }
            break;
        }
        if !entry.is_empty() {
            out.push(entry);
        }
        if j == before {
            j += 1;
        }
    }
    *i = end + 1;
    Some(out)
}

fn skip_value(b: &[u8], i: &mut usize) {
    *i = skip_ws_and_comments(b, *i);
    while *i < b.len() {
        match b[*i] {
            b',' => return,
            b'{' => {
                if let Some(end) = match_brace(b, *i) {
                    *i = end + 1;
                } else {
                    *i = b.len();
                }
            }
            b'`' | b'"' => {
                let _ = read_string(b, i);
            }
            _ => *i += 1,
        }
    }
}

// ---- evaluation ------------------------------------------------------------

#[derive(Debug)]
#[allow(dead_code)]
struct Outcome {
    case: Case,
    passed: bool,
    detail: String,
}

fn evaluate(case: &Case, eng: &Engine, spec: &ProviderSpec) -> Outcome {
    let chunk = Chunk {
        bytes: case.input.as_bytes(),
        offset: 0,
        origin: ChunkOrigin::Raw,
    };
    let mut hits: Vec<_> = eng.scan_chunk(&chunk);
    hits.retain(|h| spec.rule_ids.contains(&h.rule_id.as_str()));

    match &case.want {
        Some(expected) if expected.is_empty() => {
            // Some test files used `want: []string{}` (empty) — same as nil.
            if hits.is_empty() {
                Outcome {
                    case: case.clone(),
                    passed: true,
                    detail: "no hits expected; got none".into(),
                }
            } else if spec.tolerate_false_positives {
                Outcome {
                    case: case.clone(),
                    passed: true,
                    detail: format!(
                        "tolerated extra hits ({}): {}",
                        hits.len(),
                        hits.iter()
                            .map(|h| h.rule_id.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                }
            } else {
                Outcome {
                    case: case.clone(),
                    passed: false,
                    detail: format!(
                        "expected no hits; got {} (rules: {})",
                        hits.len(),
                        hits.iter()
                            .map(|h| h.rule_id.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                }
            }
        }
        Some(expected) => {
            // Each expected substring must appear inside at least one hit's slice.
            let mut missed = Vec::new();
            for want in expected {
                let want_bytes = want.as_bytes();
                let mut found = false;
                for h in &hits {
                    let from = h.offset as usize;
                    let to = from + h.len;
                    if to > case.input.len() {
                        continue;
                    }
                    let slice = &case.input.as_bytes()[from..to];
                    if slice == want_bytes || contains_subslice(slice, want_bytes) {
                        found = true;
                        break;
                    }
                    // Also accept the case where trufflehog's expected substring
                    // contains our hit (we match a tighter region).
                    if contains_subslice(want_bytes, slice) {
                        found = true;
                        break;
                    }
                }
                if !found {
                    missed.push(want.clone());
                }
            }
            if missed.is_empty() {
                Outcome {
                    case: case.clone(),
                    passed: true,
                    detail: format!(
                        "{}/{} expected substrings matched",
                        expected.len(),
                        expected.len()
                    ),
                }
            } else {
                Outcome {
                    case: case.clone(),
                    passed: false,
                    detail: format!(
                        "missing {} expected substring(s): {}",
                        missed.len(),
                        missed
                            .iter()
                            .map(|s| truncate(s, 80))
                            .collect::<Vec<_>>()
                            .join(" | ")
                    ),
                }
            }
        }
        None => {
            // want == nil — must match nothing from this provider.
            if hits.is_empty() {
                Outcome {
                    case: case.clone(),
                    passed: true,
                    detail: "negative case: no hits".into(),
                }
            } else if spec.tolerate_false_positives {
                Outcome {
                    case: case.clone(),
                    passed: true,
                    detail: format!(
                        "tolerated extra hits ({}): {}",
                        hits.len(),
                        hits.iter()
                            .map(|h| h.rule_id.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                }
            } else {
                Outcome {
                    case: case.clone(),
                    passed: false,
                    detail: format!(
                        "negative case: false-positive hits ({} from rules: {})",
                        hits.len(),
                        hits.iter()
                            .map(|h| h.rule_id.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                }
            }
        }
    }
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.into()
    } else {
        format!("{}…", &s[..n])
    }
}

// ---- main ------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    // We expect to be invoked from the workspace root via `cargo run`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Providers whose tests we deliberately let pass even when scrump produces
/// hits TruffleHog's verification-aware detector would have filtered out.
///
/// Empty by design: every previously-tolerated divergence has been replaced
/// with a real fix. JWT is now handled by the hand-coded `JwtHsAware`
/// detector in `scrump-rules` that base64-decodes the header and rejects
/// HMAC-signed tokens, matching TruffleHog exactly.
const TOLERATED: &[&str] = &[];

/// Providers whose auto-extracted rule names don't reflect the actual
/// scrump rule we want to use. (Custom-coded detectors with hand-picked
/// ids belong here.)
const RULE_OVERRIDES: &[(&str, &[&str])] = &[
    // The auto-extracted `jwt__keypat` is stripped at load time in favour
    // of `JwtHsAware`, which uses the rule id `jwt_token`.
    ("jwt", &["jwt_token"]),
];

fn main() -> std::io::Result<()> {
    let root = workspace_root();
    let detectors_dir = root.join("vendor/trufflehog/pkg/detectors");
    if !detectors_dir.exists() {
        eprintln!(
            "vendor/trufflehog/pkg/detectors not found at {} — clone with:\n\
             git clone --depth=1 --filter=blob:none --sparse \
             https://github.com/trufflesecurity/trufflehog.git vendor/trufflehog && \
             cd vendor/trufflehog && git sparse-checkout set pkg/detectors",
            detectors_dir.display()
        );
        std::process::exit(2);
    }

    let detectors = scrump_rules::default_detectors().expect("default rules");
    let engine = Engine::new(detectors);

    // Load the provider → rule_ids map produced by `th-extract`. Leak the
    // map so all references into it can be `&'static` — simplifies plumbing
    // through `ProviderSpec` without introducing lifetime params.
    let map_path = root.join("crates/scrump-trufflehog-compat/data/provider_map.json");
    let map_json = std::fs::read_to_string(&map_path)?;
    let provider_map: BTreeMap<String, Vec<String>> =
        serde_json::from_str(&map_json).expect("provider_map.json malformed");
    let provider_map: &'static BTreeMap<String, Vec<String>> = Box::leak(Box::new(provider_map));

    // Discover every test file under pkg/detectors/.
    let test_files = find_all_test_files(&detectors_dir);

    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut per_provider: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failure_details: Vec<(String, String, String)> = Vec::new();
    let mut skipped_no_cases = 0usize;
    let mut skipped_no_rules = 0usize;

    for (provider, path) in test_files {
        // Pick override list first, falling back to the auto-extracted map.
        let override_ids = RULE_OVERRIDES
            .iter()
            .find_map(|(p, ids)| (*p == provider).then_some(*ids));
        let rule_ids: Vec<&'static str> = match override_ids {
            Some(ids) => ids.to_vec(),
            None => {
                let Some(rule_strings) = provider_map.get(&provider) else {
                    skipped_no_rules += 1;
                    continue;
                };
                // Drop rules that scrump-rules quarantined as unusable
                // noise on real artifacts (issue #9). A provider whose
                // only auto-extracted rules are quarantined is skipped:
                // its positive cases would always fail because the
                // engine no longer carries that rule, so counting them
                // as failures would just inflate the harness floor.
                let active: Vec<&str> = rule_strings
                    .iter()
                    .map(String::as_str)
                    .filter(|id| scrump_rules::rule_is_active(id))
                    .collect();
                if active.is_empty() {
                    skipped_no_rules += 1;
                    continue;
                }
                active
            }
        };
        let spec = ProviderSpec {
            name: Box::leak(provider.clone().into_boxed_str()),
            test_path: Box::leak(path.to_string_lossy().into_owned().into_boxed_str()),
            rule_ids: Box::leak(rule_ids.into_boxed_slice()),
            tolerate_false_positives: TOLERATED.iter().any(|t| *t == provider),
        };

        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cases = parse_provider(&src, spec.name);
        if cases.is_empty() {
            skipped_no_cases += 1;
            continue;
        }
        for c in &cases {
            let outcome = evaluate(c, &engine, &spec);
            let entry = per_provider.entry(provider.clone()).or_insert((0, 0));
            if outcome.passed {
                entry.0 += 1;
                total_pass += 1;
            } else {
                entry.1 += 1;
                total_fail += 1;
                failure_details.push((provider.clone(), c.name.clone(), outcome.detail.clone()));
            }
        }
    }
    eprintln!(
        "(meta) skipped: {} providers with no extracted rules, {} providers with no parsed cases",
        skipped_no_rules, skipped_no_cases
    );

    // ---- report ------------------------------------------------------------
    println!("\nTruffleHog compat — scrump's engine vs TruffleHog's test corpus\n");
    let providers_run = per_provider.len();
    let providers_pass = per_provider.values().filter(|(_p, f)| *f == 0).count();
    let providers_fail = providers_run - providers_pass;
    println!(
        "providers run: {providers_run}  (clean: {providers_pass}, with failures: {providers_fail})"
    );
    println!(
        "cases:         pass = {total_pass}, fail = {total_fail}, total = {}",
        total_pass + total_fail
    );

    if !failure_details.is_empty() {
        println!("\nProviders with failures:");
        let mut by_p: BTreeMap<&str, Vec<(&String, &String)>> = BTreeMap::new();
        for (p, n, d) in &failure_details {
            by_p.entry(p).or_default().push((n, d));
        }
        for (p, items) in &by_p {
            println!("  [{p}] ({} fail)", items.len());
            for (n, d) in items.iter().take(3) {
                println!("    {n}: {d}");
            }
            if items.len() > 3 {
                println!("    … +{} more", items.len() - 3);
            }
        }
    }

    // Allow CI to set a non-zero failure floor for the 200-ish cross-provider
    // negative cases where scrump's auto-extracted PrefixRegex rule for one
    // provider hits a different provider's input fixture. These are
    // false-positives in the trufflehog test sense (a "no hits expected" case
    // produced N hits), not missed detections; they don't represent a leak in
    // the redaction path. The floor is read from SCRUMP_TH_MAX_FAILURES (env)
    // — default 0 keeps local runs strict so regressions show up.
    let max_failures: usize = std::env::var("SCRUMP_TH_MAX_FAILURES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if total_fail > max_failures {
        eprintln!(
            "FAIL: {total_fail} failures exceeds floor of {max_failures} \
             (set SCRUMP_TH_MAX_FAILURES to raise the floor — \
             only after confirming new failures are cross-provider FPs)"
        );
        std::process::exit(1);
    }
    if total_fail > 0 {
        println!("(tolerating {total_fail} failure(s); floor = {max_failures})");
    }
    Ok(())
}

fn find_all_test_files(root: &std::path::Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    walk_for_tests(root, root, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk_for_tests(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_for_tests(root, &p, out);
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with("_test.go") || name.ends_with("_integration_test.go") {
            continue;
        }
        if let Ok(rel) = p.parent().unwrap().strip_prefix(root) {
            let provider = rel.to_string_lossy().replace(['/', '\\'], "_");
            out.push((provider, p.clone()));
        }
    }
}
