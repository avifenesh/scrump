//! Extract Presidio's PATTERNS + parametrized test cases into a JSON
//! manifest. Output: `crates/scrump-presidio-compat/data/manifest.json`.
//!
//! Per recognizer we capture:
//!   - the `Pattern(name, regex, confidence)` tuples from the `PATTERNS`
//!     class attribute;
//!   - the `CONTEXT` keyword list;
//!   - every parametrized test case in `tests/test_<stem>.py` of the
//!     form `(text, expected_len, expected_positions)`.
//!
//! The parser is regex-driven and tolerant of formatting variations
//! (line-folded raw strings, trailing commas, `# noqa` comments).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use scrump_presidio_compat::*;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn main() -> std::io::Result<()> {
    let root = workspace_root();
    let analyzer_root = root.join("vendor/presidio/presidio-analyzer");
    if !analyzer_root.exists() {
        eprintln!("missing {}", analyzer_root.display());
        std::process::exit(2);
    }

    // ---- 1. Walk recognizers -----------------------------------------------
    let mut recognizers_by_stem: BTreeMap<String, Recognizer> = BTreeMap::new();
    let recogs_root = analyzer_root.join("presidio_analyzer/predefined_recognizers");
    walk_recognizers(&recogs_root, &mut recognizers_by_stem);

    // ---- 2. Walk test files and pair them with recognizers ------------------
    let mut providers: Vec<ProviderManifest> = Vec::new();
    let tests_dir = analyzer_root.join("tests");
    let entries = fs::read_dir(&tests_dir)?;
    let test_pat = Regex::new(r"^test_(.+)\.py$").unwrap();
    for e in entries.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(cap) = test_pat.captures(name) else {
            continue;
        };
        let stem = cap.get(1).unwrap().as_str().to_string();
        let Some(recog) = recognizers_by_stem.get(&stem).cloned() else {
            // Test file exists but no matching recognizer (e.g.
            // test_analyzer_engine.py — engine-level test) — skip.
            continue;
        };
        let src = fs::read_to_string(&p)?;
        let tests = parse_test_file(&src);
        if tests.is_empty() {
            continue;
        }
        providers.push(ProviderManifest {
            recognizer: recog,
            tests,
        });
    }

    let manifest = Manifest { providers };
    let out_dir = root.join("crates/scrump-presidio-compat/data");
    fs::create_dir_all(&out_dir)?;
    let out_path = out_dir.join("manifest.json");
    let body = serde_json::to_string_pretty(&manifest)
        .map_err(|e| std::io::Error::other(format!("serialize: {e}")))?;
    fs::write(&out_path, body)?;

    let total_tests: usize = manifest.providers.iter().map(|p| p.tests.len()).sum();
    let total_patterns: usize = manifest
        .providers
        .iter()
        .map(|p| p.recognizer.patterns.len())
        .sum();
    let portable_patterns: usize = manifest
        .providers
        .iter()
        .flat_map(|p| p.recognizer.patterns.iter())
        .filter(|p| p.portable)
        .count();
    eprintln!(
        "Extracted: {} providers, {} patterns ({} portable), {} test cases",
        manifest.providers.len(),
        total_patterns,
        portable_patterns,
        total_tests
    );
    eprintln!("Manifest: {}", out_path.display());
    Ok(())
}

fn walk_recognizers(root: &Path, out: &mut BTreeMap<String, Recognizer>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut scanned = 0usize;
    let mut accepted = 0usize;
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_recognizers(&p, out);
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with("_recognizer.py") || name == "__init__.py" {
            continue;
        }
        scanned += 1;
        let Ok(src) = fs::read_to_string(&p) else {
            continue;
        };
        let stem = name.strip_suffix(".py").unwrap().to_string();
        if let Some(recog) = parse_recognizer(&src, &stem) {
            accepted += 1;
            out.insert(stem, recog);
        }
    }
    if scanned > 0 {
        eprintln!(
            "  walked {}: scanned {scanned}, accepted {accepted}",
            root.display()
        );
    }
}

// ---- recognizer parsing ----------------------------------------------------

fn parse_recognizer(src: &str, stem: &str) -> Option<Recognizer> {
    // Entity name is whichever `supported_entity: str = "FOO"` default arg appears.
    let ent_pat = Regex::new(r#"supported_entity:\s*str\s*=\s*"([A-Z_]+)""#).unwrap();
    let entity = ent_pat
        .captures(src)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| stem.to_uppercase());

    // Pre-scan module/class-level constants like
    //   BASE_URL_REGEX = r"..."
    // so `+ BASE_URL_REGEX` inside Pattern(...) gets resolved.
    let local_consts = scan_local_consts(src);

    // Pull every `Pattern("name", r"regex", confidence)` triple.
    let mut patterns = Vec::new();
    let pat_block = find_patterns_block(src)?;
    for entry in iter_pattern_entries(&pat_block) {
        if let Some(p) = parse_pattern_entry(&entry, &local_consts) {
            patterns.push(p);
        }
    }

    if patterns.is_empty() {
        return None;
    }

    // CONTEXT keywords.
    let context_pat = Regex::new(r#"CONTEXT\s*=\s*\[([^\]]*)\]"#).unwrap();
    let context = context_pat
        .captures(src)
        .and_then(|c| c.get(1))
        .map(|m| {
            let inner = m.as_str();
            Regex::new(r#""([^"]*)""#)
                .unwrap()
                .captures_iter(inner)
                .map(|c| c[1].to_string())
                .collect()
        })
        .unwrap_or_default();

    Some(Recognizer {
        entity,
        file_stem: stem.to_string(),
        patterns,
        context,
    })
}

fn find_patterns_block(src: &str) -> Option<String> {
    let needle = "PATTERNS = [";
    let start = src.find(needle)?;
    let after = &src[start + needle.len()..];
    // Match brackets until balanced.
    let mut depth = 1i32;
    let bytes = after.as_bytes();
    let mut i = 0;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b'"' => {
                i += 1;
                // Handle r"..." raw strings AND multi-line escapes.
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
            }
            _ => {}
        }
        if depth == 0 {
            return Some(after[..i].to_string());
        }
        i += 1;
    }
    None
}

fn iter_pattern_entries(block: &str) -> Vec<String> {
    // Each Pattern(...) is one entry separated by commas at top level.
    let mut entries = Vec::new();
    let bytes = block.as_bytes();
    let mut depth_paren = 0i32;
    let mut start = None;
    let mut i = 0;
    while i < bytes.len() {
        // Skip line comments.
        if bytes[i] == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Detect `Pattern(`
        if start.is_none() && block[i..].starts_with("Pattern(") {
            start = Some(i);
            depth_paren = 0;
        }
        if start.is_some() {
            match bytes[i] {
                b'(' => depth_paren += 1,
                b')' => {
                    depth_paren -= 1;
                    if depth_paren == 0 {
                        let s = start.take().unwrap();
                        entries.push(block[s..=i].to_string());
                    }
                }
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            i += 2;
                            continue;
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    entries
}

fn parse_pattern_entry(
    entry: &str,
    local_consts: &std::collections::HashMap<String, String>,
) -> Option<Pattern> {
    let name_pat = Regex::new(r#"Pattern\(\s*(?:name\s*=\s*)?"([^"]*)""#).unwrap();
    let name = name_pat
        .captures(entry)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())?;

    let body = extract_regex_body(entry, local_consts)?;
    // Mirror Presidio's default PatternRecognizer flags:
    //   re.DOTALL | re.MULTILINE | re.IGNORECASE
    // so `[A-Z]` matches lowercase, `.` matches newlines, and `^`/`$`
    // operate per-line. Rust regex applies these as inline flags `(?ims)`.
    let regex_body = if body.starts_with("(?ims)") || body.starts_with("(?ism)") {
        body
    } else {
        format!("(?ims){body}")
    };

    let conf_pat = Regex::new(r"(\d+\.\d+)\s*\)\s*$").unwrap();
    let confidence = conf_pat
        .captures(entry.trim_end())
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<f32>().ok())
        .unwrap_or(0.5);

    // Rust regex doesn't support lookbehind, lookahead, or backreferences.
    let portable = !regex_body.contains("(?<")
        && !regex_body.contains("(?=")
        && !regex_body.contains("(?!")
        && !has_backreference(&regex_body);
    Some(Pattern {
        name,
        raw: regex_body,
        portable,
        confidence,
    })
}

fn has_backreference(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i + 1].is_ascii_digit() && bytes[i + 1] != b'0' {
                return true;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

/// Scan recognizer source for module/class-level constants of the form
///   IDENT = r"..."        (raw string)
///   IDENT = "..."         (escaped string)
/// Used to resolve `+ IDENT` references inside `PATTERNS = […]` entries.
fn scan_local_consts(src: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let re = Regex::new(r#"(?m)^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(r?)('|")"#).unwrap();
    let bytes = src.as_bytes();
    for cap in re.captures_iter(src) {
        let name = cap[1].to_string();
        let is_raw = !cap[2].is_empty();
        let quote = cap[3].as_bytes()[0];
        let m = cap.get(0).unwrap();
        // Find the opening quote position in the original bytes.
        let q_pos = m.end() - 1;
        let mut i = q_pos + 1;
        let start = i;
        while i < bytes.len() && bytes[i] != quote {
            if !is_raw && bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            i += 1;
        }
        if i <= bytes.len() {
            let val = std::str::from_utf8(&bytes[start..i])
                .unwrap_or("")
                .to_string();
            out.insert(name, val);
        }
    }
    out
}

/// Pull every `r"..."` / `"..."` segment plus `+ IDENT` references (looked
/// up via `local_consts`) after the first comma in the entry and
/// concatenate them. Skips numeric / kwarg trailers.
fn extract_regex_body(
    entry: &str,
    local_consts: &std::collections::HashMap<String, String>,
) -> Option<String> {
    // Skip past Pattern("name", or Pattern(name="name",
    let after_name = entry.split_once(',')?.1;
    let bytes = after_name.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace / newlines / continuations.
        while i < bytes.len()
            && (bytes[i].is_ascii_whitespace()
                || bytes[i] == b'\\'
                || bytes[i] == b'+'
                || bytes[i] == b'#')
        {
            if bytes[i] == b'#' {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        if i >= bytes.len() {
            break;
        }
        // Identifier reference: `+ IDENT` → look up in local_consts. Also
        // handle the `r"..."` / `r'...'` raw-string prefix that LOOKS like
        // an identifier `r` followed by a quote.
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let id_start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let id = std::str::from_utf8(&bytes[id_start..i]).ok()?;
            let next_is_quote = i < bytes.len() && (bytes[i] == 0x22 || bytes[i] == 0x27);
            if id == "r" && next_is_quote {
                // Treat as raw string.
                let quote = bytes[i];
                i += 1;
                let s_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let body = std::str::from_utf8(&bytes[s_start..i]).ok()?;
                out.push_str(body);
                i += 1;
                continue;
            }
            if let Some(val) = local_consts.get(id) {
                out.push_str(val);
                continue;
            }
            // Unknown identifier — bail.
            return None;
        }
        if !(bytes[i] == 0x22 || bytes[i] == 0x27) {
            break;
        }
        let is_raw = false;
        let quote = bytes[i];
        i += 1;
        let start = i;
        while i < bytes.len() && bytes[i] != quote {
            if !is_raw && bytes[i] == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            i += 1;
        }
        let body = std::str::from_utf8(&bytes[start..i]).ok()?;
        if is_raw {
            out.push_str(body);
        } else {
            // Translate Python-string escapes (best-effort: \\n etc).
            let mut it = body.chars();
            while let Some(c) = it.next() {
                if c == '\\' {
                    if let Some(n) = it.next() {
                        match n {
                            'n' => out.push('\n'),
                            't' => out.push('\t'),
                            'r' => out.push('\r'),
                            '\\' => out.push('\\'),
                            other => {
                                out.push('\\');
                                out.push(other);
                            }
                        }
                    }
                } else {
                    out.push(c);
                }
            }
        }
        i += 1;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

// ---- test parsing ----------------------------------------------------------

fn parse_test_file(src: &str) -> Vec<TestCase> {
    // Look for any `parametrize(...)` whose first string argument contains
    // the three column names we care about. The header line may be on the
    // next line (`parametrize(\n    "text, expected_len, …"\n    [\n …`).
    let header_re = Regex::new(
        r#"parametrize\s*\(\s*"([^"]*\btext[^"]*\bexpected_len[^"]*\bexpected_positions[^"]*)"\s*,"#,
    )
    .unwrap();
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(m) = header_re.find(&src[search_from..]) {
        let absolute = search_from + m.end();
        // Skip whitespace and locate the opening `[`.
        let bytes = src.as_bytes();
        let mut i = absolute;
        while i < bytes.len() && bytes[i] != b'[' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Walk through the list literal until balanced.
        let body_start = i + 1;
        let mut depth = 1i32;
        let mut j = body_start;
        while j < bytes.len() && depth > 0 {
            match bytes[j] {
                b'[' => depth += 1,
                b']' => depth -= 1,
                b'"' => {
                    j += 1;
                    while j < bytes.len() && bytes[j] != b'"' {
                        if bytes[j] == b'\\' && j + 1 < bytes.len() {
                            j += 2;
                            continue;
                        }
                        j += 1;
                    }
                }
                b'#' => {
                    while j < bytes.len() && bytes[j] != b'\n' {
                        j += 1;
                    }
                    continue;
                }
                _ => {}
            }
            if depth == 0 {
                break;
            }
            j += 1;
        }
        let body = std::str::from_utf8(&bytes[body_start..j]).unwrap_or("");
        for case in iter_parametrize_cases(body) {
            if let Some(c) = parse_test_case(&case) {
                out.push(c);
            }
        }
        search_from = j + 1;
    }
    out
}

fn iter_parametrize_cases(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] != b'(' {
            i += 1;
            continue;
        }
        let start = i;
        let mut depth = 1i32;
        i += 1;
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            i += 2;
                            continue;
                        }
                        i += 1;
                    }
                }
                b'\'' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'\'' {
                        if bytes[i] == b'\\' && i + 1 < bytes.len() {
                            i += 2;
                            continue;
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
            if depth == 0 {
                break;
            }
            i += 1;
        }
        out.push(body[start..=i].to_string());
        i += 1;
    }
    out
}

fn parse_test_case(entry: &str) -> Option<TestCase> {
    // Strip outer parens.
    let inner = entry.trim().strip_prefix('(')?.strip_suffix(')')?;
    // Three top-level items: text, expected_len, expected_positions
    let items = split_top_level_commas(inner);
    if items.len() < 2 {
        return None;
    }
    let text = read_python_string(items[0].trim())?;
    let expected_len: usize = items[1].trim().parse().ok()?;
    let positions = if items.len() >= 3 {
        parse_positions(items[2].trim())
    } else {
        Vec::new()
    };
    Some(TestCase {
        text,
        expected_len,
        positions,
    })
}

fn split_top_level_commas(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
            }
            b'\'' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
            }
            b',' if depth == 0 => {
                out.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < s.len() {
        out.push(s[start..].to_string());
    }
    out
}

fn read_python_string(s: &str) -> Option<String> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut i = 0;
    // Concatenate adjacent string literals. Collect into Vec<u8> so multi-
    // byte UTF-8 sequences pass through verbatim (the previous version
    // pushed each byte as `bytes[i] as char` which mangled non-ASCII).
    let mut out: Vec<u8> = Vec::new();
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let is_raw = bytes[i] == b'r';
        if is_raw {
            i += 1;
        }
        if i >= bytes.len() || (bytes[i] != b'"' && bytes[i] != b'\'') {
            break;
        }
        let q = bytes[i];
        i += 1;
        while i < bytes.len() && bytes[i] != q {
            if !is_raw && bytes[i] == b'\\' && i + 1 < bytes.len() {
                let n = bytes[i + 1];
                match n {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'\\' => out.push(b'\\'),
                    b'"' => out.push(b'"'),
                    b'\'' => out.push(b'\''),
                    other => {
                        out.push(b'\\');
                        out.push(other);
                    }
                }
                i += 2;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        i += 1;
    }
    if out.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&out).into_owned())
    }
}

fn parse_positions(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let pair_pat = Regex::new(r"\(\s*(\d+)\s*,\s*(\d+)\s*\)").unwrap();
    for cap in pair_pat.captures_iter(s) {
        let a: usize = cap[1].parse().unwrap_or(0);
        let b: usize = cap[2].parse().unwrap_or(0);
        out.push((a, b));
    }
    out
}
