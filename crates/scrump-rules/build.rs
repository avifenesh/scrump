//! Turns the embedded rule files into static tables, so a run neither parses
//! YAML nor compiles a regex it does not need.
//!
//! For each rule the table carries what the engine needs before compiling
//! the pattern: a set of byte strings one of which every match contains (its
//! prefilter keywords), and whether the pattern holds a line or text anchor.
//! Every pattern is compiled here once, so a rule that does not compile
//! fails the build instead of a run.

use std::fmt::Write as _;
use std::path::Path;

use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::Hir;
use serde::Deserialize;

#[derive(Deserialize)]
struct RulesFile {
    rules: Vec<RuleDef>,
}

#[derive(Deserialize)]
struct RuleDef {
    id: String,
    pattern: String,
    #[serde(default)]
    min_entropy: Option<f64>,
    #[serde(default)]
    capture_index: Option<usize>,
}

/// A keyword shorter than this fires on nearly every text, so the scan
/// would pay for its matches and compile the rule anyway: such a rule runs
/// on every chunk instead.
const MIN_KEYWORD: usize = 3;

fn main() {
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let mut code = String::new();
    for (name, file) in [
        ("DEFAULT", "rules/default.yaml"),
        ("TRUFFLEHOG", "rules/trufflehog.yaml"),
        ("TEXT", "rules/text.yaml"),
    ] {
        println!("cargo:rerun-if-changed={file}");
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{file}: {e}"));
        let rules: RulesFile =
            serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{file}: yaml parse: {e}"));
        writeln!(code, "pub(crate) static {name}: &[EmbeddedRule] = &[").unwrap();
        for r in &rules.rules {
            if let Err(e) = regex::bytes::Regex::new(&r.pattern) {
                panic!("{file}: rule {}: regex compile failed: {e}", r.id);
            }
            let keywords = match keywords(&parse(&r.pattern, false)) {
                Some(k) => {
                    let mut s = String::from("Some(&[");
                    for k in k {
                        write!(s, "b\"{}\",", k.escape_ascii()).unwrap();
                    }
                    s.push_str("])");
                    s
                }
                None => "None".into(),
            };
            writeln!(
                code,
                "    EmbeddedRule {{ id: {:?}, pattern: {:?}, min_entropy: {:?}, capture_index: {:?}, keywords: {keywords}, anchored: {} }},",
                r.id,
                r.pattern,
                r.min_entropy,
                r.capture_index,
                anchored(&r.pattern),
            )
            .unwrap();
        }
        writeln!(code, "];").unwrap();
    }
    std::fs::write(Path::new(&out).join("embedded_rules.rs"), code).expect("write tables");
}

/// The pattern as `regex::bytes::Regex::new` reads it.
fn parse(pattern: &str, ignore_whitespace: bool) -> Hir {
    regex_syntax::ParserBuilder::new()
        .utf8(false)
        .ignore_whitespace(ignore_whitespace)
        .build()
        .parse(pattern)
        .unwrap_or_else(|e| panic!("{pattern}: {e}"))
}

/// The same test as `has_anchor` in scrump-detect, which reads it back from
/// a compiled regex: a line or text anchor under either reading of `#`.
fn anchored(pattern: &str) -> bool {
    [false, true].into_iter().any(|x| {
        regex_syntax::ParserBuilder::new()
            .utf8(false)
            .ignore_whitespace(x)
            .build()
            .parse(pattern)
            .map_or(true, |hir| hir.properties().look_set().contains_anchor())
    })
}

/// Byte strings, ASCII-lowercased, one of which lies in every match: the
/// prefix set or the suffix set regex-syntax extracts, whichever has the
/// longer shortest member (then the fewer members). The extractor
/// guarantees every match starts (ends) with a member of a finite set.
/// Cutting each member to its first (last) `n` bytes keeps that guarantee,
/// lowercasing only widens what an ASCII case-insensitive search finds, and
/// dropping a member that holds another member keeps it too. Members are
/// cut to the longest `n` that leaves at most [`MAX_KEYWORDS`] of them.
/// `None` when neither set is finite or fits with members of at least
/// [`MIN_KEYWORD`] bytes.
fn keywords(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    let mut best: Option<Vec<Vec<u8>>> = None;
    for kind in [ExtractKind::Prefix, ExtractKind::Suffix] {
        let prefix = matches!(kind, ExtractKind::Prefix);
        let seq = Extractor::new().kind(kind).limit_total(10_000).extract(hir);
        let Some(lits) = seq.literals() else { continue };
        let lits: Vec<Vec<u8>> = lits
            .iter()
            .map(|l| l.as_bytes().to_ascii_lowercase())
            .collect();
        let Some(longest) = lits.iter().map(Vec::len).max() else {
            continue;
        };
        for n in (MIN_KEYWORD..=longest).rev() {
            let cut = lits.iter().map(|l| {
                let k = l.len().min(n);
                if prefix {
                    l[..k].to_vec()
                } else {
                    l[l.len() - k..].to_vec()
                }
            });
            let set = minimal(cut);
            if set.len() > MAX_KEYWORDS {
                continue;
            }
            let shortest = set.iter().map(Vec::len).min().unwrap_or(0);
            if shortest < MIN_KEYWORD {
                break;
            }
            let better = match &best {
                None => true,
                Some(b) => {
                    let bs = b.iter().map(Vec::len).min().unwrap_or(0);
                    shortest > bs || (shortest == bs && set.len() < b.len())
                }
            };
            if better {
                best = Some(set);
            }
            break;
        }
    }
    best
}

/// The most keywords a rule keeps; a set that cannot be cut to this many
/// leaves the rule running on every chunk.
const MAX_KEYWORDS: usize = 64;

/// Deduplicated, without a member that holds another member.
fn minimal(set: impl Iterator<Item = Vec<u8>>) -> Vec<Vec<u8>> {
    let mut set: Vec<Vec<u8>> = set.collect();
    set.sort();
    set.dedup();
    // Shortest first, so a member is only checked against shorter ones.
    set.sort_by_key(Vec::len);
    let mut kept: Vec<Vec<u8>> = Vec::new();
    for s in set {
        if !kept.iter().any(|k| contains(&s, k)) {
            kept.push(s);
        }
    }
    kept
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || hay.windows(needle.len()).any(|w| w == needle)
}
