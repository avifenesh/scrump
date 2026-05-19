//! Default rules + YAML loader.
//!
//! The default ruleset (`rules/default.yaml`) is compiled into the binary
//! via `include_str!`. Users override it via `--rules-path FILE.yaml`.

use std::path::Path;

use regex::bytes::Regex;
use scrump_core::{Detector, Result, ScrumpError};
use serde::Deserialize;

const DEFAULT_RULES_YAML: &str = include_str!("../rules/default.yaml");
const TRUFFLEHOG_RULES_YAML: &str = include_str!("../rules/trufflehog.yaml");

#[derive(Debug, Deserialize)]
struct RulesFile {
    rules: Vec<RuleDef>,
}

#[derive(Debug, Deserialize, Clone)]
struct RuleDef {
    id: String,
    pattern: String,
    #[serde(default)]
    min_entropy: Option<f64>,
    /// If set, hits report the n-th capture group instead of the full match.
    #[serde(default)]
    capture_index: Option<usize>,
}

pub struct YamlDetector {
    id: String,
    pattern: Regex,
    min_entropy: Option<f64>,
    capture_index: Option<usize>,
}

impl YamlDetector {
    fn from_def(def: RuleDef) -> Result<Self> {
        let pattern = Regex::new(&def.pattern).map_err(|e| {
            ScrumpError::Other(format!("rule {}: regex compile failed: {}", def.id, e))
        })?;
        Ok(Self {
            id: def.id,
            pattern,
            min_entropy: def.min_entropy,
            capture_index: def.capture_index,
        })
    }
}

impl Detector for YamlDetector {
    fn id(&self) -> &str {
        &self.id
    }
    fn pattern(&self) -> &Regex {
        &self.pattern
    }
    fn min_entropy(&self) -> Option<f64> {
        self.min_entropy
    }
    fn capture_index(&self) -> Option<usize> {
        self.capture_index
    }
}

/// Load detectors from the embedded default ruleset (curated rules +
/// auto-extracted TruffleHog mirror + hand-coded detectors that need
/// post-pattern logic regex can't express).
pub fn default_detectors() -> Result<Vec<Box<dyn Detector>>> {
    let mut all = parse_yaml(DEFAULT_RULES_YAML)?;
    let th = parse_yaml(TRUFFLEHOG_RULES_YAML)?;
    all.extend(th);

    // Replace every JWT pattern with our HMAC-aware detector. Both the
    // curated `jwt_token` and the auto-extracted `jwt__keypat` are dropped.
    all.retain(|d| d.id() != "jwt_token" && !d.id().starts_with("jwt__"));
    all.push(Box::new(custom::JwtHsAware::new()));

    Ok(all)
}

mod custom {
    use base64::Engine;
    use regex::bytes::Regex;
    use scrump_core::Detector;
    use std::sync::OnceLock;

    /// JWT detector that mirrors TruffleHog's behaviour: matches the
    /// canonical three-segment JWT shape, then base64-decodes the header
    /// and rejects the hit when the `alg` claim is HMAC (`HS256`,
    /// `HS384`, `HS512`, or any other `HS*`). HMAC-signed JWTs are
    /// useless without the shared secret — TruffleHog drops them post-
    /// pattern, and so do we.
    pub struct JwtHsAware;

    impl JwtHsAware {
        pub fn new() -> Self {
            Self
        }
    }

    impl Detector for JwtHsAware {
        fn id(&self) -> &str {
            "jwt_token"
        }
        fn pattern(&self) -> &Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| {
                Regex::new(
                    r"\b(?:eyJ|ewogIC|ewoid)[A-Za-z0-9_-]{8,}={0,2}\.(?:eyJ|ewo)[A-Za-z0-9_-]{8,}={0,2}\.[A-Za-z0-9_-]{8,}",
                )
                .unwrap()
            })
        }
        fn min_entropy(&self) -> Option<f64> {
            Some(3.5)
        }
        fn post_filter(&self, candidate: &[u8]) -> bool {
            // Extract the header (first segment).
            let dot = match candidate.iter().position(|&b| b == b'.') {
                Some(i) => i,
                None => return false,
            };
            let header_b64 = &candidate[..dot];
            // Strip any base64 padding `=` chars.
            let trimmed = match std::str::from_utf8(header_b64) {
                Ok(s) => s.trim_end_matches('='),
                Err(_) => return false,
            };
            // JWT uses base64url-without-padding.
            let cfg = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let decoded = match cfg.decode(trimmed.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    // Header didn't decode — accept the hit (we'd rather
                    // over-redact than under-redact something we can't
                    // confidently identify).
                    return true;
                }
            };
            let text = match std::str::from_utf8(&decoded) {
                Ok(s) => s,
                Err(_) => return true,
            };
            // Cheap JSON-claim grep — match `"alg":"…"` regardless of spaces.
            let needle = "\"alg\"";
            let Some(p) = text.find(needle) else {
                // No alg field — accept (unknown shape, conservatively redact).
                return true;
            };
            let after = &text[p + needle.len()..];
            // Skip `:` and any whitespace, then look at the value.
            let after = after.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            let after = after.trim_start_matches('"');
            // If `alg` starts with HS (HS256, HS384, HS512, etc.), drop.
            !after.starts_with("HS")
        }
    }
}

/// Load detectors from a YAML file on disk.
pub fn detectors_from_path(p: &Path) -> Result<Vec<Box<dyn Detector>>> {
    let s = std::fs::read_to_string(p)?;
    parse_yaml(&s)
}

fn parse_yaml(s: &str) -> Result<Vec<Box<dyn Detector>>> {
    let file: RulesFile =
        serde_yaml::from_str(s).map_err(|e| ScrumpError::Other(format!("yaml parse: {e}")))?;
    file.rules
        .into_iter()
        .map(|d| YamlDetector::from_def(d).map(|x| Box::new(x) as Box<dyn Detector>))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ruleset_compiles() {
        let dets = default_detectors().expect("default rules must compile");
        assert!(!dets.is_empty(), "default ruleset must not be empty");
        // sanity: at least the GH PAT rule we know about
        let ids: Vec<&str> = dets.iter().map(|d| d.id()).collect();
        assert!(
            ids.contains(&"github_pat_classic"),
            "missing github_pat_classic in default ruleset: {ids:?}"
        );
    }

    #[test]
    fn duplicate_ids_are_loaded_as_separate_detectors() {
        // Sanity check that the YAML parser accepts two rules with the same id
        // (we don't enforce uniqueness; the detection engine just runs both).
        let yaml = "rules:\n  - id: dup\n    pattern: 'aaa'\n  - id: dup\n    pattern: 'bbb'\n";
        let dets = parse_yaml(yaml).unwrap();
        assert_eq!(dets.len(), 2);
    }

    #[test]
    fn bad_regex_surfaces_error() {
        let yaml = "rules:\n  - id: bad\n    pattern: '['\n";
        assert!(parse_yaml(yaml).is_err());
    }
}
