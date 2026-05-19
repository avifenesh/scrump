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

/// Auto-extracted TruffleHog rules whose patterns produce unusable noise on
/// real artifacts (issue #9). Each entry was added based on an empirical
/// audit (`tests/noise_audit.rs`) that runs the full ruleset against an
/// ~ 8 MB synthetic corpus mimicking SQLite log text, source code, config
/// files, `.env`-style assignments, alphanumeric blobs, and tar padding.
/// A rule is quarantined when it either fires more than ten times or
/// captures more than 1 KB on that corpus — both dimensions matter
/// because the unbounded-quantifier class (`{N,}` patterns) fires once
/// per blob but eats megabytes per fire, equally destructive for `scrub`.
///
/// These patterns are unsalvageable as scrubber rules: scrump
/// deliberately does not verify candidates against the upstream
/// provider's API (the way TruffleHog does), so per-rule false positives
/// translate one-for-one into destructive overwrites in `scrub`.
///
/// Users who need a quarantined rule can reintroduce it via `--rules-path`.
///
/// Kept in sorted order so the const itself is easy to review.
pub const TH_QUARANTINE: &[&str] = &[
    "alibaba__keypat",                 // `\b([a-zA-Z0-9]{30})\b` no anchor
    "anypoint__keypat",                // UUID, no keyword anchor
    "anypoint__orgpat",                // keyword `org` is too generic
    "anypointoauth2__idpat",           // keyword `id` + 32 hex — matches any MD5/UUID-like in logs
    "atlassian_v2__organizationidpat", // keyword `org|id` + UUID
    "auth0managementapitoken__managementapitokenpat", // `\b(ey[a-zA-Z0-9._-]+)\b` unbounded
    "auth0oauth__clientsecretpat",     // `\b([a-zA-Z0-9_-]{64,})\b` unbounded — eats megabytes
    "aws_session_keys__sessionpat",    // `[a-zA-Z0-9+/]{100,}` unbounded — eats megabytes
    "azure_batch__secretpat",          // raw `[A-Za-z0-9+/=]{88}` no anchor
    "azureapimanagement_repositorykey__regex", // `\d+\.\d+\.\d+` — fires on every semver in any log
    "azureapimanagementsubscriptionkey__keypat", // keyword `key` + 32 alnums — fires on every config
    "boxoauth__clientidpat", // keyword `id` + 32 alnums — duplicate of spotify/shopify hits
    "boxoauth__clientsecretpat", // keyword `secret` + 32 alnums — matches Go function names
    "boxoauth__subjectidpat", // keyword `user|subject|id` + 6-20 digits — every numeric ID matches
    "browserstack__keypat",  // keyword `key` + 20 alnums — fires on every env var
    "browserstack__userpat", // keyword `user|username` + 9-29 alnums — fires on every env var
    "circleci_v1__keypat",   // keyword `circle` + 40 hex — matches every git SHA-1 near the word
    "clickhelp__emailpat",   // RFC-shaped email pattern, no provider context
    "clickhelp__keypat",     // keyword `key|token|api|secret` + 24 alnums — every config value
    "cloudflareglobalapikey__emailpat", // RFC-shaped email pattern, no provider context
    "copper__idpat",         // `\b([a-z0-9]{4,25}@[a-zA-Z0-9]{2,12}.[a-zA-Z0-9]{2,6})\b` email
    "currencycloud__emailpat", // RFC-shaped email pattern, no provider context
    "datadogapikey__apikeypat", // keyword `dd` + 32 alnums — fires on Go fn names
    "datadogtoken__apipat",  // keyword `dd` + 32 alnums — duplicate of datadogapikey
    "datadogtoken__apppat",  // keyword `dd` fires on `dd-mm-yyyy` etc.
    "digitaloceantoken__keypat", // keyword `do` matches every English `do`
    "dockerhub_v1__usernamepat", // keyword `docker|id` + 4-40 alnums — matches `network`
    "dockerhub_v2__emailpat", // RFC-shaped email pattern, no provider context
    "dockerhub_v2__usernamepat", // keyword `id` matches every config field
    "docusign__idpat",       // keyword `integration|id` + UUID
    "dotdigital__passpat",   // keyword `pw|pass` fires on every config password line
    "easyinsight__idpat",    // keyword `id` + 20 alnums — every random env value
    "easyinsight__keypat",   // keyword `key` + 20 alnums — every random env value
    "eightxeight__idpat",    // keyword `8x8` + 18-30 alnums — matches `8x8 grid`/`8x8 pixel` text
    "elevenlabs_v1__keypat", // keyword `el` matches `elephant`, `panel`, `level`, etc.
    "clicksendsms__keypat",  // `\b([0-9A-Z]{8}-...-{12})\b` UUID, no keyword
    "flowflu__accountpat",   // keyword `account` is too generic
    "gcpapplicationdefaultcredentials__keypat", // `\{[^{]+client_secret[^}]+\}` greedy — captured 8KB JSON
    "gemini__secretpat",                        // unanchored 27-28 char alnum
    "github_oauth2__oauth2clientsecretpat", // keyword `github` + 40 hex — matches every git SHA-1
    "gitlaboauth2__clientidpat",            // keyword `id` + 64 hex
    "graphcms__idpat", // keyword `graph` + 25 alnums — matches GraphQL identifiers
    "jdbc__pattern",   // `(?i)pass.*?=(.+?)\b` matches any config `password=...` line
    "jiratoken_v2__domainpat", // `\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]{2,16})\b` matches every dotted hostname
    "jiratoken_v2__emailpat",  // RFC-shaped email pattern, no provider context
    "ldap__passwordpat",       // keyword `pass` + quoted 4-48 chars — every config `password='…'`
    "ldap__usernamepat",       // keyword `user` + any quoted string
    "magicbell__emailpat",     // RFC-shaped email pattern, no provider context
    "mapbox__idpat",           // `([a-zA-Z-0-9]{4,32})` no boundary, no keyword
    "mrticktock__emailpat",    // RFC-shaped email pattern, no provider context
    "netsuite__accountidpat",  // keyword `id|account|netsuite` too broad
    "netsuite__consumerkeypat", // keyword `consumer|key` + 64 alnums — matches SHA-256-shape
    "netsuite__consumersecretpat", // keyword `consumer|secret` + 64 alnums — matches placeholder zeros
    "netsuite__tokenkeypat",       // keyword `token|key` + 64 alnums — duplicate of consumerkey
    "netsuite__tokensecretpat",    // keyword `token|secret` + 64 alnums — matches placeholder zeros
    "onedesk__emailpat",           // RFC-shaped email pattern, no provider context
    "onelogin__oauthclientidpat",  // keyword `id` + 64 lowercase hex
    "openvpn__clientsecretpat",    // `\b([a-zA-Z0-9_-]{64,})\b` unbounded — eats megabytes
    "paypaloauth__keypat", // `\b([A-Za-z0-9_\.\-]{44,80})\b` no anchor; needs hand-coded rule in default.yaml
    "planetscale__usernamepat", // `\b[a-z0-9]{12}\b` no keyword
    "planetscaledb__usernamepat", // `\b[a-z0-9]{20}\b` no keyword
    "postgres__connstrpartpattern", // `([[:alpha:]]+)='(.+?)' ?` matches every quoted assignment; default.yaml has the proper postgres__uripattern
    "pusherchannelkey__keypat",     // keyword `key` ALONE — fires on every key/value pair
    "razorpay__secretpat", // `\b[A-Za-z0-9]{24}\b` no anchor — the auto-extracted pattern is broken even though the curated version works
    "robinhoodcrypto__privkeybase64pat", // generic base64 with `=`/`==` tail
    "salesforceoauth2__consumersecretpat", // keyword `secret|consumer` + 19-64 alnums
    "salesforcerefreshtoken__consumersecretpat", // same shape as above
    "saucelabs__usernamepat", // keyword `username` + 2-70 alnums — too loose
    "shopifyoauth__clientidpat", // keyword `id` + 32 alnums — duplicate hits of spotify/box
    "signable__keywordpat", // `(?i)([a-z]{2})signable` matches `assignable`, captures only 2 chars
    "signable__tokenpat",  // `.{0,2}signable` matches `assignable` followed by 32 alnums
    "snowflake__accountidentifierpat", // keyword `account` + 7-262 chars — matches arbitrary identifiers
    "sourcegraph__keypat",             // third alternative `[a-fA-F0-9]{40}` matches every SHA-1
    "sparkpost__keypat",               // `\b([a-zA-Z0-9]{40})\b` no anchor
    "spotifykey__idpat",               // keyword `id` + 32 alnums — duplicate hits of shopify/box
    "spotifykey__secretpat", // keyword `key|secret` + 32 alnums — matches Go function names
    "tableau__tokennamepat", // keyword `name` is too generic
    "trelloapikey__tokenpat", // `\b([a-zA-Z-0-9]{64})\b` no anchor
    "tru__keypat",           // keyword `tru` + UUID — same broken keyword as tru__secrepat
    "tru__secrepat",         // keyword `tru` matches `true`, `trust`, etc.
    "twilio__keypat",        // `\b[0-9a-f]{32}\b` — matches every MD5 / 32-char hex
    "twilioapikey__secretpat", // `\b[0-9a-zA-Z]{32}\b` no anchor
    "user__keypat", // keyword `user` + 64 chars — matches Google profile photo URL fragments
    "wepay__appidpat", // `\b(\d{6})\b` — every six-digit number
    "zendeskapi__email", // email pattern, no provider context
    "zipapi__emailpat", // RFC-shaped email pattern, no provider context
    "zipbooks__emailpat", // RFC-shaped email pattern, no provider context
    "zipbooks__pwordpat", // keyword `zipbooks|password` fires on every config
    "zulipchat__idpat", // email pattern, no provider context
];

/// Returns `true` when a rule id is part of the active ruleset — i.e. it
/// is not on the quarantine list. Exposed so the TruffleHog compat harness
/// can honor the same curation when consulting the auto-generated
/// `provider_map.json`.
pub fn rule_is_active(id: &str) -> bool {
    !TH_QUARANTINE.contains(&id)
}

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
/// auto-extracted TruffleHog mirror minus the quarantined-for-noise rules
/// + hand-coded detectors that need post-pattern logic regex can't express).
pub fn default_detectors() -> Result<Vec<Box<dyn Detector>>> {
    let mut all = parse_yaml(DEFAULT_RULES_YAML)?;
    let th = parse_yaml_filtered(TRUFFLEHOG_RULES_YAML, rule_is_active)?;
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
                .expect("hand-written JwtHsAware regex must compile")
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
    parse_yaml_filtered(s, |_| true)
}

/// Parse a YAML ruleset, retaining only rules whose id satisfies `keep`.
/// Used to drop quarantined rules from the auto-extracted TruffleHog set.
fn parse_yaml_filtered(s: &str, keep: impl Fn(&str) -> bool) -> Result<Vec<Box<dyn Detector>>> {
    let file: RulesFile =
        serde_yaml::from_str(s).map_err(|e| ScrumpError::Other(format!("yaml parse: {e}")))?;
    file.rules
        .into_iter()
        .filter(|d| keep(&d.id))
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
