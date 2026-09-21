//! Narrow metadata exclusions for the default Azure detectors.
//!
//! Preserve the upstream patterns and their unstructured credential coverage.
//! Only a match in a complete, recognized JSON metadata field is excluded.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use regex::bytes::Regex;
use scrump_core::{Detector, Replacement, VerifyResult};
use serde_json::Value;
use std::sync::OnceLock;

const MAX_CONTEXT: usize = 16 * 1024;

enum MetadataKind {
    Integrity,
    SecretStore,
}

struct MetadataFilter {
    inner: Box<dyn Detector>,
    kind: MetadataKind,
}

pub(super) fn filter_known_metadata(detector: Box<dyn Detector>) -> Box<dyn Detector> {
    let kind = match detector.id() {
        "azure_cosmosdb__dbkeypattern" => MetadataKind::Integrity,
        "azure_openai__azurekeypat" => MetadataKind::SecretStore,
        _ => return detector,
    };
    Box::new(MetadataFilter {
        inner: detector,
        kind,
    })
}

impl Detector for MetadataFilter {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn pattern(&self) -> &Regex {
        self.inner.pattern()
    }
    fn min_entropy(&self) -> Option<f64> {
        self.inner.min_entropy()
    }
    fn capture_index(&self) -> Option<usize> {
        self.inner.capture_index()
    }
    fn replacement(&self) -> Replacement {
        self.inner.replacement()
    }
    fn post_filter(&self, candidate: &[u8]) -> bool {
        self.inner.post_filter(candidate)
    }
    fn verify(&self, candidate: &[u8]) -> VerifyResult {
        self.inner.verify(candidate)
    }
    fn post_filter_with_context(&self, candidate: &[u8], before: &[u8], after: &[u8]) -> bool {
        self.inner
            .post_filter_with_context(candidate, before, after)
            && !self.known_metadata(candidate, before, after)
    }
}

impl MetadataFilter {
    fn known_metadata(&self, candidate: &[u8], before: &[u8], after: &[u8]) -> bool {
        // The candidate must occupy the whole relevant JSON string value.
        // Match the field at this offset, not another field with equal bytes.
        if after.first() != Some(&b'"') {
            return false;
        }
        let before = &before[before.len().saturating_sub(MAX_CONTEXT)..];
        let prefix = match self.kind {
            MetadataKind::Integrity => {
                static PREFIX: OnceLock<Regex> = OnceLock::new();
                PREFIX.get_or_init(|| {
                    Regex::new(r#""integrity"[ \t\r\n]*:[ \t\r\n]*"sha512-$"#).unwrap()
                })
            }
            MetadataKind::SecretStore => {
                static PREFIX: OnceLock<Regex> = OnceLock::new();
                PREFIX.get_or_init(|| Regex::new(r#""store_id"[ \t\r\n]*:[ \t\r\n]*"$"#).unwrap())
            }
        };
        if !prefix.is_match(before) {
            return false;
        }
        let Some(object) = containing_object(before, candidate, after) else {
            return false;
        };
        let Ok(text) = std::str::from_utf8(candidate) else {
            return false;
        };
        match self.kind {
            MetadataKind::Integrity => {
                let Ok(digest) = STANDARD.decode(candidate) else {
                    return false;
                };
                digest.len() == 64
                    && STANDARD.encode(&digest) == text
                    && object.get("integrity").and_then(Value::as_str)
                        == Some(format!("sha512-{text}").as_str())
            }
            MetadataKind::SecretStore => {
                object.get("store_id").and_then(Value::as_str) == Some(text)
                    && ["binding", "secret_name"].iter().all(|key| {
                        object
                            .get(key)
                            .and_then(Value::as_str)
                            .is_some_and(|value| !value.is_empty())
                    })
            }
        }
    }
}

/// Inspect only a bounded complete object around the candidate. If the nearest
/// opening brace is inside a string, or the object extends beyond the available
/// context, parsing fails and the candidate remains a finding.
fn containing_object(before: &[u8], candidate: &[u8], after: &[u8]) -> Option<Value> {
    let start = before.iter().rposition(|&byte| byte == b'{')?;
    let prefix = &before[start..];
    let candidate_end = prefix.len() + candidate.len();
    let suffix = &after[..after.len().min(MAX_CONTEXT)];
    let mut bytes = Vec::with_capacity(candidate_end + suffix.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(candidate);
    bytes.extend_from_slice(suffix);
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        if index < candidate_end {
                            return None;
                        }
                        return serde_json::from_slice(&bytes[..=index]).ok();
                    }
                }
                _ => {}
            }
        }
    }
    None
}
