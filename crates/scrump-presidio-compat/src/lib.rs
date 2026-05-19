//! Shared types for the Presidio extractor and the cross-format harness.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub name: String,
    /// Original Presidio regex (Python flavour).
    pub raw: String,
    /// Whether the pattern is portable to Rust's `regex` crate
    /// (no lookbehind/lookahead).
    pub portable: bool,
    /// Confidence weight, 0.0..=1.0.
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recognizer {
    /// PII entity name, e.g. "EMAIL_ADDRESS".
    pub entity: String,
    /// Recognizer file stem, e.g. "email_recognizer".
    pub file_stem: String,
    pub patterns: Vec<Pattern>,
    /// Context keywords that raise confidence.
    pub context: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub text: String,
    pub expected_len: usize,
    /// `(start, end)` byte offsets in `text`. Empty for negative cases.
    pub positions: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderManifest {
    pub recognizer: Recognizer,
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub providers: Vec<ProviderManifest>,
}
