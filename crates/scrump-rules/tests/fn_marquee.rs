//! False-negative guard for issue #9.
//!
//! The rule curation that quarantined ~145 noisy auto-extracted TruffleHog
//! rules (see `TH_QUARANTINE`) reduced false positives massively — but
//! aggressive quarantining risks the opposite failure: dropping a rule
//! that was the only thing catching a real secret, turning a true positive
//! into a silent leak.
//!
//! This test plants real-shaped (obviously fake) secrets for every marquee
//! provider scrump commits to detecting and asserts each one is covered by
//! at least one hit from `default_detectors()`. If a future quarantine
//! addition breaks marquee detection, this fails.
//!
//! Secrets are assembled at runtime from a deterministic high-entropy fill
//! so (a) the source file carries no leaked-token shape for secret bots to
//! flag, and (b) entropy-gated rules (`jwt_token`) still match.

use scrump_core::{Chunk, ChunkOrigin};
use scrump_detect::Engine;
use scrump_rules::default_detectors;

/// Deterministic high-entropy alphanumeric fill of length `n`.
fn fill(seed: u64, n: usize) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::with_capacity(n);
    let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    for _ in 0..n {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s.push(ALPHA[((x >> 33) as usize) % ALPHA.len()] as char);
    }
    s
}

fn hexfill(seed: u64, n: usize) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(n);
    let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(99);
    for _ in 0..n {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s.push(HEX[((x >> 33) as usize) % HEX.len()] as char);
    }
    s
}

/// (label, planted secret string). Real-shaped, fake. Each must be detected.
fn marquee_secrets() -> Vec<(&'static str, String)> {
    // base64url-ish JWT segments (no padding) — RS256 so JwtHsAware keeps it.
    let jwt_hdr = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    let jwt_pl = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3QifQ";
    vec![
        ("github_pat_classic", format!("ghp_{}", fill(1, 36))),
        ("github_oauth_token", format!("gho_{}", fill(2, 36))),
        ("github_user_token", format!("ghu_{}", fill(3, 36))),
        ("github_server_token", format!("ghs_{}", fill(4, 36))),
        ("github_refresh_token", format!("ghr_{}", fill(5, 36))),
        (
            "github_fine_grained_pat",
            format!("github_pat_{}", fill(6, 82)),
        ),
        ("huggingface_user_token", format!("hf_{}", fill(7, 34))),
        (
            "openai_classic_key",
            format!("sk-{}T3BlbkFJ{}", fill(8, 8), fill(9, 24)),
        ),
        ("openai_project_key", format!("sk-proj-{}", fill(10, 30))),
        (
            "anthropic_api_key",
            format!("sk-ant-api03-{}AA", fill(11, 93)),
        ),
        (
            "aws_access_key_id",
            format!(
                "AKIA{}",
                fill(12, 16)
                    .to_uppercase()
                    .chars()
                    .take(16)
                    .collect::<String>()
            ),
        ),
        (
            "aws_temp_access_key_id",
            format!(
                "ASIA{}",
                fill(13, 16)
                    .to_uppercase()
                    .chars()
                    .take(16)
                    .collect::<String>()
            ),
        ),
        (
            "google_oauth_access_token",
            format!("ya29.{}", fill(14, 30)),
        ),
        ("google_api_key", format!("AIza{}", fill(15, 35))),
        (
            "slack_bot_token",
            format!("xoxb-1234567890-1234567890-{}", fill(16, 24)),
        ),
        ("slack_app_token", format!("xapp-{}", fill(17, 24))),
        ("nvidia_ngc_api_key", format!("nvapi-{}", fill(18, 64))),
        (
            "wandb_api_key_prefixed",
            format!("wandb-{}", hexfill(19, 40)),
        ),
        ("stripe_live_secret", format!("sk_live_{}", fill(20, 24))),
        ("stripe_test_secret", format!("sk_test_{}", fill(21, 24))),
        ("jwt_token", format!("{jwt_hdr}.{jwt_pl}.{}", fill(22, 43))),
    ]
}

#[test]
fn marquee_secrets_are_not_missed_after_curation() {
    let secrets = marquee_secrets();

    // Build one buffer with every secret on its own labeled line, recording
    // each secret's byte span so we can confirm a hit covers it.
    let mut buf: Vec<u8> = Vec::new();
    let mut spans: Vec<(&str, usize, usize)> = Vec::new();
    for (label, secret) in &secrets {
        buf.extend_from_slice(label.as_bytes());
        buf.extend_from_slice(b" = ");
        let start = buf.len();
        buf.extend_from_slice(secret.as_bytes());
        let end = buf.len();
        spans.push((label, start, end));
        buf.push(b'\n');
    }

    let detectors = default_detectors().expect("default rules must compile");
    let engine = Engine::new(detectors);
    let chunk = Chunk {
        bytes: &buf,
        offset: 0,
        origin: ChunkOrigin::Raw,
    };
    let hits = engine.scan_chunk(&chunk);

    // A secret is "caught" if at least one hit overlaps its byte span.
    let mut missed = Vec::new();
    for (label, start, end) in &spans {
        let covered = hits.iter().any(|h| {
            let hs = h.offset as usize;
            let he = hs + h.len;
            hs < *end && he > *start
        });
        if !covered {
            missed.push(*label);
        }
    }

    assert!(
        missed.is_empty(),
        "FALSE NEGATIVE — {} marquee secret(s) no longer detected after rule \
         curation: {:?}\n\
         A quarantine addition removed the only rule covering these. Either \
         reinstate the rule or add a tighter detector to `default.yaml`.",
        missed.len(),
        missed
    );
}
