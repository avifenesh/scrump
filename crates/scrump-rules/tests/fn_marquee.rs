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
        // 23-char suffix: longer than gitlab_v2__keypat's 20..22 cap, so
        // only the curated gitlab_pat rule catches it (issue #10 probe).
        ("gitlab_pat", format!("glpat-_{}", fill(23, 22))),
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
        (
            "microsoft_teams_webhook_v2",
            format!(
                "https://default{}.62.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/{}/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig={}",
                hexfill(24, 28),
                hexfill(25, 32),
                fill(26, 43),
            ),
        ),
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
fn microsoft_teams_webhook_requires_signature_in_any_query_position() {
    let base = format!(
        "https://default{}.62.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/{}/triggers/manual/paths/invoke",
        hexfill(27, 28),
        hexfill(28, 32),
    );
    let sig = fill(29, 43);
    let signed_last =
        format!("{base}?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig={sig}");
    let signed_first =
        format!("{base}?sig={sig}&api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0");
    let unsigned = format!("{base}?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0");

    let detectors = default_detectors().expect("default rules must compile");
    let engine = Engine::new(detectors);
    for candidate in [&signed_last, &signed_first] {
        let chunk = Chunk {
            bytes: candidate.as_bytes(),
            offset: 0,
            origin: ChunkOrigin::Raw,
        };
        let hits = engine.scan_chunk(&chunk);
        assert!(
            hits.iter().any(
                |hit| hit.rule_id == "microsoft_teams_webhook_v2" && hit.len == candidate.len()
            ),
            "expected signed Teams webhook to be detected: {candidate}"
        );
    }

    let chunk = Chunk {
        bytes: unsigned.as_bytes(),
        offset: 0,
        origin: ChunkOrigin::Raw,
    };
    assert!(
        engine
            .scan_chunk(&chunk)
            .iter()
            .all(|hit| hit.rule_id != "microsoft_teams_webhook_v2"),
        "unsigned Teams webhook must not be treated as a credential"
    );
}

#[test]
fn survey_key_detected_but_a_lane_slug_is_not() {
    // `surveyanyplace__idpat` (keyword `(?i:survey)` — the English word — plus
    // `\b([a-z0-9A-Z-]{36})\b`) was quarantined on 2026-09-02: the hyphen in the class makes any
    // 36-char slug near the word "survey" a hit, and one of those hits sat in a research index
    // that nearly every change touches, so a pre-commit gate was unpassable without an override
    // and two lanes typed one in a day. Both halves of the decision are asserted here, because
    // each without the other is a defect: dropping the id rule is only correct if the KEY rule
    // still fires, and keeping the key rule is only useful if the id rule has actually stopped.
    //
    // The key is assembled at runtime (same reason as `marquee_secrets`): this source file must
    // not itself carry a key-shaped literal.
    let key = fill(57, 32);
    assert_eq!(
        key.len(),
        32,
        "surveyanyplace__keypat wants exactly 32 chars"
    );
    assert!(
        !key.contains('-'),
        "the key shape excludes the hyphen — that is the whole difference from the id rule"
    );

    // Verbatim from the repo that surfaced this (research/INDEX.md line 70), and the two other
    // captures the same pattern produced across two more repos. All three used to block a commit.
    let prose = "| engines-kv-oversubscription-20260830 | SURVEY: no public receipts for a                  reuse-vs-recompute crossover cell (nobody publishes one). Survey only, no                  engine decision | `engines-kv-oversubscription-20260830/RESEARCH.md` |
                 a survey of what-reads-as-trustworthy-verified-claims in engine READMEs
                 survey of direct-subscription-patterns-revenue for the business direction
";
    let credential = format!("SURVEY_ANYPLACE_API_KEY={key}\n");

    let detectors = default_detectors().expect("default rules must compile");
    let engine = Engine::new(detectors);

    // --- the key must still be caught (anti-blind) ---
    let buf = credential.clone().into_bytes();
    let hits = engine.scan_chunk(&Chunk {
        bytes: &buf,
        offset: 0,
        origin: ChunkOrigin::Raw,
    });
    assert!(
        hits.iter().any(|h| h.rule_id == "surveyanyplace__keypat"),
        "FALSE NEGATIVE — a Survey Anyplace API key is no longer detected. Quarantining \
         `surveyanyplace__idpat` made `surveyanyplace` a known-noisy provider, and the structural \
         sweep has now eaten the paired key rule as collateral; it needs a STRUCTURAL_ALLOWLIST \
         entry. Rules that did fire: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );

    // --- the prose must produce no surveyanyplace hit at all (the false positive being removed) ---
    let buf = prose.as_bytes();
    let hits = engine.scan_chunk(&Chunk {
        bytes: buf,
        offset: 0,
        origin: ChunkOrigin::Raw,
    });
    let survey_hits: Vec<&String> = hits
        .iter()
        .filter(|h| h.rule_id.starts_with("surveyanyplace__"))
        .map(|h| &h.rule_id)
        .collect();
    assert!(
        survey_hits.is_empty(),
        "prose about surveys must not read as a credential; still firing: {survey_hits:?}"
    );
}

#[test]
fn harvest_token_detected_but_account_id_is_not() {
    // `harvest__idpat` (keyword `harvest` + a bare 4-9 digit integer) was quarantined on
    // 2026-08-23 because it is Harvest's ACCOUNT id, not a credential, and it fired 450 times
    // across 421 files of a real prose repo — dates inside branch names, upstream issue numbers,
    // tensor dims. Both halves of that decision are asserted here, because each without the
    // other is a defect: dropping the id rule is only correct if the TOKEN rule still fires, and
    // keeping the token rule is only useful if the id rule has actually stopped.
    //
    // The token is assembled at runtime (same reason as `marquee_secrets`): this source file must
    // not itself carry a token-shaped literal.
    let token = fill(31, 97);
    assert_eq!(token.len(), 97, "harvest__keypat wants exactly 97 chars");

    // Verbatim shapes from the repo that surfaced this, both of which used to block a commit.
    let prose = "**B0 done (memra lane/dspark-harvest-fix-20260820 @ 77ffb69a37)**: flag-gated \
                 shifted-label harvest, oracle emits DSPARK-strategy reference by default\n\
                 DISPATCHED: box6 -> H4 confidence-window verify prototype (stacked on the \
                 harvest fix; sglang v0.5.16 planner + vLLM #47808 as references)\n";
    let credential = format!("HARVEST_ACCESS_TOKEN={token}\n");

    let detectors = default_detectors().expect("default rules must compile");
    let engine = Engine::new(detectors);

    // --- the token must still be caught (anti-blind) ---
    let buf = credential.clone().into_bytes();
    let hits = engine.scan_chunk(&Chunk {
        bytes: &buf,
        offset: 0,
        origin: ChunkOrigin::Raw,
    });
    assert!(
        hits.iter().any(|h| h.rule_id == "harvest__keypat"),
        "FALSE NEGATIVE — a Harvest bearer token is no longer detected. Quarantining \
         `harvest__idpat` made `harvest` a known-noisy provider, and the structural sweep has \
         now eaten the paired token rule as collateral; it needs a STRUCTURAL_ALLOWLIST entry. \
         Rules that did fire: {:?}",
        hits.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
    );

    // --- the prose must produce no harvest hit at all (the false positive being removed) ---
    let buf = prose.as_bytes();
    let hits = engine.scan_chunk(&Chunk {
        bytes: buf,
        offset: 0,
        origin: ChunkOrigin::Raw,
    });
    let harvest: Vec<_> = hits
        .iter()
        .filter(|h| h.rule_id.starts_with("harvest__"))
        .map(|h| {
            (
                h.rule_id.clone(),
                String::from_utf8_lossy(&buf[h.offset as usize..h.offset as usize + h.len])
                    .into_owned(),
            )
        })
        .collect();
    assert!(
        harvest.is_empty(),
        "a dated lane name and an upstream issue number still match a harvest rule, so the \
         forced-override loop this quarantine was meant to end is back: {harvest:?}"
    );
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
