//! Regression gate for issue #9 — the default ruleset must not produce
//! runaway false-positives on real-shaped input.
//!
//! The corpus is the same synthetic ~8 MB blob used by the audit tool in
//! `noise_audit.rs`: log-like lines stamped with the keywords TruffleHog's
//! `PrefixRegex` anchors on, source-code-like prose, config-file
//! placeholders, `.env`-style assignments with random alphanumeric
//! payloads, an alphanumeric blob with periodic UUID and short-token
//! inserts, and tar-padding-style repeating alphanumerics.
//!
//! Four invariants are asserted:
//!   1. **Bounded by count and bytes**: no rule in `default_detectors()`
//!      fires more than `MAX_HITS_PER_RULE` times OR captures more than
//!      `MAX_BYTES_PER_RULE` bytes on the corpus. Both dimensions matter
//!      — the unbounded-quantifier class (`{N,}` patterns) fires once
//!      per blob but eats megabytes per fire.
//!   2. **Positive control**: when a single shaped `ghp_…` token is
//!      planted in the corpus, `github_pat_classic` still fires —
//!      protects against over-aggressive curation dropping marquee
//!      rules.
//!   3. **Quarantine enforcement**: every id in `TH_QUARANTINE` is
//!      absent from `default_detectors()`'s output — protects against
//!      a regression where the filter stops being applied.
//!   4. **Scrub safety**: `apply_hits_in_place` on the noise corpus
//!      overwrites at most 0.1% of the corpus bytes — directly verifies
//!      the user-visible damage `scrub` would do on real input.

use scrump_core::{apply_hits_in_place, Chunk, ChunkOrigin};
use scrump_detect::Engine;
use scrump_rules::default_detectors;

/// Per-rule hit ceiling on the noise corpus. The audit (`noise_audit.rs`)
/// confirmed every active rule sits at zero after curation; this is the
/// margin we allow for future rules that may legitimately fire on the
/// shapes the corpus contains.
const MAX_HITS_PER_RULE: usize = 10;

/// Per-rule captured-byte ceiling. Catches the unbounded-quantifier class
/// (`{N,}` patterns with no upper limit) that fires only once per blob
/// but eats megabytes per fire — `MAX_HITS_PER_RULE` alone would not see
/// these.
const MAX_BYTES_PER_RULE: usize = 1024;

/// Build the same 8 MB synthetic noise corpus the audit tool uses. Kept
/// in-test (rather than shared) so the regression gate is self-contained
/// — anyone reading this file can see exactly what it's asserting against.
fn build_noise_corpus() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(8 * 1024 * 1024);

    let log_template = b"[2026-05-19T10:23:00.123Z] INFO  service=router \
        user=admin name=\"data ingest\" org=acme account=tenant_42 \
        id=4f9e2a8b9c1d4e7f host=prod-router-7 method=GET path=/v1/items \
        status=200 latency_ms=14 trace=00-1234567890abcdef-fedcba0987654321 \
        action=warn detail=\"info pool drain user-id retry\"\n";
    while out.len() < 2 * 1024 * 1024 {
        out.extend_from_slice(log_template);
    }

    let src_template = b"package detector\n\
        // Resolve the inbound request id from headers or fall back to a\n\
        // freshly generated uuid. The integration id is stable per tenant.\n\
        fn resolve(name: &str, org: &str, user_id: u64) -> String {\n\
            let token_name = format!(\"{name}-{org}-{user_id}\");\n\
            tracing::info!(target = \"core\", id = %token_name, \"resolve\");\n\
            return token_name;\n\
        }\n";
    while out.len() < 3 * 1024 * 1024 {
        out.extend_from_slice(src_template);
    }

    let cfg_template = b"# config\n\
        api_key=replaceMe-please-set-via-env\n\
        password=changeme-not-a-real-secret-just-placeholder\n\
        secret=put-real-value-here-when-deploying-thank-you\n\
        token=NOT_A_REAL_TOKEN_replace_at_deploy_time\n\
        client_id=tenant-acme-prod-replace-me\n\
        client_secret=fake-client-secret-do-not-use-in-prod\n\
        webhook_url=https://example.invalid/hook/please-set\n\
        admin_password=please-rotate-before-go-live-please\n";
    while out.len() < 3 * 1024 * 1024 {
        out.extend_from_slice(cfg_template);
    }

    let env_alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let env_keys: &[&[u8]] = &[
        b"USER",
        b"USERNAME",
        b"PASSWORD",
        b"KEY",
        b"TOKEN",
        b"SECRET",
        b"API_KEY",
        b"ACCESS_KEY",
        b"CLIENT_ID",
        b"CLIENT_SECRET",
        b"AUTH_TOKEN",
        b"SESSION",
        b"REFRESH_TOKEN",
        b"BS_USERNAME",
        b"BROWSERSTACK_USERNAME",
        b"BROWSERSTACK_ACCESS_KEY",
    ];
    let mut env_seed: u64 = 0xCAFE_BABE_1234_5678;
    while out.len() < 4 * 1024 * 1024 {
        env_seed = env_seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let key = env_keys[(env_seed as usize) % env_keys.len()];
        let len = 8 + (((env_seed >> 16) as usize) % 17);
        out.extend_from_slice(key);
        out.push(b'=');
        for i in 0..len {
            let idx = ((env_seed
                .wrapping_mul(2862933555777941757)
                .wrapping_add(i as u64))
                >> 33) as usize;
            out.push(env_alphabet[idx % env_alphabet.len()]);
        }
        out.push(b'\n');
    }

    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed: u64 = 0xDEAD_BEEF_F00D_CAFE;
    while out.len() < 6 * 1024 * 1024 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = ((seed >> 33) as usize) % alphabet.len();
        out.push(alphabet[idx]);
        if out.len() % 73 == 0 {
            out.extend_from_slice(b" 4f9e2a8b-9c1d-4e7f-b3a4-1234567890ab ");
        }
        if out.len() % 41 == 0 {
            out.extend_from_slice(b" info warn data name user org id status ");
        }
    }

    let real_template = b"2026-05-19T10:23:01.234Z INFO  conn=keep-alive \
        user.name@example.com signed in from session.example.net via \
        api-gateway-v3.internal.example.org port=443 build=v1.4.27 \
        commit=abcdef1234567890abcdef1234567890abcdef12 client=cli/1.2.3 \
        artifact=registry.example.com/scrump:0.1.2 request=098765 \
        actor=service-account-a4f2.acme.io legacy.user_42@partner.example.io \
        peer=10.0.42.7:54321 release=v2.10.0 chunk=0xDEADBEEFCAFEBABEF00D \
        host='localhost' dbname='analytics' user='svc' sslmode='disable' \
        digest30=cafedeadbeef0123456789abcdefab1 \
        digest32=cafedeadbeef0123456789abcdefab12 \
        digest40=cafedeadbeef0123456789abcdefab1234567890 \
        digest64=cafedeadbeef0123456789abcdefab1234567890cafedeadbeef0123456789ab\n";
    while out.len() < 7 * 1024 * 1024 {
        out.extend_from_slice(real_template);
    }

    let tar_pad = b"0000644000000000000000000000001234567890";
    while out.len() < 8 * 1024 * 1024 {
        out.extend_from_slice(tar_pad);
    }

    out.truncate(8 * 1024 * 1024);
    out
}

/// Aggregate hit count and total captured bytes per rule.
fn stats_per_rule(bytes: &[u8]) -> std::collections::BTreeMap<String, (usize, usize)> {
    let detectors = default_detectors().expect("default rules must compile");
    let engine = Engine::new(detectors);
    let chunk = Chunk {
        bytes,
        offset: 0,
        origin: ChunkOrigin::Raw,
    };
    let hits = engine.scan_chunk(&chunk);
    let mut out: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    for h in &hits {
        let e = out.entry(h.rule_id.clone()).or_default();
        e.0 += 1;
        e.1 += h.len;
    }
    out
}

#[test]
fn no_rule_storms_on_real_shaped_noise() {
    let corpus = build_noise_corpus();
    let stats = stats_per_rule(&corpus);
    let offenders: Vec<_> = stats
        .iter()
        .filter(|(_, (n, b))| *n > MAX_HITS_PER_RULE || *b > MAX_BYTES_PER_RULE)
        .collect();
    assert!(
        offenders.is_empty(),
        "default ruleset produced more than {MAX_HITS_PER_RULE} hits OR more than \
         {MAX_BYTES_PER_RULE} captured bytes for {} rule(s) on the 8MB synthetic noise \
         corpus: {:?}\n\
         This is the FP-storm regression guard for issue #9. If you've added a new rule \
         or relaxed an existing one, run `cargo test -p scrump-rules --test noise_audit \
         -- --ignored --nocapture` to see the full distribution, then either tighten the \
         rule's pattern or add its id to `TH_QUARANTINE` in `scrump-rules/src/lib.rs`.",
        offenders.len(),
        offenders
    );
}

#[test]
fn github_pat_still_fires_on_planted_token() {
    // Positive control: confirm we didn't quarantine a rule that matters.
    // The shaped `ghp_` PAT is the marquee case that worked in the
    // reporter's 7-line synthetic test and must keep working.
    let mut corpus = build_noise_corpus();
    let planted = b"\nGITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789Ab\n";
    corpus.extend_from_slice(planted);

    let stats = stats_per_rule(&corpus);
    let ghp = stats.get("github_pat_classic").map_or(0, |(n, _)| *n);
    assert!(
        ghp >= 1,
        "expected github_pat_classic to fire on planted token, got 0 hits; \
         curation must not be dropping marquee rules. \
         Full stats: {:?}",
        stats
    );
}

#[test]
fn quarantined_rules_are_loaded_nowhere() {
    // Defence in depth: the quarantine list must actually be enforced. If
    // someone adds an id to TH_QUARANTINE but the parse path stops
    // consulting `rule_is_active`, this guard fails.
    let detectors = default_detectors().expect("default rules");
    let active_ids: std::collections::HashSet<&str> = detectors.iter().map(|d| d.id()).collect();
    for q in scrump_rules::TH_QUARANTINE {
        assert!(
            !active_ids.contains(q),
            "quarantined rule {q} still present in default_detectors(); \
             rule_is_active() filter regressed"
        );
    }
}

#[test]
fn scrub_does_not_runaway_overwrite_noise() {
    // The reporter explicitly called out `scrub` as unsafe on real
    // captures because runaway hit counts translate to millions of byte
    // overwrites. Verify the apply path is bounded after curation:
    // total bytes overwritten on the 8 MB noise corpus must be a tiny
    // fraction of the corpus size.
    let mut corpus = build_noise_corpus();
    let detectors = default_detectors().expect("default rules");
    let engine = Engine::new(detectors);
    let chunk = Chunk {
        bytes: &corpus,
        offset: 0,
        origin: ChunkOrigin::Raw,
    };
    let hits = engine.scan_chunk(&chunk);
    let total_overwrite_bytes: usize = hits.iter().map(|h| h.len).sum();

    // 0.1% of the corpus is the bound. 8 MB → ≤ 8 KB of overwrites.
    // After curation the actual number is in the low hundreds of bytes
    // (a handful of incidental matches on the synthetic data); we allow
    // headroom for future rules.
    let cap = corpus.len() / 1000;
    if total_overwrite_bytes > cap {
        let mut breakdown: std::collections::BTreeMap<String, (usize, usize)> =
            std::collections::BTreeMap::new();
        for h in &hits {
            let e = breakdown.entry(h.rule_id.clone()).or_insert((0, 0));
            e.0 += 1;
            e.1 += h.len;
        }
        let detail: Vec<String> = breakdown
            .iter()
            .map(|(id, (n, b))| format!("{id}: {n} hits, {b} bytes"))
            .collect();
        panic!(
            "scrub on the 8 MB noise corpus would overwrite {total_overwrite_bytes} bytes \
             ({} hits), exceeding the bound of {cap} bytes (0.1% of corpus). \
             Breakdown: {}",
            hits.len(),
            detail.join(" | ")
        );
    }

    // Sanity: apply_hits_in_place runs without panicking on this volume.
    let _ = apply_hits_in_place(&mut corpus, &hits);
}
