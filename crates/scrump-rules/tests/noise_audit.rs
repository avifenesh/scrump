//! Empirical audit of the default ruleset against a synthetic noise corpus
//! designed to mimic the shapes the real-world reproducer in issue #9 was
//! hitting: log-like text with the literal keywords TruffleHog's
//! `PrefixRegex` anchors on (`id`, `name`, `org`, `user`, `key`, `token`,
//! …), source-code text, hex/base64-shaped blobs, and tar-padding-style
//! repeating alphanumerics.
//!
//! This file is an audit tool, not a green/red gate. It is `#[ignore]`d by
//! default and only runs when explicitly invoked, e.g.
//!
//!   cargo test -p scrump-rules --test noise_audit -- --ignored --nocapture
//!
//! When run, it prints a table of every rule firing more than the bound
//! (default 10 hits over the whole ~8 MB corpus). The bounded regression
//! gate lives in `tests/fp_regression.rs`.

use scrump_core::{Chunk, ChunkOrigin};
use scrump_detect::Engine;
use scrump_rules::default_detectors;

/// Deterministic noise corpus. Shape-mimics the reporter's repro inputs.
/// Each section is concatenated; total length ≈ 8 MB.
fn build_noise_corpus() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(8 * 1024 * 1024);

    // -- Section A: log-like text with the keywords PrefixRegex anchors on.
    // The 703 MB SQLite log in the reporter's case was full of structured
    // log lines whose TEXT cells contained these literal English words.
    let log_template = b"[2026-05-19T10:23:00.123Z] INFO  service=router \
        user=admin name=\"data ingest\" org=acme account=tenant_42 \
        id=4f9e2a8b9c1d4e7f host=prod-router-7 method=GET path=/v1/items \
        status=200 latency_ms=14 trace=00-1234567890abcdef-fedcba0987654321 \
        action=warn detail=\"info pool drain user-id retry\"\n";
    while out.len() < 2 * 1024 * 1024 {
        out.extend_from_slice(log_template);
    }

    // -- Section B: source-code-like prose. Mimics package.json / Cargo.toml
    // / Go source the OSS tarball repro was full of.
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

    // -- Section B': config-file shape. The keywords `password`, `key`,
    // `secret`, `api_key`, `token` are the magnet for any TruffleHog rule
    // whose `PrefixRegex` includes them. Use placeholder values that
    // shouldn't match a marquee rule — we're testing for FP storms, not
    // true positives.
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

    // -- Section B'': env-var-style assignments with deterministic random
    // payloads of varied alphanumeric length. This is the shape `.env`
    // file dumps, docker-compose configs, kubernetes secrets manifests,
    // and `printenv` output take. The reporter's repro on a public OSS
    // tarball was dominated by this shape — strings of 8-24 alphanumerics
    // attached to common keywords.
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

    // -- Section C: alphanumeric/UUID-shaped blob. Mimics SQLite BLOB cells
    // and binary tar segments that the reporter's repro showed as the main
    // FP magnet for unanchored short-alnum patterns.
    let mut blob = Vec::with_capacity(2 * 1024 * 1024);
    // Deterministic linear-congruential walk over a 36-char alphabet.
    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed: u64 = 0xDEAD_BEEF_F00D_CAFE;
    while blob.len() < 2 * 1024 * 1024 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = ((seed >> 33) as usize) % alphabet.len();
        blob.push(alphabet[idx]);
        // Inject UUID-shaped tokens periodically so the UUID-keyword rules
        // are stressed too.
        if blob.len() % 73 == 0 {
            blob.extend_from_slice(b" 4f9e2a8b-9c1d-4e7f-b3a4-1234567890ab ");
        }
        // And short alphanumeric runs (4-byte) so the mapbox-style runaway
        // pattern (no boundary, no keyword) has lots of substrate.
        if blob.len() % 41 == 0 {
            blob.extend_from_slice(b" info warn data name user org id status ");
        }
    }
    out.extend_from_slice(&blob);

    // -- Section C': real-log shapes the reporter's actual SQLite log was
    // full of: email addresses, semver versions, dotted hostnames, and
    // long alphanumeric token-shaped strings. These were absent from the
    // earlier sections and let an entire class of broken rules through
    // (rules anchored on `\b<email>\b`, `\d+\.\d+\.\d+`, `\b\d{6}\b`,
    // bare `\b[a-zA-Z0-9]{40}\b`, etc.).
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

    // -- Section D: tar-padding-style repeating alphanumerics.
    let tar_pad = b"0000644000000000000000000000001234567890";
    while out.len() < 8 * 1024 * 1024 {
        out.extend_from_slice(tar_pad);
    }

    out.truncate(8 * 1024 * 1024);
    out
}

/// Aggregate hit count and total captured bytes per rule on the noise
/// corpus. Two dimensions matter: high count (many FPs spread across
/// the corpus) and high captured bytes (a single greedy match can eat
/// megabytes — equally destructive for `scrub`).
fn audit() -> Vec<(String, usize, usize)> {
    let corpus = build_noise_corpus();
    let detectors = default_detectors().expect("default rules must compile");
    let engine = Engine::new(detectors);
    let chunk = Chunk {
        bytes: &corpus,
        offset: 0,
        origin: ChunkOrigin::Raw,
    };
    let hits = engine.scan_chunk(&chunk);

    let mut acc: std::collections::BTreeMap<String, (usize, usize)> =
        std::collections::BTreeMap::new();
    for h in &hits {
        let e = acc.entry(h.rule_id.clone()).or_default();
        e.0 += 1;
        e.1 += h.len;
    }
    let mut out: Vec<(String, usize, usize)> =
        acc.into_iter().map(|(k, (n, b))| (k, n, b)).collect();
    out.sort_by(|a, b| b.2.cmp(&a.2).then(b.1.cmp(&a.1)));
    out
}

#[test]
#[ignore = "audit tool — run explicitly with --ignored --nocapture"]
fn audit_noisy_rules() {
    let hits_bound = 10usize;
    let bytes_bound = 1024usize;
    let all = audit();
    let noisy: Vec<_> = all
        .iter()
        .filter(|(_, n, b)| *n > hits_bound || *b > bytes_bound)
        .collect();
    println!(
        "\nRules exceeding either hits>{hits_bound} or bytes>{bytes_bound} \
         on the ~8MB synthetic noise corpus:\n"
    );
    println!("{:>10}  {:>12}  rule_id", "hits", "bytes");
    println!("{:>10}  {:>12}  -------", "----", "-----");
    for (id, n, b) in &noisy {
        println!("{n:>10}  {b:>12}  {id}");
    }
    println!("\ntotal rules over bounds: {}", noisy.len());
}
