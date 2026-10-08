//! The text profile (`scrump --profile text`) must redact the secret in each
//! text shape below and leave the prose, paths and counts alone.
//!
//! Every secret-shaped vector is stored reversed and rebuilt at run time, so
//! this file carries nothing a secret scanner would flag.

use scrump_core::{apply_hits_in_place, Chunk, ChunkOrigin};
use scrump_detect::Engine;
use scrump_rules::text_detectors;

fn rev(s: &str) -> String {
    s.chars().rev().collect()
}

fn engine() -> &'static Engine {
    static E: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
    E.get_or_init(|| Engine::new(text_detectors().expect("text profile loads")))
}

fn scrub(input: &str) -> String {
    let engine = engine();
    let mut bytes = input.as_bytes().to_vec();
    let hits = engine.scan_chunk(&Chunk {
        bytes: &bytes,
        offset: 0,
        origin: ChunkOrigin::Raw,
    });
    apply_hits_in_place(&mut bytes, &hits).expect("apply");
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn text_secrets_are_masked() {
    let body = "b3BlbnNzaC1".repeat(7);
    // (line with {} where the secret goes, secret), both reversed.
    let cases: &[(&str, &str)] = &[
        ("bd/h@}{:u//:sergtsop=bd", "wPterceSrepuS"),
        ("}\"}{\":\"drowssap\"{", "2retnuh2retnuh"),
        (
            "}{ cisaB :noitazirohtuA",
            "4321aaaaaaaaaaaaaaaaaaaawpjclNXd",
        ),
        ("}{ yek", "4321aaaaaaaaaaaaaaaaaaaa_evil_ks"),
        ("}{=YEK_IPA", "dcba"),
        ("'}{' :terces_tneilc", "zzzzzzzz"),
        ("}{ = nekot", "4321aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_phg"),
        ("}{ drowssap--", "x2retnuh"),
        ("\"}{\":\"drowssap\"\\", "zz9zz9zz"),
        ("\"}{ esroh tcerroc\" :drowssap", "elpats yrettab"),
        ("}{ nekot :noitazirohtuA", "210987654321fedcba"),
        ("x//:sptth }{:resu u- lruc", "54321wp"),
        ("}{=ssap_bd", "32!ytrewQ"),
        ("}{ :drowssap", "hsifdrows"),
        ("}{ :DROWSSAP_BD", "sergtsop"),
        ("}{ :dwssap", "niemtel"),
        ("}{ :yek_ipa", "hgfedcba"),
        ("}{=nekoThtua", "88zZ88zZ"),
        ("0/9736:tsoh@}{://:sider", "dr0wss4p"),
        ("ponmlkjihgfedcba=}{ ;krad=emeht :eikooC", "dinoisses"),
        ("bd h- }{p- lqsym", "ssaPterc3S"),
        (
            "}{/000B/000T/secivres/moc.kcals.skooh//:sptth",
            "XXXXXXXXXXXXXXXXXXXXXXXX",
        ),
        (
            "}{ :atad-yek-tneilc",
            "==QLtLS0tLKVERVFBRJUFgSU0VBiTdJRUC1tL0tSL",
        ),
        ("}{=NEKOT_IPA=tnemnorivnE:2:ecivres.cvs", "88qwLd93kZ"),
        ("loot }{=NEKOT_BUHTIG :egasU", "88qwLd93kZ"),
        ("1=z&}{=nekot_ssecca?y/x//:sptth", "88qwLd93kZ"),
        ("}{=drowssap?bd/tsoh@resu//:lqsergtsop", "88qwLd93kZ"),
        ("}{=YEK_SSECCA_TERCES_SWA:eton", "88qwLd93kZ88qwLd93kZ"),
        ("}{=drowssapbd", "88qwLd93kZ"),
        ("}{=NEKOTBUHTIG", "88qwLd93kZ"),
        ("}{ :nekothtua", "88qwLd93kZ"),
        ("}{=nekoThtua_:/gro.sjmpn.yrtsiger//", "88qwLd93kZ"),
        ("\"}{\" =: yeKipa", "88qwLd93kZ"),
        ("\"}{\" = gnirts drowssap rav", "88qwLd93kZ"),
        ("\"}{\" = gnirts :nekot tsnoc", "88qwLd93kZ"),
        ("}{ esarhpssap--", "88qwLd93kZ"),
        ("}{ drowssap-bd--", "88qwLd93kZ"),
        ("x//:sptth }{:u resu-- lruc", "88qwLd93kZ"),
        ("}{=ESARHPSSAP_HSS", "88qwLd93kZ"),
        ("\"sdrow }{\"=DROWSSAP_BD\n=YEK_IPA", "owt retnuh"),
        ("\"}{\" = ]\"yek_ipa\"[gfc", "88qwLd93kZ"),
        (
            "}{=YEK_GNINGIS",
            "=7bA5zY3xW1vU9tS7rQ5pO3nM1lK9jI7hG5fE+3dC/1bA",
        ),
        ("}{=YEK_GNINGIS", "21ba21ba21ba21ba21ba21ba21ba21ba"),
        ("}{=SNEKOT_HTUA", "88qwLd93kZ"),
        ("}{=terceSnekothserfer", "88qwLd93kZ"),
    ];
    for (tpl, sec) in cases {
        let secret = rev(sec);
        let line = rev(tpl).replace("{}", &secret);
        let out = scrub(&line);
        assert!(
            !out.contains(&secret),
            "{line:?} -> {out:?} still holds the secret"
        );
    }
    // Bare key bodies, with and without a grep path prefix.
    for line in [body.clone(), format!("lab/ssh/kv013-root:2:{body}")] {
        let out = scrub(&line);
        assert!(!out.contains(&body[..30]), "{line:?} -> {out:?}");
    }
    // A key block cut off before END still loses its body.
    let open = format!(
        "{}{}\nMIIEvQIBADANBg\nMIIEvQIBADANBg",
        "-----BEGIN ", "PRIVATE KEY-----"
    );
    assert!(!scrub(&open).contains("MIIEvQIBADANBg"));
    let age = format!("AGE-SECRET-KEY-1{}", "Q".repeat(58));
    assert!(!scrub(&age).contains(&"Q".repeat(58)));
}

#[test]
fn text_prose_paths_and_counts_are_kept() {
    let keep = [
        "the max_tokens=4096 setting",
        "https://github.com/avifenesh/tacit",
        "tokens: 12 per fact",
        "token: expires",
        "tokenizer: x",
        "eos_token: </s>",
        "secretName: db-credentials",
        "token_url: https://a/b",
        "password_file: /etc/app/pw",
        "Basic /home/avifenesh/projects/tacit/design.md",
        "multi-token prediction (MTP) heads",
        "per-token latency",
        "time-to-first-token figures",
        "two-pass and multi-pass runs",
        "the token configuration is stored",
        "bypass: always",
        "NOPASSWD: ALL",
        "passes: RocksDB compaction",
        "hadToken=false",
        "hadToken=false.",
        "--token-file /x/y",
        "a 2-pass sweep",
        "cache_ttl=3600",
        "sha256 75a47c46e5d2b1a0f3c9e8d7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1",
        "diverges at token 36",
        "per emitted token 936",
        "split token F1",
        "67-token 2026-09-03",
        "find . -print0",
        "cc -pthread x.c",
        "docker run -u 1000:1000 img",
        "git push -u origin main",
        "Basic authentication is off",
        "Basic principles",
        "/home/avifenesh/projects/tacit/client/cmd/tacit/reviewui/DESIGN.md",
        "primary_key=user_id_2026_10_08_abc",
        "PASS: Laya",
        "auth: scrypt",
        "research/hebrew-asr-20260902/day-20260907/science/H1-RESULTS.md",
        "rollout_summaries/2026-09-26T12-47-24-90Uf-run.md",
        "tokens_per_second=12345",
        "total_tokens_used=4096",
        "total_tokens=4096",
        "tokenization_time=12ms",
        "secretary=Jane",
        "key=bench:1234567890:profile",
        "{\"key\":\"memra/receipts/2026-10-08/run1.json\"}",
        "s3_key=uploads/2026/Q3-summary-v2.pdf",
        "token embedding-dimension-analysis-step",
        "Basic interoperability testing",
        "name\t= barbaz",
        "max_tokens\t= 4096 ok",
        "DB_PASSWORD=$DB_PASSWORD",
        "DB_PASSWORD=${DB_PASSWORD}",
        "pw=$(cat /run/secret)",
        "password=********;echo hi",
    ];
    for line in keep {
        let out = scrub(line);
        assert_eq!(out, line, "{line:?} over-redacted to {out:?}");
    }
}
