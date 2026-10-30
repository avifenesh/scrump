//! `Engine::scan_records` finds exactly what scanning each record alone
//! finds, for the text profile and the default rules, on generated records
//! that put secrets, open quotes, filtered values, keywords and flags at
//! record starts and ends.
//!
//! Secret-shaped fragments are built from pieces at run time, so this file
//! carries nothing a secret scanner would flag.

use scrump_core::{Chunk, ChunkOrigin, RECORD_SEPARATOR};
use scrump_detect::Engine;
use scrump_rules::{default_detectors, text_detectors};

fn text_engine() -> &'static Engine {
    static E: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
    E.get_or_init(|| Engine::new(text_detectors().expect("text profile loads")))
}

fn default_engine() -> &'static Engine {
    static E: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
    E.get_or_init(|| Engine::new(default_detectors().expect("default rules load")))
}

/// xorshift64*: a fixed sequence per seed, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn fragments() -> Vec<String> {
    let pw = ["pass", "word"].concat();
    let canary = ["Zq7", "Vx9", "Lm2", "Kp4"].concat();
    vec![
        format!("{pw}: '{canary}' and the rest"),
        format!("{pw}={canary}"),
        format!("--{pw} {canary}"),
        format!(
            "{}: '{}{} cut here",
            ["api", "_key"].concat(),
            "Wq8Ux0",
            "Kn3Jp5"
        ),
        format!(
            "token_url: 'https://auth.example.invalid/oauth/{}",
            "p".repeat(40)
        ),
        format!("DB_{}='$(vault read secret/db", ["PASS", "WORD"].concat()),
        format!("Authorization: Bearer {}{}", "aB3xQ7p9Lm", "Z2v8KrYfNc4WdG"),
        format!("AKIA{}", "Q".repeat(16)),
        format!("ghp_{}", "aB3xQ7p9LmZ2v8KrYfNc4WdGtJhMsE1oU6iA"),
        format!(
            "{} build",
            "a1b2c3d4e5f6a7b8c9d0".to_owned() + "e1f2a3b4c5d6"
        ),
        "notes on the abstract".to_string(),
        ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat(),
        "b3BlbnNzaC1".repeat(7),
        "max_tokens=4096".to_string(),
        "'".to_string(),
        "\"".to_string(),
        "\n".to_string(),
        " ".to_string(),
        "the build ran".to_string(),
        "cache_ttl=3600".to_string(),
        "x".to_string(),
        // Patterns that run on across separators with no bound.
        "GET /x cookie: id=7 ok".to_string(),
        "ldap://host/x".to_string(),
        "!!!!".to_string(),
        format!("{{ {}", ["auth_provider", "_x509_cert_url"].concat()),
        ["-----END RSA ", "PRIVATE KEY-----"].concat(),
        "mysql -u root".to_string(),
    ]
}

/// Hits as (offset, len, rule, origin), sorted: a duplicate counts.
type Hits = Vec<(u64, usize, String, String)>;

fn sorted(hits: Vec<scrump_core::Hit>) -> Hits {
    let mut out: Hits = hits
        .into_iter()
        .map(|h| (h.offset, h.len, h.rule_id, format!("{:?}", h.origin)))
        .collect();
    out.sort();
    out
}

fn alone(engine: &Engine, bytes: &[u8]) -> Hits {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, rec) in bytes.split(|b| *b == RECORD_SEPARATOR).enumerate() {
        let chunk = Chunk {
            bytes: rec,
            offset: start as u64,
            origin: ChunkOrigin::Section(format!("record {i}")),
        };
        out.extend(engine.scan_chunk(&chunk));
        start += rec.len() + 1;
    }
    sorted(out)
}

fn records(engine: &Engine, bytes: &[u8]) -> Hits {
    sorted(engine.scan_records(bytes))
}

#[test]
fn scan_records_finds_what_each_record_alone_finds() {
    let frags = fragments();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut with_hits = 0;
    for case in 0..200 {
        let mut input = String::new();
        // Every fourth case spans several windows (32 records each).
        let n = 1 + rng.below(if case % 4 == 0 { 120 } else { 12 });
        for _ in 0..n {
            for _ in 0..rng.below(5) {
                input.push_str(&frags[rng.below(frags.len())]);
                if rng.below(3) == 0 {
                    input.push(' ');
                }
            }
            input.push(RECORD_SEPARATOR as char);
        }
        if rng.below(2) == 0 {
            input.pop(); // no separator after the last record
        }
        for (name, engine) in [("text", text_engine()), ("default", default_engine())] {
            let want = alone(engine, input.as_bytes());
            let got = records(engine, input.as_bytes());
            assert_eq!(got, want, "{name} profile, case {case}: {input:?}");
            with_hits += usize::from(!want.is_empty());
        }
    }
    assert!(with_hits > 200, "the cases hold hits: {with_hits}");
}

#[test]
fn scan_records_names_each_record() {
    let pw = ["pass", "word"].concat();
    let input = format!("clean\x1e\x1e{pw}=abcd1234");
    let hits = text_engine().scan_records(input.as_bytes());
    assert!(!hits.is_empty());
    for h in hits {
        assert_eq!(h.origin, ChunkOrigin::Section("record 2".into()));
        assert!(h.offset >= 7);
    }
}
