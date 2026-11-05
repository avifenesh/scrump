//! The keyword prefilter loses nothing. For every loaded rule with
//! keywords, text is generated from the rule's own pattern (random members
//! of each class, Unicode case variants included); every match of the
//! pattern in it must hold one of the rule's keywords, and the engine must
//! find exactly what it finds with every keyword gate removed, chunk by
//! chunk and record by record.
//!
//! `SCRUMP_KEYWORDS_CORPUS=DIR` also writes the generated text to DIR, for a
//! differential run of two scrump binaries over it.

use regex_syntax::hir::{Class, Hir, HirKind};
use scrump_core::{Chunk, ChunkOrigin, Detector, Replacement, VerifyResult, RECORD_SEPARATOR};
use scrump_detect::Engine;
use scrump_rules::{default_detectors, text_detectors};

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

/// Bytes the pattern can match, ignoring assertions: mostly ASCII, with a
/// class's non-ASCII members (the Kelvin sign for `k`, the long s for `s`)
/// picked now and then.
fn sample(hir: &Hir, rng: &mut Rng, out: &mut Vec<u8>) {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(l) => out.extend_from_slice(&l.0),
        HirKind::Class(Class::Bytes(c)) => {
            let r = c.ranges()[rng.below(c.ranges().len())];
            out.push(r.start() + rng.below(usize::from(r.end() - r.start()) + 1) as u8);
        }
        HirKind::Class(Class::Unicode(c)) => {
            let ascii: Vec<char> = c
                .ranges()
                .iter()
                .flat_map(|r| r.start()..=r.end().min('\x7f'))
                .collect();
            let ch = if !ascii.is_empty() && rng.below(8) != 0 {
                ascii[rng.below(ascii.len())]
            } else {
                loop {
                    let r = c.ranges()[rng.below(c.ranges().len())];
                    let span = r.end() as u32 - r.start() as u32 + 1;
                    let pick = r.start() as u32 + rng.below(span.min(512) as usize) as u32;
                    if let Some(ch) = char::from_u32(pick) {
                        break ch;
                    }
                }
            };
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        HirKind::Repetition(r) => {
            let max = r.max.unwrap_or(r.min + 12).min(r.min + 12);
            let n = r.min + rng.below((max - r.min) as usize + 1) as u32;
            for _ in 0..n {
                sample(&r.sub, rng, out);
            }
        }
        HirKind::Capture(c) => sample(&c.sub, rng, out),
        HirKind::Concat(hs) => {
            for h in hs {
                sample(h, rng, out);
            }
        }
        HirKind::Alternation(hs) => sample(&hs[rng.below(hs.len())], rng, out),
    }
}

const PER_RULE: usize = 40;

const NOISE: &[&str] = &[
    "the build ran on the main branch",
    "key: value",
    "token count 4096 for the prompt",
    "secret garden path /usr/share/doc",
    "password policy v2",
    "api call returned 200",
    "",
    "id=42 user=bob",
];

/// Generated text per rule with keywords: each sample is one string of the
/// rule's shape set between spaces or noise.
fn planted(detectors: &[Box<dyn Detector>], seed: u64) -> Vec<(String, Vec<Vec<u8>>)> {
    let mut rng = Rng(seed);
    let mut all = Vec::new();
    for d in detectors {
        if d.keywords().is_none() {
            continue;
        }
        let hir = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .build()
            .parse(d.pattern().as_str())
            .expect("loaded pattern parses");
        let mut samples = Vec::new();
        for _ in 0..PER_RULE {
            let mut s = Vec::new();
            s.extend_from_slice(NOISE[rng.below(NOISE.len())].as_bytes());
            s.push(b' ');
            sample(&hir, &mut rng, &mut s);
            s.push(b' ');
            s.extend_from_slice(NOISE[rng.below(NOISE.len())].as_bytes());
            samples.push(s);
        }
        all.push((d.id().to_string(), samples));
    }
    all
}

fn holds_keyword(m: &[u8], keywords: &[&[u8]]) -> bool {
    keywords
        .iter()
        .any(|k| k.len() <= m.len() && m.windows(k.len()).any(|w| w.eq_ignore_ascii_case(k)))
}

#[test]
fn every_planted_match_holds_a_keyword() {
    for (name, detectors) in [
        ("default", default_detectors().unwrap()),
        ("text", text_detectors().unwrap()),
    ] {
        let corpus = planted(&detectors, 0x5eed_0001);
        let by_id: std::collections::HashMap<&str, &dyn Detector> =
            detectors.iter().map(|d| (d.id(), d.as_ref())).collect();
        let (mut matched, mut rules) = (0usize, 0usize);
        for (id, samples) in &corpus {
            let d = by_id[id.as_str()];
            let kw = d.keywords().unwrap();
            let mut hit = false;
            for s in samples {
                for m in d.pattern().find_iter(s) {
                    hit = true;
                    assert!(
                        holds_keyword(m.as_bytes(), kw),
                        "{name}: {id}: match {:?} holds none of {:?}",
                        String::from_utf8_lossy(m.as_bytes()),
                        kw.iter()
                            .map(|k| String::from_utf8_lossy(k))
                            .collect::<Vec<_>>()
                    );
                }
            }
            rules += 1;
            matched += usize::from(hit);
        }
        println!("{name}: {matched} of {rules} gated rules matched their planted text");
        // The generator ignores assertions, so a few shapes never match;
        // nearly all must, or the test proves little.
        assert!(matched * 100 >= rules * 95, "{name}: {matched} of {rules}");
    }
}

/// A detector with its keyword gate removed.
struct Ungated(Box<dyn Detector>);

impl Detector for Ungated {
    fn id(&self) -> &str {
        self.0.id()
    }
    fn pattern(&self) -> &regex::bytes::Regex {
        self.0.pattern()
    }
    fn min_entropy(&self) -> Option<f64> {
        self.0.min_entropy()
    }
    fn replacement(&self) -> Replacement {
        self.0.replacement()
    }
    fn capture_index(&self) -> Option<usize> {
        self.0.capture_index()
    }
    fn post_filter(&self, candidate: &[u8]) -> bool {
        self.0.post_filter(candidate)
    }
    fn post_filter_with_context(&self, candidate: &[u8], before: &[u8], after: &[u8]) -> bool {
        self.0.post_filter_with_context(candidate, before, after)
    }
    fn verify(&self, candidate: &[u8]) -> VerifyResult {
        self.0.verify(candidate)
    }
    fn anchored(&self) -> Option<bool> {
        self.0.anchored()
    }
}

fn hits(h: Vec<scrump_core::Hit>) -> Vec<String> {
    h.into_iter().map(|h| format!("{h:?}")).collect()
}

#[test]
fn the_gate_changes_no_hit() {
    let dump = std::env::var_os("SCRUMP_KEYWORDS_CORPUS").map(std::path::PathBuf::from);
    type Load = fn() -> scrump_core::Result<Vec<Box<dyn Detector>>>;
    for (name, load) in [
        ("default", default_detectors as Load),
        ("text", text_detectors as Load),
    ] {
        let gated = Engine::new(load().unwrap());
        let ungated = Engine::new(
            load()
                .unwrap()
                .into_iter()
                .map(|d| Box::new(Ungated(d)) as Box<dyn Detector>)
                .collect(),
        );
        let corpus = planted(gated.detectors(), 0x5eed_0002);
        // Chunk by chunk: one rule's samples per chunk, so most gates close.
        let mut records = Vec::new();
        let mut total = 0usize;
        for (i, (_, samples)) in corpus.iter().enumerate() {
            let bytes = samples.join(&b'\n');
            let chunk = Chunk {
                bytes: &bytes,
                offset: 0,
                origin: ChunkOrigin::Raw,
            };
            let got = hits(gated.scan_chunk(&chunk));
            total += got.len();
            assert_eq!(got, hits(ungated.scan_chunk(&chunk)), "{name}: rule {i}");
            for s in samples {
                records.extend_from_slice(s);
                records.push(RECORD_SEPARATOR);
            }
            if let Some(dir) = &dump {
                let dir = dir.join(name);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join(format!("rule-{i:04}.txt")), &bytes).unwrap();
            }
        }
        assert!(total > 0);
        // Record by record, every sample its own record.
        let got = hits(gated.scan_records(&records));
        assert!(!got.is_empty());
        assert_eq!(got, hits(ungated.scan_records(&records)), "{name}: records");
        if let Some(dir) = &dump {
            std::fs::write(dir.join(format!("{name}-records.txt")), &records).unwrap();
        }
    }
}
