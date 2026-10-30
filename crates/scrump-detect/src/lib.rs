//! Detection engine: runs a set of [`Detector`]s over [`Chunk`]s and
//! returns [`Hit`]s.
//!
//! Designed to be cheap to construct, expensive only when scanning. For
//! large files, callers should hand chunks to [`Engine::scan_chunks_par`]
//! which parallelises across `rayon`'s default pool.

use std::sync::OnceLock;

use rayon::prelude::*;
use regex::bytes::Regex;
use scrump_core::{shannon_entropy, Chunk, ChunkOrigin, Detector, Hit, RECORD_SEPARATOR};

pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
    /// Per detector, whether its pattern holds an anchor (`has_anchor`),
    /// worked out on the first records scan.
    anchored: OnceLock<Vec<bool>>,
}

impl Engine {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self {
            detectors,
            anchored: OnceLock::new(),
        }
    }

    pub fn detectors(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }

    /// Scan a single chunk and return hits (sequential, single-thread).
    pub fn scan_chunk(&self, chunk: &Chunk<'_>) -> Vec<Hit> {
        let mut hits = Vec::new();
        for det in &self.detectors {
            scan_with(det.as_ref(), chunk, &mut hits);
        }
        hits
    }

    /// Scan `bytes` as records separated by [`RECORD_SEPARATOR`], each on
    /// its own: the hits are those of [`Engine::scan_chunk`] on every record
    /// as a chunk of its own (offsets in `bytes`, origin `record N`), so no
    /// hit starts in one record and reaches into the next.
    ///
    /// A regex call per detector per record makes many short records slow
    /// (about 0.1 ms a record with the text profile's thousand rules), so
    /// each detector first searches `bytes` whole and only the records a
    /// match can start in are scanned alone.
    /// That is exact for a pattern without a line or text anchor: a match a
    /// record holds alone is also a match at the same place in `bytes`,
    /// because the separator, like the end of a text, is no word character
    /// (`\b` reads the same), and the leftmost match in `bytes` starts at or
    /// before it. A pattern with an anchor (`^`, `$`, `\A`, `\z`) is scanned
    /// record by record.
    pub fn scan_records(&self, bytes: &[u8]) -> Vec<Hit> {
        let records = record_spans(bytes);
        let chunk = |i: usize| {
            let (start, end) = records[i];
            Chunk {
                bytes: &bytes[start..end],
                offset: start as u64,
                origin: ChunkOrigin::Section(format!("record {i}")),
            }
        };
        let anchored = self.anchored.get_or_init(|| {
            self.detectors
                .iter()
                .map(|d| has_anchor(d.pattern()))
                .collect()
        });
        let mut hits = Vec::new();
        for (det, &anchored) in self.detectors.iter().zip(anchored) {
            let det = det.as_ref();
            if anchored {
                for i in 0..records.len() {
                    scan_with(det, &chunk(i), &mut hits);
                }
                continue;
            }
            let mut i = 0;
            while i < records.len() {
                let Some(m) = det.pattern().find_at(bytes, records[i].0) else {
                    break;
                };
                // The first record that ends at or after the match's start: a
                // match there alone cannot start before it.
                i += records[i..].partition_point(|&(_, end)| end < m.start());
                if i >= records.len() {
                    break;
                }
                scan_with(det, &chunk(i), &mut hits);
                i += 1;
            }
        }
        hits
    }

    /// Scan many chunks in parallel via rayon.
    pub fn scan_chunks_par<'a, I>(&self, chunks: I) -> Vec<Hit>
    where
        I: IntoParallelIterator<Item = Chunk<'a>>,
    {
        chunks
            .into_par_iter()
            .flat_map(|c| self.scan_chunk(&c))
            .collect()
    }
}

/// One detector's hits in one chunk, the context its filter reads bounded
/// by the chunk.
fn scan_with(det: &dyn Detector, chunk: &Chunk<'_>, hits: &mut Vec<Hit>) {
    let mut keep = |start: usize, end: usize| {
        let matched = &chunk.bytes[start..end];
        if let Some(min) = det.min_entropy() {
            if shannon_entropy(matched) < min {
                return;
            }
        }
        if !det.post_filter_with_context(matched, &chunk.bytes[..start], &chunk.bytes[end..]) {
            return;
        }
        hits.push(Hit {
            offset: chunk.offset + start as u64,
            len: end - start,
            rule_id: det.id().to_string(),
            verified: None,
            replacement: det.replacement(),
            origin: chunk.origin.clone(),
        });
    };
    match det.capture_index() {
        Some(ci) => {
            for caps in det.pattern().captures_iter(chunk.bytes) {
                if let Some(m) = caps.get(ci) {
                    keep(m.start(), m.end());
                }
            }
        }
        None => {
            for m in det.pattern().find_iter(chunk.bytes) {
                keep(m.start(), m.end());
            }
        }
    }
}

/// The records of `bytes`: the spans between separators, the last one
/// running to the end. Empty input is one empty record.
fn record_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (i, b) in bytes.iter().enumerate() {
        if *b == RECORD_SEPARATOR {
            spans.push((start, i));
            start = i + 1;
        }
    }
    spans.push((start, bytes.len()));
    spans
}

/// Does the pattern hold a line or text anchor? One it cannot be parsed
/// back from counts as anchored: it is then scanned record by record.
fn has_anchor(re: &Regex) -> bool {
    regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(re.as_str())
        .map_or(true, |hir| hir.properties().look_set().contains_anchor())
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;
    use scrump_core::ChunkOrigin;
    use std::sync::OnceLock;

    struct GhPat;
    impl Detector for GhPat {
        fn id(&self) -> &str {
            "github_pat_classic"
        }
        fn pattern(&self) -> &Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap())
        }
    }

    struct HighEntropy;
    impl Detector for HighEntropy {
        fn id(&self) -> &str {
            "high_entropy_40"
        }
        fn pattern(&self) -> &Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new(r"[A-Za-z0-9]{40}").unwrap())
        }
        fn min_entropy(&self) -> Option<f64> {
            Some(4.5)
        }
    }

    #[test]
    fn finds_planted_ghp_token() {
        let bytes = b"some prefix ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa some suffix";
        let chunk = Chunk {
            bytes,
            offset: 100,
            origin: ChunkOrigin::Raw,
        };
        let eng = Engine::new(vec![Box::new(GhPat)]);
        let hits = eng.scan_chunk(&chunk);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "github_pat_classic");
        assert_eq!(hits[0].len, 40);
        // offset is chunk.offset + match-start-within-chunk
        assert_eq!(hits[0].offset, 100 + 12);
    }

    #[test]
    fn entropy_floor_suppresses_low_entropy_match() {
        // 40 A's: pattern matches, but entropy is 0 < 4.5
        let bytes = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let chunk = Chunk {
            bytes,
            offset: 0,
            origin: ChunkOrigin::Raw,
        };
        let eng = Engine::new(vec![Box::new(HighEntropy)]);
        assert!(eng.scan_chunk(&chunk).is_empty());
    }

    #[test]
    fn entropy_floor_admits_high_entropy_match() {
        // 40 chars from a high-entropy run
        let bytes = b"aB3xQ7p9LmZ2v8KrYfNc4WdGtJhMsE1oU6iA0Bnq";
        assert_eq!(bytes.len(), 40);
        let chunk = Chunk {
            bytes,
            offset: 0,
            origin: ChunkOrigin::Raw,
        };
        let eng = Engine::new(vec![Box::new(HighEntropy)]);
        let hits = eng.scan_chunk(&chunk);
        assert_eq!(hits.len(), 1);
    }

    struct Contextual {
        capture: bool,
    }

    impl Detector for Contextual {
        fn id(&self) -> &str {
            "contextual-test"
        }
        fn pattern(&self) -> &Regex {
            static CAPTURE: OnceLock<Regex> = OnceLock::new();
            static WHOLE: OnceLock<Regex> = OnceLock::new();
            if self.capture {
                CAPTURE.get_or_init(|| Regex::new(r"KEY=(secret)").unwrap())
            } else {
                WHOLE.get_or_init(|| Regex::new(r"secret").unwrap())
            }
        }
        fn capture_index(&self) -> Option<usize> {
            self.capture.then_some(1)
        }
        fn post_filter_with_context(&self, candidate: &[u8], before: &[u8], after: &[u8]) -> bool {
            assert_eq!(candidate, b"secret");
            before.ends_with(b"KEY=") && after.starts_with(b";")
        }
    }

    #[test]
    fn context_tracks_the_selected_capture_or_whole_match_without_shifting_offsets() {
        let bytes = b"secret KEY=secret; KEY=secretX";
        let chunk = Chunk {
            bytes,
            offset: 100,
            origin: ChunkOrigin::Raw,
        };
        for capture in [false, true] {
            let engine = Engine::new(vec![Box::new(Contextual { capture })]);
            let hits = engine.scan_chunk(&chunk);
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].offset, 111);
            assert_eq!(hits[0].len, 6);
        }
    }

    struct CandidateOnly;
    impl Detector for CandidateOnly {
        fn id(&self) -> &str {
            "candidate-only"
        }
        fn pattern(&self) -> &Regex {
            static PATTERN: OnceLock<Regex> = OnceLock::new();
            PATTERN.get_or_init(|| Regex::new("secret").unwrap())
        }
        fn post_filter(&self, candidate: &[u8]) -> bool {
            assert_eq!(candidate, b"secret");
            false
        }
    }

    #[test]
    fn context_default_keeps_existing_candidate_only_filters() {
        let engine = Engine::new(vec![Box::new(CandidateOnly)]);
        assert!(engine
            .scan_chunk(&Chunk {
                bytes: b"KEY=secret;",
                offset: 0,
                origin: ChunkOrigin::Raw,
            })
            .is_empty());
    }
}
