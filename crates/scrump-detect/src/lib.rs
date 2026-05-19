//! Detection engine: runs a set of [`Detector`]s over [`Chunk`]s and
//! returns [`Hit`]s.
//!
//! Designed to be cheap to construct, expensive only when scanning. For
//! large files, callers should hand chunks to [`Engine::scan_chunks_par`]
//! which parallelises across `rayon`'s default pool.

use rayon::prelude::*;
use scrump_core::{shannon_entropy, Chunk, Detector, Hit};

pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    pub fn detectors(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }

    /// Scan a single chunk and return hits (sequential, single-thread).
    pub fn scan_chunk(&self, chunk: &Chunk<'_>) -> Vec<Hit> {
        let mut hits = Vec::new();
        for det in &self.detectors {
            match det.capture_index() {
                Some(ci) => {
                    for caps in det.pattern().captures_iter(chunk.bytes) {
                        let Some(m) = caps.get(ci) else { continue };
                        let matched = &chunk.bytes[m.start()..m.end()];
                        if let Some(min) = det.min_entropy() {
                            if shannon_entropy(matched) < min {
                                continue;
                            }
                        }
                        if !det.post_filter(matched) {
                            continue;
                        }
                        hits.push(Hit {
                            offset: chunk.offset + m.start() as u64,
                            len: m.end() - m.start(),
                            rule_id: det.id().to_string(),
                            verified: None,
                            replacement: det.replacement(),
                            origin: chunk.origin.clone(),
                        });
                    }
                }
                None => {
                    for m in det.pattern().find_iter(chunk.bytes) {
                        let matched = &chunk.bytes[m.start()..m.end()];
                        if let Some(min) = det.min_entropy() {
                            if shannon_entropy(matched) < min {
                                continue;
                            }
                        }
                        if !det.post_filter(matched) {
                            continue;
                        }
                        hits.push(Hit {
                            offset: chunk.offset + m.start() as u64,
                            len: m.end() - m.start(),
                            rule_id: det.id().to_string(),
                            verified: None,
                            replacement: det.replacement(),
                            origin: chunk.origin.clone(),
                        });
                    }
                }
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
}
