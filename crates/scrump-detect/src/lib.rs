//! Detection engine: runs a set of [`Detector`]s over [`Chunk`]s and
//! returns [`Hit`]s.
//!
//! Designed to be cheap to construct, expensive only when scanning. For
//! large files, callers should hand chunks to [`Engine::scan_chunks_par`]
//! which parallelises across `rayon`'s default pool.

use std::collections::HashMap;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use rayon::prelude::*;
use regex::bytes::Regex;
use scrump_core::{shannon_entropy, Chunk, ChunkOrigin, Detector, Hit, RECORD_SEPARATOR};

pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
    /// Per detector, whether its pattern holds an anchor (`has_anchor`),
    /// worked out on the first records scan.
    anchored: OnceLock<Vec<bool>>,
    /// The detectors' keywords, built on the first scan.
    keywords: OnceLock<Keywords>,
}

impl Engine {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self {
            detectors,
            anchored: OnceLock::new(),
            keywords: OnceLock::new(),
        }
    }

    fn keywords(&self) -> &Keywords {
        self.keywords.get_or_init(|| Keywords::new(&self.detectors))
    }

    pub fn detectors(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }

    /// Scan a single chunk and return hits (sequential, single-thread).
    ///
    /// A detector with [`Detector::keywords`] runs only when the chunk holds
    /// one of them; one search finds every detector's keywords.
    pub fn scan_chunk(&self, chunk: &Chunk<'_>) -> Vec<Hit> {
        let live = self.keywords().live(chunk.bytes);
        let mut hits = Vec::new();
        for (det, live) in self.detectors.iter().zip(live) {
            if live {
                scan_with(det.as_ref(), chunk, &mut hits);
            }
        }
        hits
    }

    /// Scan `bytes` as records separated by [`RECORD_SEPARATOR`], each on
    /// its own: the hits are those of [`Engine::scan_chunk`] on every record
    /// as a chunk of its own (offsets in `bytes`, origin `record N` from 0),
    /// so no hit starts in one record and reaches into the next.
    ///
    /// A regex call per detector per record makes many short records slow
    /// (about 0.1 ms a record with the text profile's thousand rules). So the
    /// records are taken in windows of whole records ([`RECORD_WINDOW`]
    /// bytes or more), and in each window a detector searches for its
    /// leftmost match, the search ending at the window's end, scans alone
    /// only the record that match starts in, and searches again from the
    /// next record. That is exact for a pattern without a line or text
    /// anchor: a match a record holds alone is also a match at the same place
    /// in its window, because the window ends where a record does and the
    /// separator, like the end of a text, is no word character (`\b` reads
    /// the same). A pattern with an anchor (`^`, `$`, `\A`, `\z`) is scanned
    /// record by record, and so is the rest of a window once a match runs
    /// past its record. No search reads past its window and a window holds
    /// at most 32 records, so a detector's searches read each byte at most
    /// 32 times.
    ///
    /// A detector with [`Detector::keywords`] skips every window that holds
    /// none of them: a match a record holds alone lies in its window.
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
        let windows = record_windows(&records);
        let live = self.keywords().live_windows(bytes, &records, &windows);
        let anchored = self.anchored.get_or_init(|| {
            self.detectors
                .iter()
                .map(|d| d.anchored().unwrap_or_else(|| has_anchor(d.pattern())))
                .collect()
        });
        let mut hits = Vec::new();
        let every: Vec<u32> = (0..windows.len() as u32).collect();
        for ((det, &anchored), live) in self.detectors.iter().zip(anchored).zip(&live) {
            let det = det.as_ref();
            let live = live.as_deref().unwrap_or(&every);
            for &w in live {
                let (first, end) = windows[w as usize];
                if anchored {
                    for i in first..end {
                        scan_with(det, &chunk(i), &mut hits);
                    }
                    continue;
                }
                let window = &bytes[..records[end - 1].1];
                let mut i = first;
                while i < end {
                    let Some(m) = det.pattern().find_at(window, records[i].0) else {
                        break;
                    };
                    // The first record that ends at or after the match's
                    // start: a match there alone cannot start before it.
                    i += records[i..end].partition_point(|&(_, e)| e < m.start());
                    if i >= end {
                        break;
                    }
                    if m.end() > records[i].1 {
                        // The match runs past its record, so the pattern can
                        // cross separators and each search could run to the
                        // window's end: scan the rest of it record by record.
                        for k in i..end {
                            scan_with(det, &chunk(k), &mut hits);
                        }
                        break;
                    }
                    scan_with(det, &chunk(i), &mut hits);
                    i += 1;
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

/// Every detector's [`Detector::keywords`] in one ASCII case-insensitive
/// search. A detector without keywords is live everywhere.
struct Keywords {
    /// `None` when no detector has keywords.
    search: Option<AhoCorasick>,
    /// Per keyword (search pattern), the detectors it lets run.
    owners: Vec<Vec<usize>>,
    /// Per detector, whether keywords gate it.
    gated: Vec<bool>,
}

impl Keywords {
    fn new(detectors: &[Box<dyn Detector>]) -> Self {
        let mut index: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut owners: Vec<Vec<usize>> = Vec::new();
        let mut gated = vec![false; detectors.len()];
        for (i, d) in detectors.iter().enumerate() {
            // No set, an empty set or an empty keyword: run everywhere.
            let Some(kw) = d.keywords() else { continue };
            if kw.is_empty() || kw.iter().any(|k| k.is_empty()) {
                continue;
            }
            gated[i] = true;
            for k in kw {
                let k = k.to_ascii_lowercase();
                let id = *index.entry(k.clone()).or_insert_with(|| {
                    patterns.push(k);
                    owners.push(Vec::new());
                    owners.len() - 1
                });
                owners[id].push(i);
            }
        }
        let search = (!patterns.is_empty())
            .then(|| {
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::Standard)
                    .build(&patterns)
            })
            .transpose();
        match search {
            Ok(search) => Self {
                search,
                owners,
                gated,
            },
            // A search that cannot be built gates nothing.
            Err(_) => Self {
                search: None,
                owners: Vec::new(),
                gated: vec![false; detectors.len()],
            },
        }
    }

    /// Per detector, whether it runs on `bytes`.
    fn live(&self, bytes: &[u8]) -> Vec<bool> {
        let mut live: Vec<bool> = self.gated.iter().map(|g| !g).collect();
        let Some(search) = &self.search else {
            return live;
        };
        let mut seen = vec![false; self.owners.len()];
        let mut left = self.owners.len();
        for m in search.find_overlapping_iter(bytes) {
            let p = m.pattern().as_usize();
            if !seen[p] {
                seen[p] = true;
                for &d in &self.owners[p] {
                    live[d] = true;
                }
                left -= 1;
                if left == 0 {
                    break;
                }
            }
        }
        live
    }

    /// Per detector, the windows it runs on, ascending: `None` for every
    /// window. A keyword counts for a window when it lies wholly inside it.
    fn live_windows(
        &self,
        bytes: &[u8],
        records: &[(usize, usize)],
        windows: &[(usize, usize)],
    ) -> Vec<Option<Vec<u32>>> {
        let mut live: Vec<Option<Vec<u32>>> =
            self.gated.iter().map(|&g| g.then(Vec::new)).collect();
        let Some(search) = &self.search else {
            return live;
        };
        let starts: Vec<usize> = windows.iter().map(|&(f, _)| records[f].0).collect();
        let ends: Vec<usize> = windows.iter().map(|&(_, e)| records[e - 1].1).collect();
        // The last window each keyword was counted in.
        let mut last = vec![u32::MAX; self.owners.len()];
        for m in search.find_overlapping_iter(bytes) {
            let w = starts.partition_point(|&s| s <= m.start()) - 1;
            if m.end() > ends[w] {
                continue;
            }
            let p = m.pattern().as_usize();
            let w = w as u32;
            if last[p] == w {
                continue;
            }
            last[p] = w;
            for &d in &self.owners[p] {
                if let Some(l) = &mut live[d] {
                    if l.last() != Some(&w) {
                        l.push(w);
                    }
                }
            }
        }
        for l in live.iter_mut().flatten() {
            l.sort_unstable();
            l.dedup();
        }
        live
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

/// The bytes of whole records [`Engine::scan_records`] searches together:
/// no search of its reads past a window of them.
pub const RECORD_WINDOW: usize = 4 << 10;

/// The most records in a window. Each search starts at a record of the
/// window and reads at most to its end, so a detector reads each byte at
/// most this many times.
const WINDOW_RECORDS: usize = 32;

/// Runs of whole records, `(first, end)` indexes: a window closes once it
/// spans [`RECORD_WINDOW`] bytes or holds [`WINDOW_RECORDS`] records.
fn record_windows(records: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut windows = Vec::new();
    let mut first = 0;
    for (i, &(_, end)) in records.iter().enumerate() {
        if end - records[first].0 >= RECORD_WINDOW
            || i + 1 - first == WINDOW_RECORDS
            || i + 1 == records.len()
        {
            windows.push((first, i + 1));
            first = i + 1;
        }
    }
    windows
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

/// Does the pattern hold a line or text anchor? It is parsed back from its
/// text as written and as `RegexBuilder::ignore_whitespace` would read it
/// (where `#` starts a comment), since the builder's flags are not in the
/// text; one it cannot be parsed back from counts as anchored. An anchored
/// pattern is scanned record by record.
fn has_anchor(re: &Regex) -> bool {
    [false, true].into_iter().any(|x| {
        regex_syntax::ParserBuilder::new()
            .utf8(false)
            .ignore_whitespace(x)
            .build()
            .parse(re.as_str())
            .map_or(true, |hir| hir.properties().look_set().contains_anchor())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_windows_close_at_32_records_or_4_kib() {
        let tiny: Vec<_> = (0..70).map(|i| (i * 2, i * 2 + 1)).collect();
        assert_eq!(record_windows(&tiny), vec![(0, 32), (32, 64), (64, 70)]);
        let big = vec![(0, 5000), (5001, 5002), (5003, 9200), (9201, 9300)];
        assert_eq!(record_windows(&big), vec![(0, 1), (1, 3), (3, 4)]);
        assert_eq!(record_windows(&[(0, 0)]), vec![(0, 1)]);
    }

    #[test]
    fn an_anchor_hidden_by_ignore_whitespace_counts() {
        let hidden = regex::bytes::RegexBuilder::new("#[\n^]a")
            .ignore_whitespace(true)
            .build()
            .unwrap();
        assert!(has_anchor(&hidden));
        assert!(has_anchor(&Regex::new("(?:^|x)a").unwrap()));
        assert!(!has_anchor(&Regex::new(r"\bkey\b[^\n]*").unwrap()));
    }
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
