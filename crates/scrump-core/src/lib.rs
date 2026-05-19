//! Core traits and types for `scrump`.
//!
//! A capture file is opened by exactly one [`Format`] implementation, which
//! yields scannable [`Chunk`]s for the detection engine. The engine produces
//! [`Hit`]s, which the format then applies as in-place redactions. The final
//! bytes can be obtained via [`Format::to_bytes`] (used by container formats
//! to repackage their members) or written atomically with [`write_atomic`].

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use regex::bytes::Regex;

// -----------------------------------------------------------------------------
// Types

/// Origin of a chunk inside a capture file. Carrying this with each chunk
/// lets format-specific scrubbers make smarter redaction decisions and lets
/// the CLI explain *where* a hit was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkOrigin {
    /// Generic bytes from an unknown / passthrough format.
    Raw,
    /// The captured process's command-line arguments.
    Cmdline,
    /// The captured process's environment block.
    Env,
    /// A named string table or string pool inside a structured format.
    StringTable(String),
    /// A named subsection of a structured format.
    Section(String),
    /// A nested member (e.g. inside a tar archive).
    NestedMember { path: String, format: String },
}

impl ChunkOrigin {
    /// Wrap an inner origin with an outer container-member context.
    pub fn nested_within(self, container_member: &str, inner_format: &str) -> ChunkOrigin {
        match self {
            ChunkOrigin::NestedMember { path, format } => ChunkOrigin::NestedMember {
                path: format!("{container_member}!{path}"),
                format,
            },
            _ => ChunkOrigin::NestedMember {
                path: container_member.to_string(),
                format: inner_format.to_string(),
            },
        }
    }
}

/// A region inside the source file that the detection engine should scan.
#[derive(Debug, Clone)]
pub struct Chunk<'a> {
    pub bytes: &'a [u8],
    pub offset: u64,
    pub origin: ChunkOrigin,
}

/// Strategy for redacting a [`Hit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replacement {
    /// Replace the matched bytes with NUL of equal length. Structure-preserving.
    ZeroFill,
    /// Replace with a repeating byte pattern of equal length.
    Pattern(Vec<u8>),
    /// Drop the matched region entirely. Only valid for formats that can
    /// absorb length changes (most binary formats cannot).
    Drop,
}

/// A confirmed sensitive region to be redacted.
#[derive(Debug, Clone)]
pub struct Hit {
    pub offset: u64,
    pub len: usize,
    pub rule_id: String,
    pub verified: Option<bool>,
    pub replacement: Replacement,
    pub origin: ChunkOrigin,
}

/// Verification result from an optional live HTTP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    Live,
    Dead,
    Unknown,
}

/// Errors produced by format and engine code.
#[derive(Debug, thiserror::Error)]
pub enum ScrumpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("invalid file: {0}")]
    InvalidFile(String),
    #[error("redaction failed: {0}")]
    RedactionFailed(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ScrumpError>;

// -----------------------------------------------------------------------------
// Format trait + Handler

/// A handler for one specific capture-file format.
///
/// The trait is intentionally `dyn`-compatible: no `Self: Sized` methods, no
/// associated constants. Construction is done via free `fn` pointers on a
/// [`Handler`] so the [`Dispatcher`] can route based on file head bytes.
pub trait Format: Send {
    /// Short human-readable name of the format (e.g. `"perf"`, `"tar"`).
    fn name(&self) -> &'static str;

    /// Iterate scannable chunks for the detection engine.
    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a>;

    /// Apply redactions in place. The implementation chooses whether each
    /// [`Hit`] can be satisfied with [`Replacement::ZeroFill`] alone or
    /// whether structural updates (offsets, checksums, child-format
    /// repackaging) are also needed.
    fn apply(&mut self, hits: &[Hit]) -> Result<()>;

    /// Serialize the (possibly-scrubbed) file to an in-memory byte vector.
    /// Used by container formats (tar, zip, nsys) to repackage child members
    /// without going through a temp file.
    fn to_bytes(&self) -> Result<Vec<u8>>;
}

/// Detection function: given the first ~512 bytes and the original path,
/// decide whether this handler claims the file.
pub type DetectFn = fn(head: &[u8], path: &Path) -> bool;

/// Open from a filesystem path.
pub type OpenPathFn = fn(path: &Path) -> Result<Box<dyn Format>>;

/// Open from an in-memory buffer. `hint_path` lets the implementation
/// preserve filename context (used for atomic-write naming and for
/// extension-based detection of inner members).
pub type OpenBytesFn = fn(bytes: Vec<u8>, hint_path: Option<&Path>) -> Result<Box<dyn Format>>;

/// A handler entry registered with the [`Dispatcher`].
#[derive(Clone, Copy)]
pub struct Handler {
    pub name: &'static str,
    pub detect: DetectFn,
    pub open_path: OpenPathFn,
    pub open_bytes: OpenBytesFn,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

// -----------------------------------------------------------------------------
// Dispatcher

/// Routes a file (by path or bytes) to the appropriate [`Format`] handler.
///
/// Handlers are tried in registration order; the first one whose `detect`
/// returns true wins. If none match and a [`fallback`](Dispatcher::set_fallback)
/// is set, the fallback handles the file. Otherwise [`open_path`] /
/// [`open_bytes`] return [`ScrumpError::UnsupportedFormat`].
#[derive(Default)]
pub struct Dispatcher {
    handlers: Vec<Handler>,
    fallback: Option<Handler>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, h: Handler) {
        self.handlers.push(h);
    }

    pub fn set_fallback(&mut self, h: Handler) {
        self.fallback = Some(h);
    }

    pub fn handlers(&self) -> &[Handler] {
        &self.handlers
    }

    pub fn fallback(&self) -> Option<&Handler> {
        self.fallback.as_ref()
    }

    /// Pick a handler for the given head bytes + path, without opening.
    pub fn find(&self, head: &[u8], path: &Path) -> Option<&Handler> {
        for h in &self.handlers {
            if (h.detect)(head, path) {
                return Some(h);
            }
        }
        self.fallback.as_ref()
    }

    /// Find a handler by name (used by `--format <name>`).
    pub fn find_by_name(&self, name: &str) -> Option<&Handler> {
        self.handlers
            .iter()
            .chain(self.fallback.as_ref())
            .find(|h| h.name == name)
    }

    /// Open a path: read the head, find a handler, open the file.
    pub fn open_path(&self, path: &Path) -> Result<Box<dyn Format>> {
        let head = read_head(path)?;
        let h = self.find(&head, path).ok_or_else(|| {
            ScrumpError::UnsupportedFormat(format!("no handler for {}", path.display()))
        })?;
        (h.open_path)(path)
    }

    /// Open in-memory bytes; use `hint_path` for extension/naming context.
    pub fn open_bytes(&self, bytes: Vec<u8>, hint_path: Option<&Path>) -> Result<Box<dyn Format>> {
        let head_len = bytes.len().min(512);
        let head = &bytes[..head_len];
        let placeholder_path = PathBuf::from("");
        let hint = hint_path.unwrap_or(&placeholder_path);
        let h = self.find(head, hint).ok_or_else(|| {
            ScrumpError::UnsupportedFormat(format!(
                "no handler for in-memory bytes (hint = {})",
                hint.display()
            ))
        })?;
        (h.open_bytes)(bytes, hint_path)
    }

    /// Force a specific handler by name (CLI `--format`).
    pub fn open_path_with(&self, path: &Path, handler_name: &str) -> Result<Box<dyn Format>> {
        let h = self
            .find_by_name(handler_name)
            .ok_or_else(|| ScrumpError::UnsupportedFormat(handler_name.into()))?;
        (h.open_path)(path)
    }
}

fn read_head(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 512];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

// -----------------------------------------------------------------------------
// Detector trait + engine helpers

/// A detection rule: a regex (+ optional entropy floor) matching candidate
/// secrets in arbitrary bytes.
pub trait Detector: Send + Sync {
    fn id(&self) -> &str;
    fn pattern(&self) -> &Regex;
    fn min_entropy(&self) -> Option<f64> {
        None
    }
    fn replacement(&self) -> Replacement {
        Replacement::ZeroFill
    }
    /// If `Some(n)`, the engine reports the n-th regex capture group as the
    /// hit range instead of the whole match. Enables keyword-proximity
    /// patterns like `wandb[\s\S]{0,300}([0-9a-f]{40})` that anchor on a
    /// nearby keyword but redact only the secret itself.
    fn capture_index(&self) -> Option<usize> {
        None
    }
    /// Optional post-pattern filter. Receives the candidate bytes (the
    /// regex match — or the capture group if `capture_index` is set) and
    /// must return `true` to keep the hit, `false` to drop it.
    ///
    /// Used to encode semantic constraints regex can't express — e.g. for
    /// JWT we drop HMAC-signed tokens after base64-decoding the header.
    fn post_filter(&self, _candidate: &[u8]) -> bool {
        true
    }
    fn verify(&self, _candidate: &[u8]) -> VerifyResult {
        VerifyResult::Unknown
    }
}

/// Shannon entropy of a byte slice in bits per byte (range 0.0..=8.0).
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

// -----------------------------------------------------------------------------
// Atomic write helper

/// Write `bytes` to `out` atomically (write to a sibling tmp file, fsync,
/// then rename over the destination).
pub fn write_atomic(out: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_sibling(out);
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, out)?;
    Ok(())
}

fn tmp_sibling(p: &Path) -> PathBuf {
    let mut name: OsString = p
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| OsString::from("out"));
    name.push(".scrump.tmp");
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.join(name),
        _ => PathBuf::from(name),
    }
}

// -----------------------------------------------------------------------------
// In-place byte editor used by every format's `apply` impl.
//
// Single source of truth for byte-level redaction so all formats behave
// identically (length-preserving zero-fill, optional repeating pattern,
// rejection of length-changing `Drop`).

/// Apply a list of [`Hit`]s to a flat byte buffer in place.
///
/// Returns `Err(ScrumpError::RedactionFailed)` on out-of-bounds, empty
/// `Pattern`, or unsupported `Drop`.
pub fn apply_hits_in_place(buf: &mut [u8], hits: &[Hit]) -> Result<()> {
    for h in hits {
        let start = h.offset as usize;
        let end = start
            .checked_add(h.len)
            .ok_or_else(|| ScrumpError::RedactionFailed("hit offset+len overflow".into()))?;
        if end > buf.len() {
            return Err(ScrumpError::RedactionFailed(format!(
                "hit out of bounds: {start}..{end} (buf len {})",
                buf.len()
            )));
        }
        match &h.replacement {
            Replacement::ZeroFill => {
                for b in &mut buf[start..end] {
                    *b = 0;
                }
            }
            Replacement::Pattern(p) => {
                if p.is_empty() {
                    return Err(ScrumpError::RedactionFailed(
                        "empty replacement pattern".into(),
                    ));
                }
                for (i, b) in buf[start..end].iter_mut().enumerate() {
                    *b = p[i % p.len()];
                }
            }
            Replacement::Drop => {
                return Err(ScrumpError::RedactionFailed(
                    "Drop replacement requires a structurally-aware format".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_of_uniform_byte_is_zero() {
        assert_eq!(shannon_entropy(&[0u8; 100]), 0.0);
    }

    #[test]
    fn entropy_of_two_balanced_bytes_is_one() {
        let bytes: Vec<u8> = (0..100)
            .map(|i| if i % 2 == 0 { 0u8 } else { 1u8 })
            .collect();
        assert!((shannon_entropy(&bytes) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_of_random_bytes_is_near_eight() {
        let mut state: u32 = 0xdead_beef;
        let mut bytes = vec![0u8; 4096];
        for b in &mut bytes {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (state >> 24) as u8;
        }
        let h = shannon_entropy(&bytes);
        assert!(h > 7.5, "expected near-uniform entropy, got {h}");
    }

    #[test]
    fn apply_hits_in_place_zero_fill_preserves_length() {
        let mut buf = b"abcdEFGHijkl".to_vec();
        let hit = Hit {
            offset: 4,
            len: 4,
            rule_id: "x".into(),
            verified: None,
            replacement: Replacement::ZeroFill,
            origin: ChunkOrigin::Raw,
        };
        apply_hits_in_place(&mut buf, &[hit]).unwrap();
        assert_eq!(buf, b"abcd\0\0\0\0ijkl");
    }

    #[test]
    fn apply_hits_in_place_pattern_repeats() {
        let mut buf = b"abcdEFGHijkl".to_vec();
        let hit = Hit {
            offset: 4,
            len: 4,
            rule_id: "x".into(),
            verified: None,
            replacement: Replacement::Pattern(b"XY".to_vec()),
            origin: ChunkOrigin::Raw,
        };
        apply_hits_in_place(&mut buf, &[hit]).unwrap();
        assert_eq!(buf, b"abcdXYXYijkl");
    }

    #[test]
    fn apply_hits_in_place_oob_errors() {
        let mut buf = b"short".to_vec();
        let hit = Hit {
            offset: 0,
            len: 100,
            rule_id: "x".into(),
            verified: None,
            replacement: Replacement::ZeroFill,
            origin: ChunkOrigin::Raw,
        };
        assert!(apply_hits_in_place(&mut buf, &[hit]).is_err());
    }

    #[test]
    fn write_atomic_writes_and_renames() {
        let dir = std::env::temp_dir().join(format!(
            "scrump-core-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("file.bin");
        write_atomic(&target, b"hello").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        // Re-write overwrites cleanly.
        write_atomic(&target, b"world").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"world");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dispatcher_picks_first_match_then_fallback() {
        fn d_yes(_h: &[u8], _p: &Path) -> bool {
            true
        }
        fn d_no(_h: &[u8], _p: &Path) -> bool {
            false
        }
        fn op(_p: &Path) -> Result<Box<dyn Format>> {
            Err(ScrumpError::Other("not used".into()))
        }
        fn ob(_b: Vec<u8>, _p: Option<&Path>) -> Result<Box<dyn Format>> {
            Err(ScrumpError::Other("not used".into()))
        }
        let mut d = Dispatcher::new();
        d.register(Handler {
            name: "first",
            detect: d_no,
            open_path: op,
            open_bytes: ob,
        });
        d.register(Handler {
            name: "second",
            detect: d_yes,
            open_path: op,
            open_bytes: ob,
        });
        let pick = d.find(b"", Path::new("/")).unwrap();
        assert_eq!(pick.name, "second");
        d.set_fallback(Handler {
            name: "fb",
            detect: d_no,
            open_path: op,
            open_bytes: ob,
        });
        // First positive still wins
        let pick = d.find(b"", Path::new("/")).unwrap();
        assert_eq!(pick.name, "second");
    }

    #[test]
    fn dispatcher_uses_fallback_when_nothing_matches() {
        fn d_no(_h: &[u8], _p: &Path) -> bool {
            false
        }
        fn op(_p: &Path) -> Result<Box<dyn Format>> {
            Err(ScrumpError::Other("nope".into()))
        }
        fn ob(_b: Vec<u8>, _p: Option<&Path>) -> Result<Box<dyn Format>> {
            Err(ScrumpError::Other("nope".into()))
        }
        let mut d = Dispatcher::new();
        d.register(Handler {
            name: "n",
            detect: d_no,
            open_path: op,
            open_bytes: ob,
        });
        assert!(d.find(b"", Path::new("/")).is_none());
        d.set_fallback(Handler {
            name: "fb",
            detect: d_no,
            open_path: op,
            open_bytes: ob,
        });
        let pick = d.find(b"", Path::new("/")).unwrap();
        assert_eq!(pick.name, "fb");
    }
}
