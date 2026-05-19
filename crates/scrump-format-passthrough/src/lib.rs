//! Passthrough format: any file is treated as a single big chunk.
//!
//! Used as the unconditional fallback when no format-specific handler claims
//! the file. Still useful in its own right for log files, plain-text
//! captures, and `.env`-style files.

use std::io::Read;
use std::path::{Path, PathBuf};

use scrump_core::{
    apply_hits_in_place, write_atomic, Chunk, ChunkOrigin, Format, Handler, Hit, Result,
};

pub struct Passthrough {
    /// Original path, retained for debugging / NestedMember labelling.
    path: Option<PathBuf>,
    bytes: Vec<u8>,
}

impl Passthrough {
    pub fn open_path(path: &Path) -> Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Ok(Self {
            path: Some(path.to_path_buf()),
            bytes,
        })
    }

    pub fn open_bytes(bytes: Vec<u8>, hint: Option<&Path>) -> Result<Self> {
        Ok(Self {
            path: hint.map(|p| p.to_path_buf()),
            bytes,
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Format for Passthrough {
    fn name(&self) -> &'static str {
        "passthrough"
    }

    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a> {
        Box::new(std::iter::once(Chunk {
            bytes: &self.bytes,
            offset: 0,
            origin: ChunkOrigin::Raw,
        }))
    }

    fn apply(&mut self, hits: &[Hit]) -> Result<()> {
        apply_hits_in_place(&mut self.bytes, hits)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.bytes.clone())
    }
}

// ---- Handler registration ---------------------------------------------------

/// Always-true detector — passthrough is the universal fallback.
fn detect(_head: &[u8], _path: &Path) -> bool {
    true
}

fn open_path_dyn(path: &Path) -> Result<Box<dyn Format>> {
    Ok(Box::new(Passthrough::open_path(path)?))
}

fn open_bytes_dyn(bytes: Vec<u8>, hint: Option<&Path>) -> Result<Box<dyn Format>> {
    Ok(Box::new(Passthrough::open_bytes(bytes, hint)?))
}

/// Returns the handler suitable for [`scrump_core::Dispatcher::set_fallback`].
pub fn handler() -> Handler {
    Handler {
        name: "passthrough",
        detect,
        open_path: open_path_dyn,
        open_bytes: open_bytes_dyn,
    }
}

/// Convenience helper used by tests and by the CLI scrub flow:
/// scan, redact, atomically write.
pub fn write_to(p: &Passthrough, out: &Path) -> Result<()> {
    write_atomic(out, &p.to_bytes()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrump_core::Replacement;

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "scrump-pt-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn open_path_round_trip() {
        let dir = tempdir();
        let p = dir.join("a.txt");
        std::fs::write(&p, b"hello world").unwrap();
        let pt = Passthrough::open_path(&p).unwrap();
        let chunks: Vec<_> = pt.chunks().collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].bytes, b"hello world");
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].origin, ChunkOrigin::Raw);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_bytes_works_without_path() {
        let pt = Passthrough::open_bytes(b"in-memory".to_vec(), None).unwrap();
        assert_eq!(pt.bytes(), b"in-memory");
        assert!(pt.path().is_none());
    }

    #[test]
    fn zero_fill_preserves_length() {
        let dir = tempdir();
        let p = dir.join("a.txt");
        let content = b"abc SECRET def";
        std::fs::write(&p, content).unwrap();
        let mut pt = Passthrough::open_path(&p).unwrap();
        pt.apply(&[Hit {
            offset: 4,
            len: 6,
            rule_id: "fake".into(),
            verified: None,
            replacement: Replacement::ZeroFill,
            origin: ChunkOrigin::Raw,
        }])
        .unwrap();
        let out = dir.join("clean.txt");
        write_to(&pt, &out).unwrap();
        let result = std::fs::read(&out).unwrap();
        assert_eq!(result.len(), content.len());
        assert_eq!(&result[0..4], b"abc ");
        assert_eq!(&result[4..10], &[0u8; 6]);
        assert_eq!(&result[10..], b" def");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn handler_detects_anything() {
        let h = handler();
        assert_eq!(h.name, "passthrough");
        assert!((h.detect)(b"anything", Path::new("/x/y")));
        assert!((h.detect)(b"", Path::new("")));
    }
}
