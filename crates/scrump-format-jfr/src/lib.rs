//! Java Flight Recorder (JFR) handler.
//!
//! JFR 2.x file format (per the OpenJDK source under
//! `src/jdk.jfr/share/classes/jdk/jfr/internal/`):
//!
//!   Repeated, one or more chunks per file:
//!     - bytes 0..4: magic `FLR\0`
//!     - bytes 4..6: major version (u16 BE)
//!     - bytes 6..8: minor version (u16 BE)
//!     - bytes 8..16: chunk size in bytes (u64 BE, total — incl. header)
//!     - bytes 16..24: constant-pool offset within the chunk (u64 BE)
//!     - bytes 24..32: metadata offset within the chunk (u64 BE)
//!     - bytes 32..40: start nanos (u64 BE)
//!     - bytes 40..48: duration nanos (u64 BE)
//!     - bytes 48..56: start ticks (u64 BE)
//!     - bytes 56..64: ticks per second (u64 BE)
//!     - bytes 64..68: features (u32 BE)
//!     - body up to chunk_size
//!
//! Strategy: walk chunks by `chunk_size`, surface each chunk's
//! post-header body as a single scannable [`Chunk`] with absolute file
//! offset; redact via byte-level zero-fill. The 68-byte chunk header is
//! *never* exposed to the scanner — the magic, version bytes, and the
//! offset fields stay untouched, so the file's chunk structure remains
//! intact and downstream tooling (`jfr summary`, JDK Mission Control)
//! continues to parse it.

use std::io::Read;
use std::path::Path;

use byteorder::{BigEndian, ByteOrder};
use scrump_core::{
    apply_hits_in_place, Chunk, ChunkOrigin, Format, Handler, Hit, Result, ScrumpError,
};

const MAGIC: &[u8; 4] = b"FLR\0";
const CHUNK_HEADER_SIZE: u64 = 68;

#[derive(Clone, Debug)]
struct ChunkRange {
    /// Absolute file offset of this chunk's magic byte.
    chunk_start: u64,
    /// Total size of this chunk (incl. header).
    chunk_size: u64,
    major: u16,
    minor: u16,
}

pub struct Jfr {
    bytes: Vec<u8>,
    chunks: Vec<ChunkRange>,
}

impl Jfr {
    pub fn open_path(path: &Path) -> Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < CHUNK_HEADER_SIZE as usize {
            return Err(ScrumpError::InvalidFile(
                "JFR: file shorter than one chunk header (68 bytes)".into(),
            ));
        }
        let mut chunks = Vec::new();
        let mut cursor: u64 = 0;
        while (cursor as usize) < bytes.len() {
            if (cursor as usize) + CHUNK_HEADER_SIZE as usize > bytes.len() {
                return Err(ScrumpError::InvalidFile(format!(
                    "JFR: incomplete chunk header at offset {cursor}"
                )));
            }
            let head = &bytes[cursor as usize..cursor as usize + CHUNK_HEADER_SIZE as usize];
            if &head[..4] != MAGIC {
                return Err(ScrumpError::InvalidFile(format!(
                    "JFR: bad magic at chunk offset {cursor} (got {:?})",
                    &head[..4]
                )));
            }
            let major = BigEndian::read_u16(&head[4..6]);
            let minor = BigEndian::read_u16(&head[6..8]);
            let chunk_size = BigEndian::read_u64(&head[8..16]);
            if chunk_size < CHUNK_HEADER_SIZE {
                return Err(ScrumpError::InvalidFile(format!(
                    "JFR: chunk at {cursor} declares size {chunk_size} < header size"
                )));
            }
            if cursor + chunk_size > bytes.len() as u64 {
                return Err(ScrumpError::InvalidFile(format!(
                    "JFR: chunk at {cursor} (size {chunk_size}) extends past EOF ({} bytes)",
                    bytes.len()
                )));
            }
            chunks.push(ChunkRange {
                chunk_start: cursor,
                chunk_size,
                major,
                minor,
            });
            cursor += chunk_size;
        }
        Ok(Self { bytes, chunks })
    }
}

impl Format for Jfr {
    fn name(&self) -> &'static str {
        "jfr"
    }

    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a> {
        let mut out: Vec<Chunk<'a>> = Vec::new();
        for (i, c) in self.chunks.iter().enumerate() {
            let body_start = c.chunk_start + CHUNK_HEADER_SIZE;
            let body_end = c.chunk_start + c.chunk_size;
            if body_end as usize > self.bytes.len() || body_start >= body_end {
                continue;
            }
            out.push(Chunk {
                bytes: &self.bytes[body_start as usize..body_end as usize],
                offset: body_start,
                origin: ChunkOrigin::Section(format!("jfr.chunk[{i}].v{}.{}", c.major, c.minor)),
            });
        }
        Box::new(out.into_iter())
    }

    fn apply(&mut self, hits: &[Hit]) -> Result<()> {
        // Guard: every hit must land entirely inside a chunk body — never
        // touching a chunk header (magic, version, size, offsets).
        for h in hits {
            let placed = self.chunks.iter().any(|c| {
                let body_start = c.chunk_start + CHUNK_HEADER_SIZE;
                let body_end = c.chunk_start + c.chunk_size;
                h.offset >= body_start && (h.offset + h.len as u64) <= body_end
            });
            if !placed {
                return Err(ScrumpError::RedactionFailed(format!(
                    "JFR: hit at offset {} (len {}) is outside any chunk body — \
                     would corrupt header bytes",
                    h.offset, h.len
                )));
            }
        }
        apply_hits_in_place(&mut self.bytes, hits)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.bytes.clone())
    }
}

// ---- handler registration --------------------------------------------------

fn detect(head: &[u8], _path: &Path) -> bool {
    head.len() >= 4 && &head[..4] == MAGIC
}

fn open_path(path: &Path) -> Result<Box<dyn Format>> {
    Ok(Box::new(Jfr::open_path(path)?))
}

fn open_bytes(bytes: Vec<u8>, _hint: Option<&Path>) -> Result<Box<dyn Format>> {
    Ok(Box::new(Jfr::from_bytes(bytes)?))
}

pub fn handler() -> Handler {
    Handler {
        name: "jfr",
        detect,
        open_path,
        open_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrump_core::Replacement;

    fn synth_jfr_chunk(body: &[u8]) -> Vec<u8> {
        let chunk_size = CHUNK_HEADER_SIZE + body.len() as u64;
        let mut h = Vec::with_capacity(chunk_size as usize);
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&2u16.to_be_bytes()); // major
        h.extend_from_slice(&1u16.to_be_bytes()); // minor
        h.extend_from_slice(&chunk_size.to_be_bytes());
        for _ in 0..6 {
            h.extend_from_slice(&0u64.to_be_bytes());
        }
        h.extend_from_slice(&0u32.to_be_bytes()); // features
        assert_eq!(h.len(), CHUNK_HEADER_SIZE as usize);
        h.extend_from_slice(body);
        h
    }

    #[test]
    fn detect_recognises_magic() {
        assert!(detect(b"FLR\0xxxx", Path::new("/x")));
        assert!(!detect(b"NOPE", Path::new("/x")));
    }

    #[test]
    fn parses_single_chunk_and_redacts_body() {
        let token = b"hf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let body = [b"prefix " as &[u8], token, b" suffix"].concat();
        let f = synth_jfr_chunk(&body);
        let pre_len = f.len();
        let mut j = Jfr::from_bytes(f.clone()).unwrap();
        // Locate token.
        let pos = f.windows(token.len()).position(|w| w == token).unwrap() as u64;
        j.apply(&[Hit {
            offset: pos,
            len: token.len(),
            rule_id: "test".into(),
            verified: None,
            replacement: Replacement::ZeroFill,
            origin: ChunkOrigin::Section("jfr.chunk[0]".into()),
        }])
        .unwrap();
        let out = j.to_bytes().unwrap();
        assert_eq!(out.len(), pre_len);
        assert!(!out.windows(token.len()).any(|w| w == token));
        assert_eq!(&out[..4], MAGIC);
    }

    #[test]
    fn refuses_to_redact_header_bytes() {
        let body = b"body";
        let f = synth_jfr_chunk(body);
        let mut j = Jfr::from_bytes(f).unwrap();
        // Hit lands at offset 0 (the magic) — must be rejected.
        let err = j
            .apply(&[Hit {
                offset: 0,
                len: 4,
                rule_id: "x".into(),
                verified: None,
                replacement: Replacement::ZeroFill,
                origin: ChunkOrigin::Section("evil".into()),
            }])
            .unwrap_err();
        assert!(matches!(err, ScrumpError::RedactionFailed(_)));
    }

    #[test]
    fn handles_multiple_chunks_in_one_file() {
        let mut f = Vec::new();
        f.extend(synth_jfr_chunk(b"chunk-a-body"));
        f.extend(synth_jfr_chunk(b"chunk-b-body"));
        let j = Jfr::from_bytes(f).unwrap();
        assert_eq!(j.chunks.len(), 2);
        let chunks: Vec<_> = j.chunks().collect();
        assert_eq!(chunks.len(), 2);
    }
}
