//! Java HPROF heap-dump handler.
//!
//! HPROF format (per the Eclipse Memory Analyzer reference and the
//! hprof_b_spec.h header that ships with the JDK):
//!
//!   File header (variable length, big-endian):
//!     - NUL-terminated ASCII format string, e.g. `JAVA PROFILE 1.0.2`
//!     - `u32 id_size`                       (size of object IDs in bytes)
//!     - `u32 timestamp_hi`
//!     - `u32 timestamp_lo`
//!
//!   Repeated thereafter, one record per iteration (big-endian fields):
//!     - `u8  tag`
//!     - `u32 ts_delta`     (micros since file start)
//!     - `u32 length`
//!     - `u8[length]` body
//!
//! We emit each record body as a separate [`Chunk`], with an
//! appropriate origin label per known tag. Special-case tag 0x01
//! (UTF8 STRING) which has the layout `id (id_size bytes) +
//! utf8 string` — we surface the utf8 portion as
//! [`ChunkOrigin::StringTable("hprof.utf8")`] so the engine concentrates
//! on what's almost certainly a leak vector.
//!
//! Redaction is byte-level zero-fill at absolute file offsets. The
//! header, every record's tag/length triplet, and the segment structure
//! of HEAP DUMP SEGMENT records remain untouched — only payload bytes
//! the engine flagged get zeroed. JVMs and analyzers tolerate that
//! gracefully (zeroed string data renders as control characters, but
//! the file remains structurally valid).

use std::io::Read;
use std::path::Path;

use byteorder::{BigEndian, ByteOrder};
use scrump_core::{
    apply_hits_in_place, Chunk, ChunkOrigin, Format, Handler, Hit, Result, ScrumpError,
};

const MIN_MAGIC_PREFIX: &[u8] = b"JAVA PROFILE";

#[derive(Clone, Debug)]
struct RecordRange {
    tag: u8,
    /// Absolute file offset of the record body (after the 9-byte tag+ts+len triplet).
    body_offset: u64,
    body_len: u64,
    /// Size of object IDs in this file (only relevant for tag 0x01 STRING records,
    /// where the first `id_size` bytes of the body are the string id, NOT scannable).
    id_size: u32,
}

pub struct Hprof {
    bytes: Vec<u8>,
    records: Vec<RecordRange>,
}

impl Hprof {
    pub fn open_path(path: &Path) -> Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if !bytes.starts_with(MIN_MAGIC_PREFIX) {
            return Err(ScrumpError::InvalidFile(
                "HPROF: missing 'JAVA PROFILE' magic prefix".into(),
            ));
        }
        // Find the NUL terminator of the format string.
        let nul = bytes
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| ScrumpError::InvalidFile("HPROF: missing NUL in header".into()))?;
        // After NUL: u32 id_size, u32 ts_hi, u32 ts_lo
        let header_after = nul + 1;
        if bytes.len() < header_after + 12 {
            return Err(ScrumpError::InvalidFile(
                "HPROF: truncated header (need id_size + timestamp)".into(),
            ));
        }
        let id_size = BigEndian::read_u32(&bytes[header_after..header_after + 4]);
        if !(1..=16).contains(&id_size) {
            return Err(ScrumpError::InvalidFile(format!(
                "HPROF: implausible id_size {id_size}"
            )));
        }
        let mut cursor = (header_after + 12) as u64;

        let mut records = Vec::new();
        while (cursor as usize) + 9 <= bytes.len() {
            let off = cursor as usize;
            let tag = bytes[off];
            let length = BigEndian::read_u32(&bytes[off + 5..off + 9]) as u64;
            let body_offset = cursor + 9;
            let body_end = body_offset + length;
            if (body_end as usize) > bytes.len() {
                return Err(ScrumpError::InvalidFile(format!(
                    "HPROF: record at {off:#x} (tag {tag:#x}, length {length}) extends past EOF ({} bytes)",
                    bytes.len()
                )));
            }
            records.push(RecordRange {
                tag,
                body_offset,
                body_len: length,
                id_size,
            });
            cursor = body_end;
        }

        Ok(Self { bytes, records })
    }
}

fn tag_label(tag: u8) -> &'static str {
    match tag {
        0x01 => "HPROF_UTF8",
        0x02 => "HPROF_LOAD_CLASS",
        0x03 => "HPROF_UNLOAD_CLASS",
        0x04 => "HPROF_FRAME",
        0x05 => "HPROF_TRACE",
        0x06 => "HPROF_ALLOC_SITES",
        0x07 => "HPROF_HEAP_SUMMARY",
        0x0A => "HPROF_START_THREAD",
        0x0B => "HPROF_END_THREAD",
        0x0C => "HPROF_HEAP_DUMP",
        0x0D => "HPROF_CPU_SAMPLES",
        0x0E => "HPROF_CONTROL_SETTINGS",
        0x1C => "HPROF_HEAP_DUMP_SEGMENT",
        0x2C => "HPROF_HEAP_DUMP_END",
        _ => "HPROF_UNKNOWN",
    }
}

impl Format for Hprof {
    fn name(&self) -> &'static str {
        "hprof"
    }

    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a> {
        let mut out: Vec<Chunk<'a>> = Vec::new();
        for r in &self.records {
            if r.body_len == 0 {
                continue;
            }
            let from = r.body_offset as usize;
            let to = from + r.body_len as usize;
            if to > self.bytes.len() {
                continue;
            }
            // UTF8 STRING: skip the id at the start, yield the rest as a tight
            // StringTable chunk; the whole body is also yielded as a generic
            // chunk for redundancy in case the id_size assumption is off.
            if r.tag == 0x01 && r.body_len > r.id_size as u64 {
                let s_from = from + r.id_size as usize;
                out.push(Chunk {
                    bytes: &self.bytes[s_from..to],
                    offset: s_from as u64,
                    origin: ChunkOrigin::StringTable("hprof.utf8".into()),
                });
            }
            out.push(Chunk {
                bytes: &self.bytes[from..to],
                offset: r.body_offset,
                origin: ChunkOrigin::Section(format!("hprof.{}", tag_label(r.tag))),
            });
        }
        Box::new(out.into_iter())
    }

    fn apply(&mut self, hits: &[Hit]) -> Result<()> {
        apply_hits_in_place(&mut self.bytes, hits)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.bytes.clone())
    }
}

// ---- handler ---------------------------------------------------------------

fn detect(head: &[u8], _path: &Path) -> bool {
    head.starts_with(MIN_MAGIC_PREFIX)
}

fn open_path(path: &Path) -> Result<Box<dyn Format>> {
    Ok(Box::new(Hprof::open_path(path)?))
}

fn open_bytes(bytes: Vec<u8>, _hint: Option<&Path>) -> Result<Box<dyn Format>> {
    Ok(Box::new(Hprof::from_bytes(bytes)?))
}

pub fn handler() -> Handler {
    Handler {
        name: "hprof",
        detect,
        open_path,
        open_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrump_core::Replacement;

    /// Build a tiny hprof file containing one UTF8 string record.
    fn synth_hprof(planted: &str) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(b"JAVA PROFILE 1.0.2\0");
        f.extend_from_slice(&(8u32).to_be_bytes()); // id_size = 8
        f.extend_from_slice(&(0u32).to_be_bytes()); // ts_hi
        f.extend_from_slice(&(0u32).to_be_bytes()); // ts_lo
                                                    // Record: UTF8 STRING (tag 0x01).
        let body_len = 8 + planted.len();
        f.push(0x01);
        f.extend_from_slice(&(0u32).to_be_bytes()); // ts_delta
        f.extend_from_slice(&(body_len as u32).to_be_bytes());
        f.extend_from_slice(&(42u64).to_be_bytes()); // string id
        f.extend_from_slice(planted.as_bytes());
        // Heap dump end record (tag 0x2C, empty).
        f.push(0x2C);
        f.extend_from_slice(&(0u32).to_be_bytes());
        f.extend_from_slice(&(0u32).to_be_bytes());
        f
    }

    #[test]
    fn detect_recognises_magic() {
        assert!(detect(b"JAVA PROFILE 1.0.2\0xxx", Path::new("/x/a.hprof")));
        assert!(!detect(b"random", Path::new("/x/a")));
    }

    #[test]
    fn parses_synthetic_hprof() {
        let token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let f = synth_hprof(token);
        let pre_len = f.len();
        let mut h = Hprof::from_bytes(f).unwrap();
        let chunks: Vec<_> = h.chunks().collect();
        // At least: UTF8 StringTable + UTF8 Section + HEAP_DUMP_END (skipped, len=0).
        let saw_string = chunks
            .iter()
            .any(|c| matches!(&c.origin, ChunkOrigin::StringTable(s) if s == "hprof.utf8"));
        assert!(saw_string);

        // Find the planted token's offset.
        let pos = h
            .bytes
            .windows(token.len())
            .position(|w| w == token.as_bytes())
            .unwrap() as u64;
        h.apply(&[Hit {
            offset: pos,
            len: token.len(),
            rule_id: "x".into(),
            verified: None,
            replacement: Replacement::ZeroFill,
            origin: ChunkOrigin::StringTable("hprof.utf8".into()),
        }])
        .unwrap();
        let out = h.to_bytes().unwrap();
        assert_eq!(out.len(), pre_len);
        assert!(!out.windows(token.len()).any(|w| w == token.as_bytes()));
        assert!(out.starts_with(MIN_MAGIC_PREFIX));
    }
}
