//! `perf.data` handler.
//!
//! Strategy:
//!   * load the file into memory;
//!   * verify the `PERFILE2` magic and parse the 104-byte
//!     [`perf_file_header`] manually (so we don't depend on a third-party
//!     parser version-matrix for the dispatcher);
//!   * after the data section, walk the packed feature-section
//!     descriptors in `adds_features` bit order and surface each
//!     known textual feature (hostname, osrelease, version, arch,
//!     cpudesc, cmdline, event_desc, …) as its own [`Chunk`] with
//!     an absolute file offset and a labelled [`ChunkOrigin`];
//!   * surface the entire data section as a `Section("data")` chunk
//!     so any tokens that ended up inside `PERF_RECORD_COMM` /
//!     `PERF_RECORD_MMAP` etc. are still caught;
//!   * redaction is plain byte-level zero-fill at the recorded
//!     absolute offsets — the file layout, header offsets, and
//!     length-prefixed strings inside each feature section are all
//!     preserved, so `perf report` continues to parse the result.

use std::io::Read;
use std::path::Path;

use byteorder::{ByteOrder, LittleEndian};
use scrump_core::{
    apply_hits_in_place, Chunk, ChunkOrigin, Format, Handler, Hit, Result, ScrumpError,
};

const MAGIC: &[u8; 8] = b"PERFILE2";
const HEADER_SIZE: usize = 104;

/// Map known feature bits to a human label + origin classification.
/// Bit numbers per `tools/perf/util/header.h` in the Linux kernel.
const KNOWN_FEATURES: &[(u32, &str, FeatureKind)] = &[
    (1, "tracing_data", FeatureKind::Section),
    (2, "build_id", FeatureKind::Section),
    (3, "hostname", FeatureKind::Section),
    (4, "osrelease", FeatureKind::Section),
    (5, "version", FeatureKind::Section),
    (6, "arch", FeatureKind::Section),
    (7, "nrcpus", FeatureKind::Section),
    (8, "cpudesc", FeatureKind::Section),
    (9, "cpuid", FeatureKind::Section),
    (10, "totalmem", FeatureKind::Section),
    (11, "cmdline", FeatureKind::Cmdline),
    (12, "event_desc", FeatureKind::Section),
    (13, "cpu_topology", FeatureKind::Section),
    (14, "numa_topology", FeatureKind::Section),
    (15, "branch_stack", FeatureKind::Section),
    (16, "pmu_mappings", FeatureKind::Section),
    (17, "group_desc", FeatureKind::Section),
    (18, "auxtrace", FeatureKind::Section),
    (19, "stat", FeatureKind::Section),
    (20, "cache", FeatureKind::Section),
    (21, "sample_time", FeatureKind::Section),
    (22, "mem_topology", FeatureKind::Section),
    (23, "clockid", FeatureKind::Section),
    (24, "dir_format", FeatureKind::Section),
    (25, "bpf_prog_info", FeatureKind::Section),
    (26, "bpf_btf", FeatureKind::Section),
    (27, "compressed", FeatureKind::Section),
    (28, "cpu_pmu_caps", FeatureKind::Section),
    (29, "clock_data", FeatureKind::Section),
    (30, "hybrid_topology", FeatureKind::Section),
    (31, "pmu_caps", FeatureKind::Section),
];

#[derive(Debug, Clone, Copy)]
enum FeatureKind {
    Cmdline,
    Section,
}

#[derive(Debug, Clone)]
struct FeatureSpan {
    bit: u32,
    name: &'static str,
    kind: FeatureKind,
    /// Absolute file offset of the feature payload.
    offset: u64,
    size: u64,
}

pub struct PerfData {
    bytes: Vec<u8>,
    /// Absolute file offset of the data section (perf_file_header.data).
    data_offset: u64,
    data_size: u64,
    features: Vec<FeatureSpan>,
}

impl PerfData {
    pub fn open_path(path: &Path) -> Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(ScrumpError::InvalidFile(
                "perf.data shorter than 104-byte header".into(),
            ));
        }
        if &bytes[..8] != MAGIC {
            return Err(ScrumpError::InvalidFile(format!(
                "perf.data: expected magic PERFILE2, got {:?}",
                &bytes[..8]
            )));
        }
        // perf_file_header layout (all u64 LE):
        //   8..16   size
        //   16..24  attr_size
        //   24..32  attrs.offset
        //   32..40  attrs.size
        //   40..48  data.offset
        //   48..56  data.size
        //   56..64  event_types.offset
        //   64..72  event_types.size
        //   72..104 adds_features[4]: u64
        let data_offset = LittleEndian::read_u64(&bytes[40..48]);
        let data_size = LittleEndian::read_u64(&bytes[48..56]);

        let mut adds_features = [0u64; 4];
        for (i, slot) in adds_features.iter_mut().enumerate() {
            *slot = LittleEndian::read_u64(&bytes[72 + i * 8..72 + i * 8 + 8]);
        }

        // Feature descriptors: packed array of perf_file_section{u64 offset, u64 size}
        // located right after the data section, in ascending feature-bit order.
        let mut features = Vec::new();
        let mut cursor = data_offset
            .checked_add(data_size)
            .ok_or_else(|| ScrumpError::InvalidFile("data section overflow".into()))?;

        // Walk every bit from 1..=255 (256-bit bitmap, bit 0 is HEADER_RESERVED).
        for bit in 1..256u32 {
            let word = bit as usize / 64;
            let mask = 1u64 << (bit % 64);
            if adds_features[word] & mask == 0 {
                continue;
            }
            // Read this feature's descriptor at `cursor`.
            let need = cursor
                .checked_add(16)
                .ok_or_else(|| ScrumpError::InvalidFile("feature desc overflow".into()))?;
            if (need as usize) > bytes.len() {
                return Err(ScrumpError::InvalidFile(format!(
                    "feature descriptor for bit {bit} runs past EOF \
                     (cursor={cursor}, file_len={})",
                    bytes.len()
                )));
            }
            let off = LittleEndian::read_u64(&bytes[cursor as usize..cursor as usize + 8]);
            let sz = LittleEndian::read_u64(&bytes[cursor as usize + 8..cursor as usize + 16]);
            cursor += 16;

            if (off + sz) as usize > bytes.len() {
                return Err(ScrumpError::InvalidFile(format!(
                    "feature bit {bit}: payload {off}+{sz} extends past EOF ({})",
                    bytes.len()
                )));
            }

            let (name, kind) = match KNOWN_FEATURES.iter().find(|(b, _, _)| *b == bit) {
                Some((_, n, k)) => (*n, *k),
                None => ("unknown", FeatureKind::Section),
            };

            features.push(FeatureSpan {
                bit,
                name,
                kind,
                offset: off,
                size: sz,
            });
        }

        Ok(Self {
            bytes,
            data_offset,
            data_size,
            features,
        })
    }
}

impl Format for PerfData {
    fn name(&self) -> &'static str {
        "perf"
    }

    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a> {
        let mut chunks: Vec<Chunk<'a>> = Vec::new();

        // 1) Data section as a single chunk (any tokens leaked into
        //    PERF_RECORD_COMM / MMAP / SAMPLE land here).
        if self.data_size > 0 {
            let from = self.data_offset as usize;
            let to = from + self.data_size as usize;
            if to <= self.bytes.len() {
                chunks.push(Chunk {
                    bytes: &self.bytes[from..to],
                    offset: self.data_offset,
                    origin: ChunkOrigin::Section("perf.data.records".into()),
                });
            }
        }

        // 2) Each feature section as its own labelled chunk.
        for f in &self.features {
            let from = f.offset as usize;
            let to = from + f.size as usize;
            if to > self.bytes.len() {
                continue;
            }
            let origin = match f.kind {
                FeatureKind::Cmdline => ChunkOrigin::Cmdline,
                FeatureKind::Section => ChunkOrigin::Section(format!("perf.{}", f.name)),
            };
            chunks.push(Chunk {
                bytes: &self.bytes[from..to],
                offset: f.offset,
                origin,
            });
            // Touch `f.bit` so the field isn't flagged as dead.
            let _ = f.bit;
        }

        Box::new(chunks.into_iter())
    }

    fn apply(&mut self, hits: &[Hit]) -> Result<()> {
        apply_hits_in_place(&mut self.bytes, hits)
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.bytes.clone())
    }
}

// ---- detection / handler registration ---------------------------------------

fn detect(head: &[u8], _path: &Path) -> bool {
    head.len() >= 8 && &head[..8] == MAGIC
}

fn open_path(path: &Path) -> Result<Box<dyn Format>> {
    Ok(Box::new(PerfData::open_path(path)?))
}

fn open_bytes(bytes: Vec<u8>, _hint: Option<&Path>) -> Result<Box<dyn Format>> {
    Ok(Box::new(PerfData::from_bytes(bytes)?))
}

pub fn handler() -> Handler {
    Handler {
        name: "perf",
        detect,
        open_path,
        open_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a perf.data identical to what `make-perf` produces.
    fn synth_perf_data(planted: &[&str]) -> Vec<u8> {
        const NAME_ALIGN: usize = 64;
        let mut cmdline_payload = Vec::new();
        cmdline_payload.extend_from_slice(&(planted.len() as u32).to_le_bytes());
        for s in planted {
            let with_nul = s.len() + 1;
            let padded = if with_nul % NAME_ALIGN == 0 {
                with_nul
            } else {
                with_nul + (NAME_ALIGN - with_nul % NAME_ALIGN)
            };
            cmdline_payload.extend_from_slice(&(padded as u32).to_le_bytes());
            cmdline_payload.extend_from_slice(s.as_bytes());
            cmdline_payload.push(0);
            cmdline_payload.resize(cmdline_payload.len() + padded - with_nul, 0);
        }

        let attr_size: u64 = 136;
        let attrs_off: u64 = 104;
        let attrs_size: u64 = attr_size + 16;
        let data_off: u64 = attrs_off + attrs_size;
        let data_size: u64 = 0;
        let feat_desc_off = data_off + data_size;
        let cmdline_off = feat_desc_off + 16;
        let cmdline_size = cmdline_payload.len() as u64;

        let mut f = Vec::new();
        f.extend_from_slice(b"PERFILE2");
        f.extend_from_slice(&104u64.to_le_bytes());
        f.extend_from_slice(&attr_size.to_le_bytes());
        f.extend_from_slice(&attrs_off.to_le_bytes());
        f.extend_from_slice(&attrs_size.to_le_bytes());
        f.extend_from_slice(&data_off.to_le_bytes());
        f.extend_from_slice(&data_size.to_le_bytes());
        f.extend_from_slice(&0u64.to_le_bytes());
        f.extend_from_slice(&0u64.to_le_bytes());
        // adds_features — set bit 11 (HEADER_CMDLINE)
        let mut feats = [0u64; 4];
        feats[0] |= 1 << 11;
        for v in &feats {
            f.extend_from_slice(&v.to_le_bytes());
        }
        // attrs payload (zeroed, with first byte = type=software=1)
        let mut attr = vec![0u8; attr_size as usize];
        attr[0] = 1;
        f.extend_from_slice(&attr);
        f.extend_from_slice(&0u64.to_le_bytes()); // ids.offset
        f.extend_from_slice(&0u64.to_le_bytes()); // ids.size
                                                  // (data section is empty)
        f.extend_from_slice(&cmdline_off.to_le_bytes());
        f.extend_from_slice(&cmdline_size.to_le_bytes());
        f.extend_from_slice(&cmdline_payload);
        f
    }

    #[test]
    fn parses_synth_perf_data() {
        let planted = [
            "perf",
            "env GH_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa sleep 0.01",
        ];
        let bytes = synth_perf_data(&planted);
        let pd = PerfData::from_bytes(bytes.clone()).expect("parse");
        assert_eq!(pd.bytes.len(), bytes.len());
        let cmdline = pd.features.iter().find(|f| f.bit == 11).expect("cmdline");
        let payload = &pd.bytes[cmdline.offset as usize..(cmdline.offset + cmdline.size) as usize];
        // Planted token visible in the cmdline payload.
        assert!(payload.windows(4).any(|w| w == b"ghp_"));
    }

    #[test]
    fn detect_recognises_magic() {
        let bytes = synth_perf_data(&["sleep"]);
        assert!(detect(&bytes[..16], Path::new("/x/y.perf.data")));
        assert!(!detect(b"not-perf", Path::new("/x/y")));
    }

    #[test]
    fn chunks_include_cmdline_and_data() {
        let bytes = synth_perf_data(&["perf", "sleep ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
        let pd = PerfData::from_bytes(bytes).unwrap();
        let chunks: Vec<_> = pd.chunks().collect();
        assert!(chunks
            .iter()
            .any(|c| matches!(c.origin, ChunkOrigin::Cmdline)));
    }

    #[test]
    fn apply_zero_fills_in_place_preserves_length() {
        let token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cmdline_str = format!("sleep --token={token}");
        let bytes = synth_perf_data(&["perf", &cmdline_str]);
        let pre_len = bytes.len();
        let mut pd = PerfData::from_bytes(bytes).unwrap();

        // Locate the token bytes in the cmdline feature payload.
        let cmdline = pd.features.iter().find(|f| f.bit == 11).cloned().unwrap();
        let pay_start = cmdline.offset as usize;
        let pay_end = pay_start + cmdline.size as usize;
        let pay = &pd.bytes[pay_start..pay_end].to_vec();
        let rel = pay
            .windows(token.len())
            .position(|w| w == token.as_bytes())
            .unwrap();
        let abs = cmdline.offset + rel as u64;

        pd.apply(&[Hit {
            offset: abs,
            len: token.len(),
            rule_id: "test".into(),
            verified: None,
            replacement: scrump_core::Replacement::ZeroFill,
            origin: ChunkOrigin::Cmdline,
        }])
        .unwrap();

        let out = pd.to_bytes().unwrap();
        assert_eq!(out.len(), pre_len);
        // Token bytes are now zeroed.
        assert!(!out.windows(4).any(|w| w == b"ghp_"));
        // PERFILE2 magic intact.
        assert_eq!(&out[..8], b"PERFILE2");
    }
}
