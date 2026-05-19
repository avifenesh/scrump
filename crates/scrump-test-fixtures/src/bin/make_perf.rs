//! Generate a deterministic, spec-compliant `perf.data` file with planted
//! tokens in the HEADER_CMDLINE feature section.
//!
//! The resulting file:
//!   * starts with the canonical `PERFFILE2` magic;
//!   * has a valid 104-byte `perf_file_header`;
//!   * carries one `perf_event_attr` (zeroed software-dummy) in the attrs
//!     section, so `linux-perf-data` recognises it as a real perf capture;
//!   * has an empty data section;
//!   * has HEADER_CMDLINE set in `adds_features` with the planted tokens
//!     appearing verbatim inside the variable-length string table.
//!
//! Usage: `make-perf <output_path> <planted_str_1> [planted_str_2 ...]`
//!
//! On default invocation by the e2e gate we plant two strings:
//!   "perf"   (the command name)
//!   "env GH_TOKEN=<ghp_...> HF_TOKEN=<hf_...> sleep 0.05"

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use scrump_test_fixtures::pad_to;

// ---- perf.data magic & layout constants -------------------------------------

/// On-disk magic for the PERF_MAGIC2 format. Kernel constant:
///   `#define PERF_MAGIC2  0x32454c4946524550ULL  /* "PERFILE2" */`
/// Little-endian, eight bytes — P E R F I L E 2.
const MAGIC: &[u8; 8] = b"PERFILE2";

/// `sizeof(perf_event_attr)` we'll claim — must be ≥ first 8 bytes used by
/// the parser. We use the modern value (136) so `linux-perf-data` accepts
/// us as a current-generation capture.
const ATTR_SIZE: u64 = 136;

/// HEADER_CMDLINE feature bit (per kernel `tools/perf/util/header.h`).
/// Enum order: RESERVED(0), TRACING_DATA(1), BUILD_ID(2), HOSTNAME(3),
/// OSRELEASE(4), VERSION(5), ARCH(6), NRCPUS(7), CPUDESC(8), CPUID(9),
/// TOTAL_MEM(10), CMDLINE(11), ...
const FEAT_CMDLINE: u32 = 11;

/// NAME_ALIGN — perf pads strings to multiples of this when writing the
/// HEADER_CMDLINE / HEADER_HOSTNAME / etc. string blobs.
const NAME_ALIGN: usize = 64;

// ---- helpers ----------------------------------------------------------------

fn write_string_blob(buf: &mut Vec<u8>, s: &str) {
    // u32 len (incl NUL, padded to NAME_ALIGN), then padded bytes.
    let raw = s.as_bytes();
    let with_nul = raw.len() + 1;
    let padded = scrump_test_fixtures::round_up(with_nul, NAME_ALIGN);
    buf.write_u32::<LittleEndian>(padded as u32).unwrap();
    buf.extend_from_slice(raw);
    buf.push(0);
    // zero-fill up to `padded`
    buf.extend(std::iter::repeat(0u8).take(padded - with_nul));
}

fn build_cmdline_section(strs: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.write_u32::<LittleEndian>(strs.len() as u32).unwrap();
    for s in strs {
        write_string_blob(&mut buf, s);
    }
    buf
}

// ---- main -------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, planted) = match args.as_slice() {
        [out, planted @ ..] if !planted.is_empty() => (out.clone(), planted.to_vec()),
        _ => {
            eprintln!("usage: make-perf <output> <planted_str> [more...]");
            std::process::exit(2);
        }
    };

    // ----- layout ------------------------------------------------------------
    //  0..104      perf_file_header
    //  104..240    perf_event_attr (136 bytes, zeroed)
    //  240..256    perf_file_section { ids.offset=0, ids.size=0 }
    //  256..256    data section: empty
    //  256..272    perf_file_section for HEADER_CMDLINE
    //  272..       cmdline payload

    // attrs section starts at 104, holds attr (136) + ids section header (16) = 152
    let attrs_offset: u64 = 104;
    let attrs_size: u64 = ATTR_SIZE + 16;
    let data_offset: u64 = attrs_offset + attrs_size; // 272 in our layout
    let data_size: u64 = 0;

    // Feature section descriptors come right after the data section.
    let features_descriptor_offset: u64 = data_offset + data_size;
    let cmdline_offset: u64 = features_descriptor_offset + 16; // one feature
    let cmdline_payload = build_cmdline_section(&planted);
    let cmdline_size = cmdline_payload.len() as u64;

    // ----- assemble ---------------------------------------------------------
    let mut file = Vec::with_capacity(cmdline_offset as usize + cmdline_payload.len());

    // perf_file_header.magic
    file.extend_from_slice(MAGIC);
    assert_eq!(file.len(), 8);

    // size (of perf_file_header itself)
    file.write_u64::<LittleEndian>(104).unwrap();
    // attr_size
    file.write_u64::<LittleEndian>(ATTR_SIZE).unwrap();
    // attrs section
    file.write_u64::<LittleEndian>(attrs_offset).unwrap();
    file.write_u64::<LittleEndian>(attrs_size).unwrap();
    // data section
    file.write_u64::<LittleEndian>(data_offset).unwrap();
    file.write_u64::<LittleEndian>(data_size).unwrap();
    // event_types section (legacy, empty)
    file.write_u64::<LittleEndian>(0).unwrap();
    file.write_u64::<LittleEndian>(0).unwrap();
    // adds_features[4] — 256-bit feature bitmap
    let mut features = [0u64; 4];
    features[(FEAT_CMDLINE / 64) as usize] |= 1u64 << (FEAT_CMDLINE % 64);
    for f in &features {
        file.write_u64::<LittleEndian>(*f).unwrap();
    }
    assert_eq!(file.len(), 104, "perf_file_header must be 104 bytes");

    // attrs section: one perf_event_attr (zeroed) + ids section pointer
    let mut attr = vec![0u8; ATTR_SIZE as usize];
    // Set attr.type = PERF_TYPE_SOFTWARE (1) at offset 0..4
    attr[0] = 1;
    // attr.size at offset 4..8 = ATTR_SIZE
    (&mut attr[4..8])
        .write_u32::<LittleEndian>(ATTR_SIZE as u32)
        .unwrap();
    // attr.config (offset 8..16) = PERF_COUNT_SW_DUMMY (9)
    (&mut attr[8..16]).write_u64::<LittleEndian>(9).unwrap();
    file.extend_from_slice(&attr);
    // ids: empty
    file.write_u64::<LittleEndian>(0).unwrap();
    file.write_u64::<LittleEndian>(0).unwrap();
    assert_eq!(file.len(), data_offset as usize);

    // (data section is empty — nothing to write)

    // Feature section descriptors: one per set feature bit, in bit order.
    file.write_u64::<LittleEndian>(cmdline_offset).unwrap();
    file.write_u64::<LittleEndian>(cmdline_size).unwrap();
    assert_eq!(file.len(), cmdline_offset as usize);

    // CMDLINE payload.
    file.extend_from_slice(&cmdline_payload);

    // Align to 8 bytes at end.
    pad_to(&mut file, 8);

    // Write atomically.
    let tmp = format!("{out}.tmp");
    {
        let mut f = std::fs::File::create(&tmp).expect("create tmp");
        f.write_all(&file).expect("write");
        f.sync_all().expect("sync");
    }
    std::fs::rename(&tmp, &out).expect("rename");
    eprintln!(
        "wrote {} ({} bytes, cmdline @ {:#x}+{})",
        out,
        file.len(),
        cmdline_offset,
        cmdline_size
    );
}
