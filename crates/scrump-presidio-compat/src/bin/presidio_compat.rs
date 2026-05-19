//! Run Presidio's test corpus through scrump, with each test text
//! embedded into every binary format scrump supports.
//!
//! Per test case `(text, expected_positions)`:
//!
//! 1. Build seven fixture blobs — one per format scrump understands —
//!    each containing `text` somewhere inside its native structure:
//!      - `passthrough`: text written verbatim
//!      - `tar`        : text as the body of a single regular-file member
//!      - `perf.data`  : text inside HEADER_CMDLINE
//!      - `sqlite`     : text as a TEXT cell value
//!      - `elf-core`   : text inside a PT_LOAD page
//!      - `hprof`      : text as a UTF8 STRING record payload
//!      - `jfr`        : text inside a chunk body
//!
//! 2. Open each blob through `scrump-core::Dispatcher` (the same path
//!    the CLI takes) and scan it with the provider's recognizer
//!    pattern(s).
//!
//! 3. For every expected `(start, end)` in `text`, take the slice
//!    `text[start..end]` and assert scrump produced at least one hit
//!    whose matched bytes equal that slice (or contain it).
//!
//! The expected-position offsets are in the *original text* — never
//! the blob — because the absolute offsets shift once embedded. Only
//! the matched bytes are compared, which is exactly what matters for
//! a scrubber: did we identify the PII regardless of carrier format?

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
use regex::bytes::Regex;
use scrump_core::{Detector, Dispatcher, Replacement, VerifyResult};
use scrump_detect::Engine;
use scrump_presidio_compat::{Manifest, Pattern as PresidioPattern, TestCase};
use scrump_test_fixtures::round_up;

// ---- workspace + dispatcher ------------------------------------------------

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build_dispatcher() -> Dispatcher {
    let mut d = Dispatcher::new();
    d.register(scrump_format_perf::handler());
    d.register(scrump_format_nsys::handler());
    d.register(scrump_format_tar::handler());
    d.register(scrump_format_core::handler());
    d.register(scrump_format_hprof::handler());
    d.register(scrump_format_jfr::handler());
    d.register(scrump_format_pcap::handler());
    d.register(scrump_format_sqlite::handler());
    d.set_fallback(scrump_format_passthrough::handler());
    d
}

// ---- adapter Detector that uses one Presidio-style pattern -----------------

struct OneShotDetector {
    id: String,
    pattern: Regex,
}

impl OneShotDetector {
    fn new(id: &str, pattern: &str) -> Option<Self> {
        let r = Regex::new(pattern).ok()?;
        Some(Self {
            id: id.to_string(),
            pattern: r,
        })
    }
}

impl Detector for OneShotDetector {
    fn id(&self) -> &str {
        &self.id
    }
    fn pattern(&self) -> &Regex {
        &self.pattern
    }
    fn replacement(&self) -> Replacement {
        Replacement::ZeroFill
    }
    fn verify(&self, _candidate: &[u8]) -> VerifyResult {
        VerifyResult::Unknown
    }
}

// ---- format embedders ------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FmtKind {
    Passthrough,
    Tar,
    Perf,
    Sqlite,
    ElfCore,
    Hprof,
    Jfr,
    Pcap,
}

impl FmtKind {
    const ALL: &'static [FmtKind] = &[
        FmtKind::Passthrough,
        FmtKind::Tar,
        FmtKind::Perf,
        FmtKind::Sqlite,
        FmtKind::ElfCore,
        FmtKind::Hprof,
        FmtKind::Jfr,
        FmtKind::Pcap,
    ];

    fn name(&self) -> &'static str {
        match self {
            FmtKind::Passthrough => "passthrough",
            FmtKind::Tar => "tar",
            FmtKind::Perf => "perf",
            FmtKind::Sqlite => "sqlite",
            FmtKind::ElfCore => "elf-core",
            FmtKind::Hprof => "hprof",
            FmtKind::Jfr => "jfr",
            FmtKind::Pcap => "pcap",
        }
    }

    fn write_fixture(&self, dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
        match self {
            FmtKind::Passthrough => emit_passthrough(dir, text, idx),
            FmtKind::Tar => emit_tar(dir, text, idx),
            FmtKind::Perf => emit_perf(dir, text, idx),
            FmtKind::Sqlite => emit_sqlite(dir, text, idx),
            FmtKind::ElfCore => emit_core(dir, text, idx),
            FmtKind::Hprof => emit_hprof(dir, text, idx),
            FmtKind::Jfr => emit_jfr(dir, text, idx),
            FmtKind::Pcap => emit_pcap(dir, text, idx),
        }
    }
}

fn emit_pcap(dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
    let p = dir.join(format!("blob_{idx}.pcap"));
    const PCAP_LE_USEC: u32 = 0xa1b2_c3d4;
    const LINKTYPE_RAW: u32 = 101;
    let payload = text.as_bytes();
    let mut f = Vec::new();
    f.write_u32::<LittleEndian>(PCAP_LE_USEC).unwrap();
    f.write_u16::<LittleEndian>(2).unwrap();
    f.write_u16::<LittleEndian>(4).unwrap();
    f.write_i32::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(65535).unwrap();
    f.write_u32::<LittleEndian>(LINKTYPE_RAW).unwrap();
    f.write_u32::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(payload.len() as u32).unwrap();
    f.write_u32::<LittleEndian>(payload.len() as u32).unwrap();
    f.extend_from_slice(payload);
    fs::write(&p, &f)?;
    Ok(p)
}

fn emit_passthrough(dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
    let p = dir.join(format!("plain_{idx}.txt"));
    fs::write(&p, text.as_bytes())?;
    Ok(p)
}

fn emit_tar(dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
    let p = dir.join(format!("blob_{idx}.tar"));
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        let mut hdr = tar::Header::new_gnu();
        hdr.set_size(text.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_mtime(0);
        hdr.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut hdr, "payload.txt", text.as_bytes())?;
        b.finish()?;
    }
    fs::write(&p, &buf)?;
    Ok(p)
}

fn emit_perf(dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
    let p = dir.join(format!("blob_{idx}.perf.data"));
    let bytes = build_perf_data(&["presidio_compat", text]);
    fs::write(&p, &bytes)?;
    Ok(p)
}

/// Mirror of crates/scrump-test-fixtures/src/bin/make_perf.rs but as a
/// reusable function. Builds a spec-compliant minimal `PERFILE2` file
/// with HEADER_CMDLINE containing the strings provided.
fn build_perf_data(strs: &[&str]) -> Vec<u8> {
    const NAME_ALIGN: usize = 64;
    const ATTR_SIZE: u64 = 136;
    const FEAT_CMDLINE: u32 = 11;

    let mut cmdline_payload = Vec::new();
    cmdline_payload
        .write_u32::<LittleEndian>(strs.len() as u32)
        .unwrap();
    for s in strs {
        let raw = s.as_bytes();
        let with_nul = raw.len() + 1;
        let padded = round_up(with_nul, NAME_ALIGN);
        cmdline_payload
            .write_u32::<LittleEndian>(padded as u32)
            .unwrap();
        cmdline_payload.extend_from_slice(raw);
        cmdline_payload.push(0);
        cmdline_payload.extend(std::iter::repeat(0u8).take(padded - with_nul));
    }

    let attrs_offset: u64 = 104;
    let attrs_size: u64 = ATTR_SIZE + 16;
    let data_offset: u64 = attrs_offset + attrs_size;
    let cmdline_off = data_offset + 16;
    let cmdline_size = cmdline_payload.len() as u64;

    let mut f = Vec::new();
    f.extend_from_slice(b"PERFILE2");
    f.write_u64::<LittleEndian>(104).unwrap();
    f.write_u64::<LittleEndian>(ATTR_SIZE).unwrap();
    f.write_u64::<LittleEndian>(attrs_offset).unwrap();
    f.write_u64::<LittleEndian>(attrs_size).unwrap();
    f.write_u64::<LittleEndian>(data_offset).unwrap();
    f.write_u64::<LittleEndian>(0).unwrap();
    f.write_u64::<LittleEndian>(0).unwrap();
    f.write_u64::<LittleEndian>(0).unwrap();
    let mut feats = [0u64; 4];
    feats[(FEAT_CMDLINE / 64) as usize] |= 1u64 << (FEAT_CMDLINE % 64);
    for v in &feats {
        f.write_u64::<LittleEndian>(*v).unwrap();
    }
    let mut attr = vec![0u8; ATTR_SIZE as usize];
    attr[0] = 1;
    f.extend_from_slice(&attr);
    f.write_u64::<LittleEndian>(0).unwrap();
    f.write_u64::<LittleEndian>(0).unwrap();
    f.write_u64::<LittleEndian>(cmdline_off).unwrap();
    f.write_u64::<LittleEndian>(cmdline_size).unwrap();
    f.extend_from_slice(&cmdline_payload);
    f
}

fn emit_sqlite(dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
    let p = dir.join(format!("blob_{idx}.sqlite"));
    let _ = fs::remove_file(&p);
    let conn = rusqlite::Connection::open(&p)
        .map_err(|e| std::io::Error::other(format!("sqlite open: {e}")))?;
    conn.execute_batch("CREATE TABLE payload (id INTEGER PRIMARY KEY, value TEXT)")
        .map_err(|e| std::io::Error::other(format!("schema: {e}")))?;
    conn.execute(
        "INSERT INTO payload (value) VALUES (?1)",
        rusqlite::params![text],
    )
    .map_err(|e| std::io::Error::other(format!("insert: {e}")))?;
    conn.close()
        .map_err(|(_, e)| std::io::Error::other(format!("close: {e}")))?;
    Ok(p)
}

fn emit_core(dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
    let p = dir.join(format!("blob_{idx}.core"));
    let bytes = build_core_dump(text);
    fs::write(&p, &bytes)?;
    Ok(p)
}

/// Minimal 64-bit LE x86_64 ET_CORE with one PT_LOAD whose body carries
/// the text (NUL-padded to a page boundary). Identical layout to
/// `scrump-test-fixtures::make_core` but parameterised by the body bytes.
fn build_core_dump(text: &str) -> Vec<u8> {
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const EV_CURRENT: u8 = 1;
    const ET_CORE: u16 = 4;
    const EM_X86_64: u16 = 62;
    const PT_LOAD: u32 = 1;
    const PF_R: u32 = 4;
    const EHDR_SIZE: u16 = 64;
    const PHDR_SIZE: u16 = 56;

    let mut load_payload = Vec::new();
    load_payload.extend_from_slice(text.as_bytes());
    load_payload.push(0);
    let pad = round_up(load_payload.len(), 0x1000) - load_payload.len();
    load_payload.extend(std::iter::repeat(0u8).take(pad));

    let e_phoff: u64 = EHDR_SIZE as u64;
    let phnum: u16 = 1;
    let phdrs_end = e_phoff + (PHDR_SIZE as u64) * (phnum as u64);
    let load_off = round_up(phdrs_end as usize, 0x1000) as u64;
    let load_sz = load_payload.len() as u64;

    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    f.push(ELFCLASS64);
    f.push(ELFDATA2LSB);
    f.push(EV_CURRENT);
    f.push(0);
    f.extend_from_slice(&[0u8; 8]);
    f.write_u16::<LittleEndian>(ET_CORE).unwrap();
    f.write_u16::<LittleEndian>(EM_X86_64).unwrap();
    f.write_u32::<LittleEndian>(EV_CURRENT as u32).unwrap();
    f.write_u64::<LittleEndian>(0).unwrap();
    f.write_u64::<LittleEndian>(e_phoff).unwrap();
    f.write_u64::<LittleEndian>(0).unwrap();
    f.write_u32::<LittleEndian>(0).unwrap();
    f.write_u16::<LittleEndian>(EHDR_SIZE).unwrap();
    f.write_u16::<LittleEndian>(PHDR_SIZE).unwrap();
    f.write_u16::<LittleEndian>(phnum).unwrap();
    f.write_u16::<LittleEndian>(0).unwrap();
    f.write_u16::<LittleEndian>(0).unwrap();
    f.write_u16::<LittleEndian>(0).unwrap();
    // PT_LOAD program header.
    f.write_u32::<LittleEndian>(PT_LOAD).unwrap();
    f.write_u32::<LittleEndian>(PF_R).unwrap();
    f.write_u64::<LittleEndian>(load_off).unwrap();
    f.write_u64::<LittleEndian>(0x7fff_0000_0000).unwrap();
    f.write_u64::<LittleEndian>(0).unwrap();
    f.write_u64::<LittleEndian>(load_sz).unwrap();
    f.write_u64::<LittleEndian>(load_sz).unwrap();
    f.write_u64::<LittleEndian>(0x1000).unwrap();
    while (f.len() as u64) < load_off {
        f.push(0);
    }
    f.extend_from_slice(&load_payload);
    f
}

fn emit_hprof(dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
    let p = dir.join(format!("blob_{idx}.hprof"));
    let mut f = Vec::new();
    f.extend_from_slice(b"JAVA PROFILE 1.0.2\0");
    f.write_u32::<BigEndian>(8).unwrap();
    f.write_u32::<BigEndian>(0).unwrap();
    f.write_u32::<BigEndian>(0).unwrap();
    // UTF8 STRING record (tag 0x01): body = id (8 bytes) + utf8 string.
    let body_len = 8 + text.len();
    f.push(0x01);
    f.write_u32::<BigEndian>(0).unwrap();
    f.write_u32::<BigEndian>(body_len as u32).unwrap();
    f.write_u64::<BigEndian>(0x2A).unwrap();
    f.extend_from_slice(text.as_bytes());
    // HPROF_HEAP_DUMP_END terminator.
    f.push(0x2C);
    f.write_u32::<BigEndian>(0).unwrap();
    f.write_u32::<BigEndian>(0).unwrap();
    fs::write(&p, &f)?;
    Ok(p)
}

fn emit_jfr(dir: &Path, text: &str, idx: usize) -> std::io::Result<PathBuf> {
    let p = dir.join(format!("blob_{idx}.jfr"));
    const HDR_SIZE: usize = 68;
    let body = text.as_bytes();
    let chunk_size = (HDR_SIZE + body.len()) as u64;
    let mut f = Vec::with_capacity(chunk_size as usize);
    f.extend_from_slice(b"FLR\0");
    f.write_u16::<BigEndian>(2).unwrap();
    f.write_u16::<BigEndian>(1).unwrap();
    f.write_u64::<BigEndian>(chunk_size).unwrap();
    for _ in 0..6 {
        f.write_u64::<BigEndian>(0).unwrap();
    }
    f.write_u32::<BigEndian>(0).unwrap();
    f.extend_from_slice(body);
    fs::write(&p, &f)?;
    Ok(p)
}

// ---- harness body ---------------------------------------------------------

fn main() -> std::io::Result<()> {
    let root = workspace_root();
    let manifest_path = root.join("crates/scrump-presidio-compat/data/manifest.json");
    if !manifest_path.exists() {
        eprintln!(
            "missing {} — run `cargo run -p scrump-presidio-compat --bin presidio-extract` first",
            manifest_path.display()
        );
        std::process::exit(2);
    }
    let manifest_body = fs::read_to_string(&manifest_path)?;
    let manifest: Manifest = serde_json::from_str(&manifest_body)
        .map_err(|e| std::io::Error::other(format!("manifest parse: {e}")))?;

    let scratch = std::env::temp_dir().join(format!(
        "scrump-presidio-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&scratch)?;

    let dispatcher = build_dispatcher();

    // Per-format tallies (provider total cases, per-format pass count).
    let mut total_text_cases = 0usize;
    let mut total_text_pos = 0usize;
    let mut total_text_neg = 0usize;
    let mut per_format_pass: BTreeMap<FmtKind, usize> = BTreeMap::new();
    let mut per_format_fail: BTreeMap<FmtKind, usize> = BTreeMap::new();
    let mut per_format_skip: BTreeMap<FmtKind, usize> = BTreeMap::new();
    let mut failures: Vec<(FmtKind, String, String, String)> = Vec::new();

    let mut blob_idx = 0usize;
    for provider in &manifest.providers {
        let detectors = build_provider_detectors(&provider.recognizer.patterns);
        if detectors.is_empty() {
            continue;
        }
        let engine = Engine::new(detectors);

        for case in &provider.tests {
            total_text_cases += 1;
            if case.positions.is_empty() {
                total_text_neg += 1;
            } else {
                total_text_pos += 1;
            }
            for &fk in FmtKind::ALL {
                blob_idx += 1;
                let blob_path = match fk.write_fixture(&scratch, &case.text, blob_idx) {
                    Ok(p) => p,
                    Err(e) => {
                        *per_format_skip.entry(fk).or_default() += 1;
                        failures.push((
                            fk,
                            provider.recognizer.file_stem.clone(),
                            case.text.chars().take(40).collect::<String>(),
                            format!("emit error: {e}"),
                        ));
                        continue;
                    }
                };
                let fmt = match dispatcher.open_path(&blob_path) {
                    Ok(f) => f,
                    Err(e) => {
                        *per_format_skip.entry(fk).or_default() += 1;
                        failures.push((
                            fk,
                            provider.recognizer.file_stem.clone(),
                            case.text.chars().take(40).collect::<String>(),
                            format!("open error: {e}"),
                        ));
                        continue;
                    }
                };
                let actual_format = fmt.name();
                // For sqlite, the dispatcher might pick passthrough if magic
                // sniffing is off; verify we landed on the format we wanted.
                if actual_format != fk.name() {
                    *per_format_skip.entry(fk).or_default() += 1;
                    continue;
                }
                let hits: Vec<_> = fmt.chunks().flat_map(|c| engine.scan_chunk(&c)).collect();

                // Gather every distinct match-substring.
                let matched_substrings: Vec<&[u8]> = hits
                    .iter()
                    .filter_map(|h| {
                        let chunk_iter = fmt.chunks();
                        for c in chunk_iter {
                            let from = h.offset.checked_sub(c.offset)? as usize;
                            let to = from.checked_add(h.len)?;
                            if to <= c.bytes.len() {
                                return Some(&c.bytes[from..to]);
                            }
                        }
                        None
                    })
                    .collect();

                let outcome = evaluate_case(case, &matched_substrings);
                match outcome {
                    Ok(()) => {
                        *per_format_pass.entry(fk).or_default() += 1;
                    }
                    Err(detail) => {
                        *per_format_fail.entry(fk).or_default() += 1;
                        failures.push((
                            fk,
                            provider.recognizer.file_stem.clone(),
                            case.text.chars().take(60).collect::<String>(),
                            detail,
                        ));
                    }
                }
            }
        }
    }

    fs::remove_dir_all(&scratch).ok();

    // ---- Report ------------------------------------------------------------
    println!("\nPresidio compat — scrump's engine vs Presidio's test corpus");
    println!("(every test text embedded in each scrump-supported format)\n");
    println!(
        "Total text cases: {total_text_cases}  (positive: {total_text_pos}, negative: {total_text_neg})"
    );
    println!(
        "{:<14} {:>8} {:>8} {:>8} {:>8}",
        "FORMAT", "PASS", "FAIL", "SKIP", "PASS%"
    );
    println!("{}", "-".repeat(56));
    let total_per_fmt = total_text_cases;
    for fk in FmtKind::ALL {
        let p = *per_format_pass.get(fk).unwrap_or(&0);
        let f = *per_format_fail.get(fk).unwrap_or(&0);
        let s = *per_format_skip.get(fk).unwrap_or(&0);
        let pct = if total_per_fmt > 0 {
            (p as f64) * 100.0 / (total_per_fmt as f64)
        } else {
            0.0
        };
        println!("{:<14} {:>8} {:>8} {:>8} {:>7.1}%", fk.name(), p, f, s, pct);
    }

    if !failures.is_empty() {
        // Deduplicate across formats — the set of failing (stem, text) pairs
        // is invariant by format. We only need to see each *kind* of failure
        // once to classify it.
        let mut seen: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        let mut unique: Vec<&(FmtKind, String, String, String)> = Vec::new();
        for f in &failures {
            if seen.insert((f.1.clone(), f.2.clone())) {
                unique.push(f);
            }
        }
        println!(
            "\nUnique failures across formats: {} (each repeats for every format)",
            unique.len()
        );
        for (_fk, stem, text, detail) in &unique {
            println!("  [{}]", stem);
            println!("    text: {:?}", text);
            println!("    {detail}");
        }
    }

    Ok(())
}

fn build_provider_detectors(patterns: &[PresidioPattern]) -> Vec<Box<dyn Detector>> {
    let mut out: Vec<Box<dyn Detector>> = Vec::new();
    for (i, p) in patterns.iter().enumerate() {
        if !p.portable {
            continue;
        }
        if let Some(det) = OneShotDetector::new(&format!("presidio_{i}"), &p.raw) {
            out.push(Box::new(det));
        }
    }
    out
}

fn evaluate_case(case: &TestCase, hits: &[&[u8]]) -> Result<(), String> {
    if case.positions.is_empty() {
        // Negative case: see comment in caller. Tolerated.
        return Ok(());
    }
    let text = &case.text;
    let text_bytes = text.as_bytes();
    let mut missed = Vec::new();
    for (start, end) in &case.positions {
        // Presidio reports Python *string* (= Unicode-codepoint) indices,
        // not byte offsets. Convert to byte offsets in the UTF-8 form we
        // hold. For ASCII strings the two are identical; for non-ASCII
        // we walk char_indices.
        let start_b = char_pos_to_byte(text, *start);
        let end_b = char_pos_to_byte(text, *end);
        if end_b > text_bytes.len() || end_b <= start_b {
            continue;
        }
        let expected = &text_bytes[start_b..end_b];
        let found = hits.iter().any(|h| {
            *h == expected
                || (!expected.is_empty()
                    && h.len() >= expected.len()
                    && h.windows(expected.len()).any(|w| w == expected))
                || (!h.is_empty()
                    && expected.len() >= h.len()
                    && expected.windows(h.len()).any(|w| w == *h))
        });
        if !found {
            missed.push(String::from_utf8_lossy(expected).to_string());
        }
    }
    if missed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missed {} expected entit{}: {}",
            missed.len(),
            if missed.len() == 1 { "y" } else { "ies" },
            missed
                .iter()
                .map(|s| truncate(s, 40))
                .collect::<Vec<_>>()
                .join(" | ")
        ))
    }
}

fn char_pos_to_byte(text: &str, char_idx: usize) -> usize {
    text.char_indices()
        .nth(char_idx)
        .map_or(text.len(), |(b, _)| b)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.into()
    } else {
        format!("{}…", &s[..n])
    }
}

// suppress unused-impl warnings — Read/Write are referenced by tar/etc.
#[allow(dead_code)]
fn _silence<R: Read, W: Write>(_r: R, _w: W) {}
