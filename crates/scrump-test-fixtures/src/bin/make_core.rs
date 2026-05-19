//! Generate a deterministic, spec-compliant 64-bit little-endian ELF core
//! dump with planted tokens in:
//!   * `NT_PRPSINFO.pr_psargs`   (cmdline)
//!   * a single `PT_LOAD` region holding fake env-block bytes
//!
//! Usage: `make-core <output> <cmdline_planted_str> <env_planted_str>`
//!
//! The file passes `readelf -h` and `readelf -n` and round-trips through
//! `object` crate parsing. Just enough for the Phase 4 e2e gate to use as
//! a stand-in for a real `gcore` output (which we cannot run because
//! `kernel.yama.ptrace_scope=1` blocks attaching to descendants).

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use scrump_test_fixtures::round_up;

// ---- ELF / core dump constants ----------------------------------------------

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
const ELFOSABI_NONE: u8 = 0;
const ET_CORE: u16 = 4;
const EM_X86_64: u16 = 62;
const PT_NOTE: u32 = 4;
const PT_LOAD: u32 = 1;
const PF_R: u32 = 4;

const EHDR_SIZE: u16 = 64;
const PHDR_SIZE: u16 = 56;

const NT_PRPSINFO: u32 = 3;

// ---- helpers ----------------------------------------------------------------

fn note_blob(name: &str, ntype: u32, desc: &[u8]) -> Vec<u8> {
    // Elf64_Nhdr is { u32 namesz; u32 descsz; u32 type; }; followed by name
    // (NUL-terminated, padded to 4) and desc (padded to 4).
    let mut buf = Vec::new();
    let name_bytes = name.as_bytes();
    let namesz = name_bytes.len() as u32 + 1;
    let descsz = desc.len() as u32;
    buf.write_u32::<LittleEndian>(namesz).unwrap();
    buf.write_u32::<LittleEndian>(descsz).unwrap();
    buf.write_u32::<LittleEndian>(ntype).unwrap();
    buf.extend_from_slice(name_bytes);
    buf.push(0);
    let padded_name = round_up(namesz as usize, 4);
    buf.extend(std::iter::repeat(0u8).take(padded_name - namesz as usize));
    buf.extend_from_slice(desc);
    let padded_desc = round_up(descsz as usize, 4);
    buf.extend(std::iter::repeat(0u8).take(padded_desc - descsz as usize));
    buf
}

/// Build a minimal NT_PRPSINFO descriptor.
///
/// Layout (Linux elf_prpsinfo, 64-bit) — see `include/linux/elfcore.h`:
///   char  pr_state;       // 1
///   char  pr_sname;       // 1
///   char  pr_zomb;        // 1
///   char  pr_nice;        // 1
///   char  __pad[4];       // 4  (alignment for `long`)
///   long  pr_flag;        // 8
///   __u32 pr_uid;         // 4
///   __u32 pr_gid;         // 4
///   pid_t pr_pid;         // 4
///   pid_t pr_ppid;        // 4
///   pid_t pr_pgrp;        // 4
///   pid_t pr_sid;         // 4
///   char  pr_fname[16];   // 16
///   char  pr_psargs[80];  // 80
/// Total: 136 bytes (64-bit).
fn prpsinfo(cmdline: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(136);
    buf.extend_from_slice(&[b'R', b'R', 0, 0]); // pr_state='R', pr_sname='R', zomb=0, nice=0
    buf.extend_from_slice(&[0u8; 4]); // __pad[4] — alignment for long
    buf.write_i64::<LittleEndian>(0).unwrap(); // pr_flag
    buf.write_u32::<LittleEndian>(1000).unwrap(); // pr_uid
    buf.write_u32::<LittleEndian>(1000).unwrap(); // pr_gid
    buf.write_i32::<LittleEndian>(1).unwrap(); // pr_pid
    buf.write_i32::<LittleEndian>(0).unwrap(); // pr_ppid
    buf.write_i32::<LittleEndian>(1).unwrap(); // pr_pgrp
    buf.write_i32::<LittleEndian>(1).unwrap(); // pr_sid
    let fname = b"sleep\0\0\0\0\0\0\0\0\0\0\0";
    assert_eq!(fname.len(), 16);
    buf.extend_from_slice(fname);
    let mut psargs = [0u8; 80];
    let n = cmdline.len().min(79);
    psargs[..n].copy_from_slice(&cmdline.as_bytes()[..n]);
    buf.extend_from_slice(&psargs);
    assert_eq!(buf.len(), 136);
    buf
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (out, cmd_planted, env_planted) = match args.as_slice() {
        [a, b, c] => (a.clone(), b.clone(), c.clone()),
        _ => {
            eprintln!("usage: make-core <out> <cmdline_planted> <env_planted>");
            std::process::exit(2);
        }
    };

    // ---- build PT_NOTE payload ---------------------------------------------
    let note_payload = note_blob("CORE", NT_PRPSINFO, &prpsinfo(&cmd_planted));

    // ---- build PT_LOAD payload (fake env block) ----------------------------
    // We'll write a small page containing the env-shaped planted string,
    // surrounded by some other plausible env entries.
    let mut load_payload: Vec<u8> = Vec::new();
    load_payload.extend_from_slice(b"PATH=/usr/bin:/bin\0");
    load_payload.extend_from_slice(b"HOME=/home/user\0");
    load_payload.extend_from_slice(env_planted.as_bytes());
    load_payload.push(0);
    load_payload.extend_from_slice(b"LANG=C.UTF-8\0");
    // Pad to 0x1000 so the segment looks like a real page.
    let pad = round_up(load_payload.len(), 0x1000) - load_payload.len();
    load_payload.extend(std::iter::repeat(0u8).take(pad));

    // ---- layout ------------------------------------------------------------
    let e_phoff: u64 = EHDR_SIZE as u64;
    let phnum: u16 = 2; // PT_NOTE + PT_LOAD
    let phdrs_end = e_phoff + (PHDR_SIZE as u64) * (phnum as u64);

    let note_off = phdrs_end;
    let note_sz = note_payload.len() as u64;

    let load_off = note_off + note_sz;
    // page-align the file offset for PT_LOAD
    let load_off = round_up(load_off as usize, 0x1000) as u64;
    let load_sz = load_payload.len() as u64;

    // ---- ELF header --------------------------------------------------------
    let mut file = Vec::new();
    file.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    file.push(ELFCLASS64);
    file.push(ELFDATA2LSB);
    file.push(EV_CURRENT);
    file.push(ELFOSABI_NONE);
    file.extend_from_slice(&[0u8; 8]); // padding
    file.write_u16::<LittleEndian>(ET_CORE).unwrap();
    file.write_u16::<LittleEndian>(EM_X86_64).unwrap();
    file.write_u32::<LittleEndian>(EV_CURRENT as u32).unwrap();
    file.write_u64::<LittleEndian>(0).unwrap(); // e_entry
    file.write_u64::<LittleEndian>(e_phoff).unwrap();
    file.write_u64::<LittleEndian>(0).unwrap(); // e_shoff
    file.write_u32::<LittleEndian>(0).unwrap(); // e_flags
    file.write_u16::<LittleEndian>(EHDR_SIZE).unwrap();
    file.write_u16::<LittleEndian>(PHDR_SIZE).unwrap();
    file.write_u16::<LittleEndian>(phnum).unwrap();
    file.write_u16::<LittleEndian>(0).unwrap(); // e_shentsize
    file.write_u16::<LittleEndian>(0).unwrap(); // e_shnum
    file.write_u16::<LittleEndian>(0).unwrap(); // e_shstrndx
    assert_eq!(file.len(), EHDR_SIZE as usize);

    // ---- Program headers ---------------------------------------------------
    // PT_NOTE
    file.write_u32::<LittleEndian>(PT_NOTE).unwrap();
    file.write_u32::<LittleEndian>(PF_R).unwrap();
    file.write_u64::<LittleEndian>(note_off).unwrap(); // p_offset
    file.write_u64::<LittleEndian>(0).unwrap(); // p_vaddr
    file.write_u64::<LittleEndian>(0).unwrap(); // p_paddr
    file.write_u64::<LittleEndian>(note_sz).unwrap(); // p_filesz
    file.write_u64::<LittleEndian>(note_sz).unwrap(); // p_memsz
    file.write_u64::<LittleEndian>(4).unwrap(); // p_align

    // PT_LOAD
    file.write_u32::<LittleEndian>(PT_LOAD).unwrap();
    file.write_u32::<LittleEndian>(PF_R).unwrap();
    file.write_u64::<LittleEndian>(load_off).unwrap();
    file.write_u64::<LittleEndian>(0x7fff_0000_0000).unwrap(); // p_vaddr (synthetic stack)
    file.write_u64::<LittleEndian>(0).unwrap(); // p_paddr
    file.write_u64::<LittleEndian>(load_sz).unwrap();
    file.write_u64::<LittleEndian>(load_sz).unwrap();
    file.write_u64::<LittleEndian>(0x1000).unwrap();

    // ---- Note payload ------------------------------------------------------
    assert_eq!(file.len(), note_off as usize);
    file.extend_from_slice(&note_payload);

    // ---- Padding to page-align before PT_LOAD ------------------------------
    while (file.len() as u64) < load_off {
        file.push(0);
    }
    assert_eq!(file.len(), load_off as usize);

    file.extend_from_slice(&load_payload);

    // ---- Write atomically --------------------------------------------------
    let tmp = format!("{out}.tmp");
    {
        let mut f = std::fs::File::create(&tmp).expect("create tmp");
        f.write_all(&file).expect("write");
        f.sync_all().expect("sync");
    }
    std::fs::rename(&tmp, &out).expect("rename");
    eprintln!(
        "wrote {} ({} bytes; note @ {:#x}+{}, load @ {:#x}+{})",
        out,
        file.len(),
        note_off,
        note_sz,
        load_off,
        load_sz
    );
}
