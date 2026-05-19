//! ELF core dump handler.
//!
//! Supports 64-bit little-endian ELF (the dominant Linux server / desktop
//! shape). We parse program headers and emit two kinds of chunks:
//!
//! * one chunk per **note** inside each `PT_NOTE` segment — with a tighter
//!   origin label for `NT_PRPSINFO` (`Cmdline`, covering only the
//!   `pr_psargs[80]` field where the captured process's argv lives);
//! * one chunk per `PT_LOAD` segment — covering memory pages, including
//!   the stack pages that hold the environment block.
//!
//! Redaction is byte-level zero-fill at absolute file offsets; segment
//! sizes, note headers, and program-header offsets are never disturbed,
//! so `readelf -h`/`-n`/`-l` and `gdb`'s `core-file` loader continue to
//! parse the result without complaint.

use std::io::Read;
use std::path::Path;

use byteorder::{ByteOrder, LittleEndian};
use scrump_core::{
    apply_hits_in_place, Chunk, ChunkOrigin, Format, Handler, Hit, Result, ScrumpError,
};

// ---- ELF constants we care about -------------------------------------------

const ELFMAG: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_CORE: u16 = 4;
const PT_NOTE: u32 = 4;
const PT_LOAD: u32 = 1;
const NT_PRSTATUS: u32 = 1;
const NT_PRFPREG: u32 = 2;
const NT_PRPSINFO: u32 = 3;
const NT_TASKSTRUCT: u32 = 4;
const NT_AUXV: u32 = 6;
const NT_FILE: u32 = 0x46494c45;
const NT_SIGINFO: u32 = 0x53494749;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

// Layout of Linux elf_prpsinfo (64-bit) — see `include/linux/elfcore.h`.
const PRPSINFO_PSARGS_OFFSET: usize = 56;
const PRPSINFO_PSARGS_LEN: usize = 80;

// ---- types -----------------------------------------------------------------

#[derive(Clone, Debug)]
struct NoteRange {
    /// Absolute file offset of the note's `desc` payload.
    desc_offset: u64,
    /// Length of the `desc` payload (NOT including 4-byte padding).
    desc_len: u64,
    n_type: u32,
}

#[derive(Clone, Debug)]
struct LoadRange {
    file_offset: u64,
    file_size: u64,
}

pub struct CoreDump {
    bytes: Vec<u8>,
    notes: Vec<NoteRange>,
    loads: Vec<LoadRange>,
}

impl CoreDump {
    pub fn open_path(path: &Path) -> Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < EHDR_SIZE {
            return Err(ScrumpError::InvalidFile(
                "ELF core: shorter than 64-byte header".into(),
            ));
        }
        if &bytes[..4] != ELFMAG {
            return Err(ScrumpError::InvalidFile("ELF core: bad magic".into()));
        }
        if bytes[4] != ELFCLASS64 {
            return Err(ScrumpError::InvalidFile(
                "ELF core: only 64-bit class is supported".into(),
            ));
        }
        if bytes[5] != ELFDATA2LSB {
            return Err(ScrumpError::InvalidFile(
                "ELF core: only little-endian data is supported".into(),
            ));
        }
        let e_type = LittleEndian::read_u16(&bytes[16..18]);
        if e_type != ET_CORE {
            return Err(ScrumpError::InvalidFile(format!(
                "ELF: not a core dump (e_type={e_type})"
            )));
        }
        let e_phoff = LittleEndian::read_u64(&bytes[32..40]);
        let e_phentsize = LittleEndian::read_u16(&bytes[54..56]);
        let e_phnum = LittleEndian::read_u16(&bytes[56..58]);
        if e_phentsize as usize != PHDR_SIZE {
            return Err(ScrumpError::InvalidFile(format!(
                "ELF: unexpected phentsize {e_phentsize} (want {PHDR_SIZE})"
            )));
        }

        let mut notes = Vec::new();
        let mut loads = Vec::new();

        for i in 0..e_phnum as u64 {
            let off = e_phoff + i * PHDR_SIZE as u64;
            let end = off + PHDR_SIZE as u64;
            if (end as usize) > bytes.len() {
                return Err(ScrumpError::InvalidFile(format!(
                    "ELF: program header {i} runs past EOF"
                )));
            }
            let ph = &bytes[off as usize..end as usize];
            let p_type = LittleEndian::read_u32(&ph[0..4]);
            let p_offset = LittleEndian::read_u64(&ph[8..16]);
            let p_filesz = LittleEndian::read_u64(&ph[32..40]);

            if (p_offset + p_filesz) as usize > bytes.len() {
                return Err(ScrumpError::InvalidFile(format!(
                    "ELF: program header {i} segment ({p_offset}..{}) past EOF (len {})",
                    p_offset + p_filesz,
                    bytes.len()
                )));
            }

            match p_type {
                PT_NOTE => {
                    parse_notes(&bytes, p_offset, p_filesz, &mut notes)?;
                }
                PT_LOAD if p_filesz > 0 => {
                    loads.push(LoadRange {
                        file_offset: p_offset,
                        file_size: p_filesz,
                    });
                }
                _ => {}
            }
        }

        Ok(Self {
            bytes,
            notes,
            loads,
        })
    }
}

fn parse_notes(
    bytes: &[u8],
    seg_offset: u64,
    seg_size: u64,
    out: &mut Vec<NoteRange>,
) -> Result<()> {
    let mut cursor = seg_offset;
    let end = seg_offset + seg_size;
    while cursor + 12 <= end {
        let off = cursor as usize;
        let namesz = LittleEndian::read_u32(&bytes[off..off + 4]) as u64;
        let descsz = LittleEndian::read_u32(&bytes[off + 4..off + 8]) as u64;
        let ntype = LittleEndian::read_u32(&bytes[off + 8..off + 12]);
        cursor += 12;

        // name: namesz bytes, padded to 4
        let name_end = cursor + ((namesz + 3) & !3);
        if name_end > end {
            return Err(ScrumpError::InvalidFile(
                "ELF: malformed note (name past segment end)".into(),
            ));
        }
        cursor = name_end;

        // desc: descsz bytes, padded to 4
        let desc_off = cursor;
        let desc_end = cursor + ((descsz + 3) & !3);
        if desc_end > end {
            return Err(ScrumpError::InvalidFile(
                "ELF: malformed note (desc past segment end)".into(),
            ));
        }
        out.push(NoteRange {
            desc_offset: desc_off,
            desc_len: descsz,
            n_type: ntype,
        });
        cursor = desc_end;
    }
    Ok(())
}

fn note_label(n_type: u32) -> &'static str {
    match n_type {
        NT_PRSTATUS => "NT_PRSTATUS",
        NT_PRFPREG => "NT_PRFPREG",
        NT_PRPSINFO => "NT_PRPSINFO",
        NT_TASKSTRUCT => "NT_TASKSTRUCT",
        NT_AUXV => "NT_AUXV",
        NT_FILE => "NT_FILE",
        NT_SIGINFO => "NT_SIGINFO",
        _ => "NOTE",
    }
}

impl Format for CoreDump {
    fn name(&self) -> &'static str {
        "elf-core"
    }

    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a> {
        let mut out: Vec<Chunk<'a>> = Vec::new();

        for n in &self.notes {
            if n.desc_len == 0 {
                continue;
            }
            let from = n.desc_offset as usize;
            let to = from + n.desc_len as usize;
            if to > self.bytes.len() {
                continue;
            }
            // Tight chunk for NT_PRPSINFO.pr_psargs (cmdline).
            if n.n_type == NT_PRPSINFO
                && n.desc_len as usize >= PRPSINFO_PSARGS_OFFSET + PRPSINFO_PSARGS_LEN
            {
                let psargs_from = from + PRPSINFO_PSARGS_OFFSET;
                let psargs_to = psargs_from + PRPSINFO_PSARGS_LEN;
                out.push(Chunk {
                    bytes: &self.bytes[psargs_from..psargs_to],
                    offset: psargs_from as u64,
                    origin: ChunkOrigin::Cmdline,
                });
            }
            // Whole note `desc` as a labelled section (catches NT_FILE
            // paths, NT_AUXV strings, NT_SIGINFO content, etc.).
            out.push(Chunk {
                bytes: &self.bytes[from..to],
                offset: n.desc_offset,
                origin: ChunkOrigin::Section(format!("elf.note.{}", note_label(n.n_type))),
            });
        }

        for l in &self.loads {
            let from = l.file_offset as usize;
            let to = from + l.file_size as usize;
            if to > self.bytes.len() {
                continue;
            }
            out.push(Chunk {
                bytes: &self.bytes[from..to],
                offset: l.file_offset,
                origin: ChunkOrigin::Section("elf.load".into()),
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

// ---- handler registration --------------------------------------------------

fn detect(head: &[u8], _path: &Path) -> bool {
    head.len() >= 18
        && &head[..4] == ELFMAG
        && head[4] == ELFCLASS64
        && head[5] == ELFDATA2LSB
        && LittleEndian::read_u16(&head[16..18]) == ET_CORE
}

fn open_path(path: &Path) -> Result<Box<dyn Format>> {
    Ok(Box::new(CoreDump::open_path(path)?))
}

fn open_bytes(bytes: Vec<u8>, _hint: Option<&Path>) -> Result<Box<dyn Format>> {
    Ok(Box::new(CoreDump::from_bytes(bytes)?))
}

pub fn handler() -> Handler {
    Handler {
        name: "elf-core",
        detect,
        open_path,
        open_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_only_accepts_et_core_elf64_le() {
        // ET_EXEC (2) — not a core.
        let mut head = vec![0u8; 64];
        head[..4].copy_from_slice(ELFMAG);
        head[4] = ELFCLASS64;
        head[5] = ELFDATA2LSB;
        head[16] = 2;
        assert!(!detect(&head, Path::new("/x")));
        // ET_CORE
        head[16] = 4;
        assert!(detect(&head, Path::new("/x")));
        // Wrong class
        head[4] = 1;
        assert!(!detect(&head, Path::new("/x")));
    }
}
