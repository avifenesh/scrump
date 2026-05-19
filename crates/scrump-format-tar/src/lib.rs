//! tar / tar.gz / tar.zst / zip recursive container handler.
//!
//! On open, we fully decode the archive and dispatch every member through
//! an in-crate [`Dispatcher`] that knows about every leaf format. Each
//! member ends up as a `Box<dyn Format>` we can scan and redact. On
//! `to_bytes`, we re-archive in the original kind/compression with each
//! member replaced by its scrubbed bytes.
//!
//! Members' chunks are exposed in a *linearised* offset space: member 0's
//! chunks land in [0, len0), member 1's in [len0, len0+len1), and so on.
//! `apply` partitions hits by that range and forwards them to the correct
//! inner format with offsets translated back into member-local coordinates.
//! The on-disk archive byte ranges are never exposed — they would be wrong
//! after re-archiving anyway.

use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(test)]
use scrump_core::ChunkOrigin;
use scrump_core::{Chunk, Dispatcher, Format, Handler, Hit, Result, ScrumpError};

// ---- archive kind ----------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CompressionKind {
    None,
    Gzip,
    Zstd,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ArchiveKind {
    Tar(CompressionKind),
    Zip,
}

// ---- member ----------------------------------------------------------------

struct Member {
    /// Path inside the archive (e.g. "src/log.txt").
    name: String,
    /// Per-member format handler (could be perf / sqlite / passthrough / …).
    fmt: Box<dyn Format>,
    /// Span this member occupies in the linearised offset space.
    base: u64,
    span: u64,
    /// Posix metadata kept around so re-archiving preserves the file mode.
    mode: u32,
    mtime: u64,
    is_dir: bool,
}

// ---- archive ---------------------------------------------------------------

pub struct Archive {
    label: &'static str,
    kind: ArchiveKind,
    members: Vec<Member>,
}

impl Archive {
    pub fn open_path(path: &Path) -> Result<Self> {
        Self::open_path_labelled(path, "tar")
    }

    /// Variant used by `scrump-format-nsys` so the dispatcher reports
    /// `(format=nsys)` while the actual logic is identical.
    pub fn open_path_labelled(path: &Path, label: &'static str) -> Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        Self::from_bytes_labelled(bytes, Some(path), label)
    }

    pub fn from_bytes(bytes: Vec<u8>, hint: Option<&Path>) -> Result<Self> {
        Self::from_bytes_labelled(bytes, hint, "tar")
    }

    pub fn from_bytes_labelled(
        bytes: Vec<u8>,
        hint: Option<&Path>,
        label: &'static str,
    ) -> Result<Self> {
        let kind = sniff(&bytes, hint).ok_or_else(|| {
            ScrumpError::InvalidFile("not a tar / tar.gz / tar.zst / zip archive".into())
        })?;
        let raw = match kind {
            ArchiveKind::Tar(CompressionKind::None) => bytes,
            ArchiveKind::Tar(CompressionKind::Gzip) => {
                let mut d = flate2::read::GzDecoder::new(Cursor::new(&bytes));
                let mut out = Vec::new();
                d.read_to_end(&mut out)?;
                out
            }
            ArchiveKind::Tar(CompressionKind::Zstd) => zstd::decode_all(Cursor::new(&bytes))
                .map_err(|e| ScrumpError::InvalidFile(format!("zstd decode: {e}")))?,
            ArchiveKind::Zip => bytes, // zip handles its own decompression
        };

        let dispatcher = inner_dispatcher();

        let members = match kind {
            ArchiveKind::Tar(_) => extract_tar(&raw, &dispatcher)?,
            ArchiveKind::Zip => extract_zip(&raw, &dispatcher)?,
        };

        // Lay out the linearised offset space now that we know each
        // member's chunk length.
        let mut placed = Vec::with_capacity(members.len());
        let mut base = 0u64;
        for (name, fmt, mode, mtime, is_dir) in members {
            let span = if is_dir {
                0
            } else {
                fmt.to_bytes()?.len() as u64
            };
            placed.push(Member {
                name,
                fmt,
                base,
                span,
                mode,
                mtime,
                is_dir,
            });
            base += span;
        }

        Ok(Self {
            label,
            kind,
            members: placed,
        })
    }
}

impl Format for Archive {
    fn name(&self) -> &'static str {
        self.label
    }

    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a> {
        let mut out: Vec<Chunk<'a>> = Vec::new();
        for m in &self.members {
            if m.is_dir {
                continue;
            }
            let inner_name = m.fmt.name();
            for c in m.fmt.chunks() {
                out.push(Chunk {
                    bytes: c.bytes,
                    offset: m.base + c.offset,
                    origin: c.origin.nested_within(&m.name, inner_name),
                });
            }
        }
        Box::new(out.into_iter())
    }

    fn apply(&mut self, hits: &[Hit]) -> Result<()> {
        let mut buckets: Vec<Vec<Hit>> = (0..self.members.len()).map(|_| Vec::new()).collect();
        for h in hits {
            let mut placed = false;
            for (i, m) in self.members.iter().enumerate() {
                if m.span == 0 {
                    continue;
                }
                if h.offset >= m.base && (h.offset + h.len as u64) <= (m.base + m.span) {
                    let mut h2 = h.clone();
                    h2.offset -= m.base;
                    buckets[i].push(h2);
                    placed = true;
                    break;
                }
            }
            if !placed {
                return Err(ScrumpError::RedactionFailed(format!(
                    "tar: hit at offset {} (len {}) did not land in any member span",
                    h.offset, h.len
                )));
            }
        }
        for (i, bucket) in buckets.into_iter().enumerate() {
            if !bucket.is_empty() {
                self.members[i].fmt.apply(&bucket)?;
            }
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let inner_bytes: Vec<(String, Vec<u8>, u32, u64, bool)> = self
            .members
            .iter()
            .map(|m| -> Result<_> {
                let b = if m.is_dir {
                    Vec::new()
                } else {
                    m.fmt.to_bytes()?
                };
                Ok((m.name.clone(), b, m.mode, m.mtime, m.is_dir))
            })
            .collect::<Result<Vec<_>>>()?;

        let raw_archive = match self.kind {
            ArchiveKind::Tar(_) => repack_tar(&inner_bytes)?,
            ArchiveKind::Zip => repack_zip(&inner_bytes)?,
        };

        Ok(match self.kind {
            ArchiveKind::Tar(CompressionKind::None) | ArchiveKind::Zip => raw_archive,
            ArchiveKind::Tar(CompressionKind::Gzip) => {
                let mut out = Vec::new();
                {
                    let mut e =
                        flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
                    e.write_all(&raw_archive)?;
                    e.finish()?;
                }
                out
            }
            ArchiveKind::Tar(CompressionKind::Zstd) => {
                zstd::encode_all(Cursor::new(&raw_archive), 0)
                    .map_err(|e| ScrumpError::Other(format!("zstd encode: {e}")))?
            }
        })
    }
}

// ---- sniffing --------------------------------------------------------------

fn sniff(bytes: &[u8], hint: Option<&Path>) -> Option<ArchiveKind> {
    // ZIP magic (PK\x03\x04 or PK\x05\x06 for empty)
    if bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07)
    {
        return Some(ArchiveKind::Zip);
    }
    // Gzip magic
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        // Could be .tar.gz or any-gz-of-tar. Decompress headers and check.
        if let Ok(mut d) =
            std::panic::catch_unwind(|| flate2::read::GzDecoder::new(Cursor::new(bytes)))
        {
            let mut head = [0u8; 512];
            if d.read_exact(&mut head).is_ok() && looks_like_tar(&head) {
                return Some(ArchiveKind::Tar(CompressionKind::Gzip));
            }
            // Even if header read failed, treat as tar.gz when extension says so.
        }
        if let Some(p) = hint {
            let s = p.to_string_lossy();
            if s.ends_with(".tar.gz") || s.ends_with(".tgz") {
                return Some(ArchiveKind::Tar(CompressionKind::Gzip));
            }
        }
        return Some(ArchiveKind::Tar(CompressionKind::Gzip));
    }
    // Zstd magic
    if bytes.len() >= 4
        && bytes[0] == 0x28
        && bytes[1] == 0xb5
        && bytes[2] == 0x2f
        && bytes[3] == 0xfd
    {
        return Some(ArchiveKind::Tar(CompressionKind::Zstd));
    }
    // Plain tar: ustar magic at offset 257.
    if bytes.len() >= 512 && looks_like_tar(bytes) {
        return Some(ArchiveKind::Tar(CompressionKind::None));
    }
    // Extension fallback for plain tar with no recognisable magic.
    if let Some(p) = hint {
        let s = p.to_string_lossy();
        if s.ends_with(".tar") {
            return Some(ArchiveKind::Tar(CompressionKind::None));
        }
        if s.ends_with(".zip") {
            return Some(ArchiveKind::Zip);
        }
    }
    None
}

fn looks_like_tar(head: &[u8]) -> bool {
    head.len() >= 265 && &head[257..262] == b"ustar"
}

// ---- inner dispatcher ------------------------------------------------------

/// Build a `Dispatcher` capable of opening every leaf format we know about,
/// with passthrough as the fallback. Does **not** include the tar handler
/// itself (so nested tars get scanned as raw bytes — bounded recursion).
fn inner_dispatcher() -> Dispatcher {
    let mut d = Dispatcher::new();
    d.register(scrump_format_perf::handler());
    d.register(scrump_format_sqlite::handler());
    d.register(scrump_format_core::handler());
    d.register(scrump_format_hprof::handler());
    d.register(scrump_format_jfr::handler());
    d.set_fallback(scrump_format_passthrough::handler());
    d
}

// ---- tar extraction --------------------------------------------------------

/// `(name, format, mode, mtime, is_dir)`. Used both during extraction
/// and re-packaging.
type ExtractedMember = (String, Box<dyn Format>, u32, u64, bool);
type RepackMember = (String, Vec<u8>, u32, u64, bool);

fn extract_tar(raw: &[u8], dispatcher: &Dispatcher) -> Result<Vec<ExtractedMember>> {
    let mut out = Vec::new();
    let mut ar = tar::Archive::new(Cursor::new(raw));
    for entry in ar.entries().map_err(io_err)? {
        let mut entry = entry.map_err(io_err)?;
        let name = entry.path().map_err(io_err)?.to_string_lossy().into_owned();
        let mode = entry.header().mode().unwrap_or(0o644);
        let mtime = entry.header().mtime().unwrap_or(0);
        let is_dir = entry.header().entry_type().is_dir();
        if is_dir {
            let pt = scrump_format_passthrough::Passthrough::open_bytes(Vec::new(), None)?;
            out.push((name, Box::new(pt) as Box<dyn Format>, mode, mtime, true));
            continue;
        }
        let mut body = Vec::new();
        entry.read_to_end(&mut body).map_err(io_err)?;
        let fmt = dispatcher.open_bytes(body, Some(Path::new(&name)))?;
        out.push((name, fmt, mode, mtime, false));
    }
    Ok(out)
}

fn repack_tar(members: &[RepackMember]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut buf);
        // Long names go through the GNU header automatically.
        for (name, body, mode, mtime, is_dir) in members {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(if *is_dir { 0 } else { body.len() as u64 });
            hdr.set_mode(*mode);
            hdr.set_mtime(*mtime);
            hdr.set_uid(0);
            hdr.set_gid(0);
            if *is_dir {
                hdr.set_entry_type(tar::EntryType::Directory);
            } else {
                hdr.set_entry_type(tar::EntryType::Regular);
            }
            b.append_data(&mut hdr, name, body.as_slice())
                .map_err(io_err)?;
        }
        b.finish().map_err(io_err)?;
    }
    Ok(buf)
}

// ---- zip extraction --------------------------------------------------------

fn extract_zip(raw: &[u8], dispatcher: &Dispatcher) -> Result<Vec<ExtractedMember>> {
    let mut zr = zip::ZipArchive::new(Cursor::new(raw))
        .map_err(|e| ScrumpError::InvalidFile(format!("zip open: {e}")))?;
    let mut out = Vec::new();
    for i in 0..zr.len() {
        let mut entry = zr
            .by_index(i)
            .map_err(|e| ScrumpError::InvalidFile(format!("zip entry {i}: {e}")))?;
        let name = entry.name().to_owned();
        let mode = entry.unix_mode().unwrap_or(0o644);
        let mtime = 0u64; // zip stores mtime differently; ignore for now
        let is_dir = entry.is_dir();
        if is_dir {
            let pt = scrump_format_passthrough::Passthrough::open_bytes(Vec::new(), None)?;
            out.push((name, Box::new(pt) as Box<dyn Format>, mode, mtime, true));
            continue;
        }
        let mut body = Vec::new();
        entry.read_to_end(&mut body)?;
        let fmt = dispatcher.open_bytes(body, Some(Path::new(&name)))?;
        out.push((name, fmt, mode, mtime, false));
    }
    Ok(out)
}

fn repack_zip(members: &[RepackMember]) -> Result<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut zw = zip::ZipWriter::new(cursor);
    for (name, body, mode, _mtime, is_dir) in members {
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(*mode);
        if *is_dir {
            zw.add_directory(name, opts)
                .map_err(|e| ScrumpError::Other(format!("zip dir: {e}")))?;
            continue;
        }
        zw.start_file(name, opts)
            .map_err(|e| ScrumpError::Other(format!("zip start_file: {e}")))?;
        zw.write_all(body)?;
    }
    let cur = zw
        .finish()
        .map_err(|e| ScrumpError::Other(format!("zip finish: {e}")))?;
    Ok(cur.into_inner())
}

// ---- handler ---------------------------------------------------------------

fn detect(head: &[u8], path: &Path) -> bool {
    sniff(head, Some(path)).is_some()
}

fn open_path(path: &Path) -> Result<Box<dyn Format>> {
    Ok(Box::new(Archive::open_path(path)?))
}

fn open_bytes(bytes: Vec<u8>, hint: Option<&Path>) -> Result<Box<dyn Format>> {
    Ok(Box::new(Archive::from_bytes(bytes, hint)?))
}

pub fn handler() -> Handler {
    Handler {
        name: "tar",
        detect,
        open_path,
        open_bytes,
    }
}

// ---- helpers ---------------------------------------------------------------

fn io_err(e: std::io::Error) -> ScrumpError {
    ScrumpError::Io(e)
}

// Suppress unused-PathBuf warning if linker eats the symbol.
#[allow(dead_code)]
fn _silence_unused(_p: PathBuf) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_chunk_a_tar_in_memory() {
        // Build a tar with one member by hand.
        let body = b"export GH_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(body.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_mtime(0);
            hdr.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut hdr, "log.txt", body.as_slice()).unwrap();
            b.finish().unwrap();
        }
        let ar = Archive::from_bytes(tar_bytes, None).unwrap();
        let chunks: Vec<_> = ar.chunks().collect();
        // 1 member -> 1 chunk (from passthrough).
        assert_eq!(chunks.len(), 1);
        // The chunk's bytes are the member body.
        assert_eq!(chunks[0].bytes, body);
        // Origin says NestedMember.
        assert!(
            matches!(&chunks[0].origin, ChunkOrigin::NestedMember { path, format }
                     if path == "log.txt" && format == "passthrough")
        );
    }

    #[test]
    fn detect_recognises_gzip_and_plain_tar() {
        let mut plain = vec![0u8; 512];
        plain[257..262].copy_from_slice(b"ustar");
        assert!(detect(&plain, Path::new("/x/a.tar")));
        assert!(detect(&[0x1f, 0x8b, 0, 0], Path::new("/x/a.tar.gz")));
        assert!(detect(&[0x50, 0x4b, 0x03, 0x04], Path::new("/x/a.zip")));
        assert!(!detect(b"hello", Path::new("/x/a.txt")));
    }
}
