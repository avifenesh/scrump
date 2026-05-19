//! NVIDIA Nsight Systems (`.nsys-rep`) / Nsight Compute (`.ncu-rep`) handler.
//!
//! These artifacts are tar archives (sometimes gzip-wrapped) carrying:
//!   * a SQLite database (the canonical metadata + timeline store);
//!   * a handful of supplementary files (manifests, descriptors, configs).
//!
//! We delegate the heavy lifting to [`scrump_format_tar::Archive`], which
//! already knows how to walk members, dispatch each to its native format
//! (so the inner SQLite member gets format-aware UPDATE-and-VACUUM
//! redaction), and re-archive. The only differences from the bare tar
//! handler are:
//!
//!   * detection — we match on `.nsys-rep` / `.ncu-rep` extension so the
//!     dispatcher reports `(format=nsys)` rather than `(format=tar)`;
//!   * the resulting [`Format::name`] returns `"nsys"`.

use std::path::Path;

use scrump_core::{Format, Handler, Result};
use scrump_format_tar::Archive;

fn ext_matches(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.ends_with(".nsys-rep") || s.ends_with(".ncu-rep")
}

fn detect(_head: &[u8], path: &Path) -> bool {
    ext_matches(path)
}

fn open_path(path: &Path) -> Result<Box<dyn Format>> {
    Ok(Box::new(Archive::open_path_labelled(path, "nsys")?))
}

fn open_bytes(bytes: Vec<u8>, hint: Option<&Path>) -> Result<Box<dyn Format>> {
    Ok(Box::new(Archive::from_bytes_labelled(bytes, hint, "nsys")?))
}

pub fn handler() -> Handler {
    Handler {
        name: "nsys",
        detect,
        open_path,
        open_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_matches_extensions() {
        assert!(detect(b"", Path::new("/x/y.nsys-rep")));
        assert!(detect(b"", Path::new("foo.ncu-rep")));
        assert!(!detect(b"", Path::new("/x/y.tar")));
    }
}
