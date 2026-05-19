//! Catalogue every TruffleHog `*_integration_test.go` and report which
//! ones could even *theoretically* be run from this checkout, plus what
//! credentials each requires.
//!
//! Three buckets:
//!
//!   - `gcp_secret`: uses `common.GetSecret(ctx, "trufflehog-testing", "detectorsN")`,
//!     which pulls from TruffleHog's private GCP Secret Manager project.
//!     **Unrunnable outside TruffleHog's CI** — these tests are gated on a
//!     specific GCP project, not on env vars.
//!   - `env_var`: uses `os.Getenv("FOO")` directly. Runnable in principle
//!     when those env vars are set. We list them and flag which are
//!     present in the current process environment.
//!   - `self_contained`: no external secret loader — probably algorithmic
//!     (JWT, base64 parsing, etc.). Theoretically portable to a Rust
//!     integration test once scrump grows a verify() backend.
//!
//! For each file we also extract the Go build tag (most carry
//! `//go:build detectors`, the convention TruffleHog uses to keep them
//! out of the default `go test ./...` run).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Bucket {
    GcpSecret,
    EnvVar,
    SelfContained,
}

impl Bucket {
    fn label(&self) -> &'static str {
        match self {
            Bucket::GcpSecret => "gcp_secret",
            Bucket::EnvVar => "env_var",
            Bucket::SelfContained => "self_contained",
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct Entry {
    provider: String,
    path: PathBuf,
    bucket: Bucket,
    env_vars: Vec<String>,
    build_tag: Option<String>,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn main() -> std::io::Result<()> {
    let root = workspace_root();
    let detectors_dir = root.join("vendor/trufflehog/pkg/detectors");
    if !detectors_dir.exists() {
        eprintln!("missing {}", detectors_dir.display());
        std::process::exit(2);
    }

    let mut entries: Vec<Entry> = Vec::new();
    walk(&detectors_dir, &detectors_dir, &mut entries);
    entries.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.path.cmp(&b.path)));

    // ---- per-bucket summary -----------------------------------------------
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &entries {
        *counts.entry(e.bucket.label()).or_insert(0) += 1;
    }

    println!("\nTruffleHog integration-test inventory\n");
    println!("Total files: {}", entries.len());
    println!("{:-<46}", "");
    for (label, count) in &counts {
        println!("  {:<18} {:>6}", label, count);
    }
    println!("{:-<46}", "");

    // ---- env-var detail ----------------------------------------------------
    let env_entries: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.bucket == Bucket::EnvVar)
        .collect();
    if !env_entries.is_empty() {
        println!(
            "\nIntegration tests using `os.Getenv` ({} files — runnable in principle):",
            env_entries.len()
        );
        for e in &env_entries {
            let missing: Vec<&str> = e
                .env_vars
                .iter()
                .filter(|v| std::env::var(v).is_err())
                .map(String::as_str)
                .collect();
            let status = if missing.is_empty() {
                "READY".into()
            } else {
                format!("blocked: missing env {}", missing.join(", "))
            };
            println!(
                "  [{}] {} — {}",
                e.provider,
                e.path
                    .strip_prefix(&detectors_dir)
                    .unwrap_or(&e.path)
                    .display(),
                status
            );
        }
    }

    // ---- self-contained detail --------------------------------------------
    let sc_entries: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.bucket == Bucket::SelfContained)
        .collect();
    if !sc_entries.is_empty() {
        println!(
            "\nSelf-contained integration tests ({} files — portable in principle, no API call):",
            sc_entries.len()
        );
        for e in &sc_entries {
            println!(
                "  [{}] {}",
                e.provider,
                e.path
                    .strip_prefix(&detectors_dir)
                    .unwrap_or(&e.path)
                    .display()
            );
        }
    }

    println!();
    let runnable_env = env_entries
        .iter()
        .filter(|e| e.env_vars.iter().all(|v| std::env::var(v).is_ok()))
        .count();
    println!(
        "Runnable right now on this host (env vars present): {} of {}",
        runnable_env,
        entries.len()
    );
    println!(
        "Blocked by `common.GetSecret` (requires TruffleHog's private GCP project): {}",
        counts.get("gcp_secret").copied().unwrap_or(0)
    );

    Ok(())
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<Entry>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(root, &p, out);
            continue;
        }
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with("_integration_test.go") {
            continue;
        }
        let src = match fs::read_to_string(&p) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let provider = p
            .parent()
            .unwrap()
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace(['/', '\\'], "_");
        let env_vars = extract_env_vars(&src);
        let bucket = classify(&src, &env_vars);
        let build_tag = extract_build_tag(&src);
        out.push(Entry {
            provider,
            path: p,
            bucket,
            env_vars,
            build_tag,
        });
    }
}

fn classify(src: &str, env_vars: &[String]) -> Bucket {
    if src.contains("common.GetSecret") {
        return Bucket::GcpSecret;
    }
    if !env_vars.is_empty() {
        return Bucket::EnvVar;
    }
    Bucket::SelfContained
}

fn extract_env_vars(src: &str) -> Vec<String> {
    // Grab every `os.Getenv("...")` literal.
    let mut out = Vec::new();
    let needle = "os.Getenv(\"";
    let mut i = 0;
    let bytes = src.as_bytes();
    while let Some(p) = src[i..].find(needle) {
        let s = i + p + needle.len();
        let mut e = s;
        while e < bytes.len() && bytes[e] != b'"' {
            e += 1;
        }
        let name = std::str::from_utf8(&bytes[s..e]).unwrap_or("").to_string();
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
        i = e + 1;
    }
    out
}

fn extract_build_tag(src: &str) -> Option<String> {
    // Look for either `//go:build …` or the older `// +build …`.
    for line in src.lines().take(5) {
        if let Some(rest) = line.strip_prefix("//go:build ") {
            return Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("// +build ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}
