//! `scrump` CLI: scan and scrub capture artifacts.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use scrump_core::{write_atomic, Dispatcher, Format};
use scrump_detect::Engine;

#[derive(Parser, Debug)]
#[command(version, about = "Format-aware secret scrubber for capture artifacts")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Override the default ruleset with a YAML file.
    #[arg(long, global = true)]
    rules_path: Option<PathBuf>,

    /// Force a specific format handler (skips auto-detect).
    #[arg(long, global = true)]
    format: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Scan a file and report findings without mutating it.
    Scan { path: PathBuf },
    /// Redact a file in place (or to -o).
    Scrub {
        path: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long)]
        backup: bool,
    },
}

/// Build the dispatcher with every registered format handler. As phases land,
/// each new format-crate's `handler()` is added here in priority order
/// (more-specific first; passthrough is the fallback).
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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let detectors = match &cli.rules_path {
        Some(p) => scrump_rules::detectors_from_path(p)
            .with_context(|| format!("loading rules from {}", p.display()))?,
        None => scrump_rules::default_detectors().context("loading default ruleset")?,
    };
    let engine = Engine::new(detectors);
    let dispatcher = build_dispatcher();

    match cli.cmd {
        Cmd::Scan { path } => scan(&path, &dispatcher, cli.format.as_deref(), &engine),
        Cmd::Scrub { path, out, backup } => scrub(
            &path,
            out.as_deref(),
            backup,
            &dispatcher,
            cli.format.as_deref(),
            &engine,
        ),
    }
}

fn open(d: &Dispatcher, path: &Path, force: Option<&str>) -> Result<Box<dyn Format>> {
    match force {
        Some(name) => d
            .open_path_with(path, name)
            .with_context(|| format!("forcing format `{name}` on {}", path.display())),
        None => d
            .open_path(path)
            .with_context(|| format!("opening {}", path.display())),
    }
}

fn scan(path: &Path, d: &Dispatcher, force: Option<&str>, eng: &Engine) -> Result<()> {
    let fmt = open(d, path, force)?;
    println!("(format={})", fmt.name());
    let mut hit_count = 0usize;
    for chunk in fmt.chunks() {
        for h in eng.scan_chunk(&chunk) {
            hit_count += 1;
            println!(
                "{}:{:#x}+{} rule={} origin={:?}",
                path.display(),
                h.offset,
                h.len,
                h.rule_id,
                h.origin
            );
        }
    }
    if hit_count == 0 {
        println!("clean: {} (0 hits)", path.display());
    } else {
        println!("found: {hit_count} hit(s) in {}", path.display());
    }
    Ok(())
}

fn scrub(
    path: &Path,
    out: Option<&Path>,
    backup: bool,
    d: &Dispatcher,
    force: Option<&str>,
    eng: &Engine,
) -> Result<()> {
    let mut fmt = open(d, path, force)?;
    println!("(format={})", fmt.name());
    let hits: Vec<_> = fmt.chunks().flat_map(|c| eng.scan_chunk(&c)).collect();
    if hits.is_empty() {
        println!("clean: {} (0 hits, nothing to scrub)", path.display());
        return Ok(());
    }
    if backup && out.is_none() {
        let orig = backup_path(path);
        std::fs::copy(path, &orig)
            .with_context(|| format!("creating backup at {}", orig.display()))?;
    }
    fmt.apply(&hits).context("applying redactions")?;
    let bytes = fmt.to_bytes().context("serializing scrubbed file")?;
    let dest = out.unwrap_or(path);
    write_atomic(dest, &bytes)
        .with_context(|| format!("writing scrubbed output to {}", dest.display()))?;
    println!(
        "scrubbed: {} ({} hits redacted)",
        dest.display(),
        hits.len()
    );
    Ok(())
}

fn backup_path(p: &Path) -> PathBuf {
    let mut name = p
        .file_name()
        .map_or_else(|| std::ffi::OsString::from("out"), |s| s.to_os_string());
    name.push(".orig");
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.join(name),
        _ => PathBuf::from(name),
    }
}
