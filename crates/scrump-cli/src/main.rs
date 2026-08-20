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
    Scan {
        path: PathBuf,
        /// Print up to N example matched-byte slices per rule (printable
        /// bytes verbatim, non-printable hex-escaped, truncated to 120
        /// chars). Useful for characterizing whether remaining hits are
        /// real tokens or false positives — see issue #9.
        #[arg(long, value_name = "N")]
        samples: Option<usize>,
        /// How many rules the trailing rule-frequency summary lists
        /// (default 10). Pass a number or `all` — see issue #11.
        #[arg(long, value_name = "N|all")]
        summary: Option<String>,
        /// Exit with status 3 when the scan finds any hit, so scripted
        /// callers (pre-commit hooks, CI gates) can block on findings.
        /// Distinct from 1 (runtime error) and 2 (usage error): a caller
        /// can tell "dirty file" from "scanner broke".
        #[arg(long)]
        fail_on_hit: bool,
    },
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

/// Exit status for `scan --fail-on-hit` when at least one hit is found.
/// Deliberately not 1 (anyhow runtime errors) or 2 (clap usage errors).
const EXIT_HITS_FOUND: i32 = 3;

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
        Cmd::Scan {
            path,
            samples,
            summary,
            fail_on_hit,
        } => {
            let summary = parse_summary(summary.as_deref())?;
            let hits = scan(
                &path,
                &dispatcher,
                cli.format.as_deref(),
                &engine,
                samples,
                summary,
            )?;
            if fail_on_hit && hits > 0 {
                std::process::exit(EXIT_HITS_FOUND);
            }
            Ok(())
        }
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

/// `--summary` argument: `all` → no cap, a number → top-N. `None` (flag
/// absent) keeps the default top-10 trailing block.
fn parse_summary(arg: Option<&str>) -> Result<usize> {
    const DEFAULT_TOP: usize = 10;
    match arg {
        None => Ok(DEFAULT_TOP),
        Some("all") => Ok(usize::MAX),
        Some(n) => n
            .parse()
            .with_context(|| format!("--summary expects a number or `all`, got `{n}`")),
    }
}

/// Scan `path` and report findings. Returns the number of hits so the
/// caller can turn them into an exit status (`--fail-on-hit`).
fn scan(
    path: &Path,
    d: &Dispatcher,
    force: Option<&str>,
    eng: &Engine,
    samples: Option<usize>,
    summary_top: usize,
) -> Result<usize> {
    let fmt = open(d, path, force)?;
    println!("(format={})", fmt.name());
    let mut hit_count = 0usize;
    let cap = samples.unwrap_or(0);
    let mut per_rule_samples: std::collections::BTreeMap<String, (usize, Vec<Vec<u8>>)> =
        std::collections::BTreeMap::new();
    let mut rule_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
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
            *rule_counts.entry(h.rule_id.clone()).or_insert(0) += 1;
            if cap > 0 {
                let entry = per_rule_samples
                    .entry(h.rule_id.clone())
                    .or_insert((0, Vec::new()));
                entry.0 += 1;
                if entry.1.len() < cap {
                    let start = h.offset.saturating_sub(chunk.offset) as usize;
                    let end = (start + h.len).min(chunk.bytes.len());
                    if start < chunk.bytes.len() {
                        entry.1.push(chunk.bytes[start..end].to_vec());
                    }
                }
            }
        }
    }
    if hit_count == 0 {
        println!("clean: {} (0 hits)", path.display());
    } else {
        println!("found: {hit_count} hit(s) in {}", path.display());
        print_rule_summary(&rule_counts, summary_top);
    }
    if cap > 0 && !per_rule_samples.is_empty() {
        println!("\n---- per-rule samples (up to {cap}) ----");
        let mut by_count: Vec<_> = per_rule_samples.iter().collect();
        by_count.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
        for (rule, (count, examples)) in by_count {
            println!("\n[{rule}]  hits={count}");
            for ex in examples {
                println!("    {}", render_sample(ex));
            }
        }
    }
    Ok(hit_count)
}

/// Trailing rule-frequency block so an operator can tell at a glance
/// whether a large scan is signal or one noisy rule (issue #11).
fn print_rule_summary(rule_counts: &std::collections::BTreeMap<String, usize>, top: usize) {
    if rule_counts.len() < 2 && top != usize::MAX {
        return; // single rule: the found: line already says everything
    }
    let mut by_count: Vec<_> = rule_counts.iter().collect();
    by_count.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let width = by_count
        .iter()
        .take(top)
        .map(|(_, n)| group_thousands(**n).len())
        .max()
        .unwrap_or(0);
    println!("top rules:");
    for (rule, count) in by_count.iter().take(top) {
        println!("  {:>width$}  {rule}", group_thousands(**count));
    }
    let hidden = by_count.len().saturating_sub(top);
    if hidden > 0 {
        println!(
            "  {:>width$}  ({hidden} more rules, --summary=all to expand)",
            "..."
        );
    }
}

/// `159364` → `159,364`.
fn group_thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Render a matched-byte slice for human inspection: printable bytes
/// verbatim, anything else hex-escaped. Truncated to 120 chars so the
/// terminal stays readable on large captures.
fn render_sample(bytes: &[u8]) -> String {
    const MAX: usize = 120;
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes.iter().take(MAX) {
        if (0x20..0x7f).contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    if bytes.len() > MAX {
        out.push_str(&format!("…[+{} bytes]", bytes.len() - MAX));
    }
    out
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
