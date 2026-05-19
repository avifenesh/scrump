# Changelog

All notable changes to scrump are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Suppressed runaway false positives from auto-extracted TruffleHog rules
  on real-world artifacts. `scrump scan` and `scrump scrub` previously
  produced unusable noise on common shapes (~60M hits on a 671 MB
  SQLite log, ~159k hits on a 486 KB public OSS tarball) because a long
  tail of auto-extracted rules either had no keyword anchor, anchored
  on generic tokens like `id`/`name`/`org`/`key`/`password`, used
  unbounded `{N,}` quantifiers that greedy-matched entire alphanumeric
  regions, or matched email / version-string / hostname / fixed-length
  hex shapes that occur throughout any real text. 65 structurally-broken
  rule patterns were moved to a `TH_QUARANTINE` list in `scrump-rules`
  and are no longer loaded into the default detector set. The list was
  derived empirically — first by an in-tree audit
  (`crates/scrump-rules/tests/noise_audit.rs`) that runs every active
  rule against an ≈ 8 MB synthetic corpus, then by rescanning a real
  671 MB SQLite log artifact end-to-end and quarantining any rule with
  more than 100 hits. On that artifact the post-fix scan reports 601
  hits — down from 61,059,863 — a 101,597× reduction. Users who depend
  on any quarantined rule for narrow inputs can reintroduce it via
  `--rules-path FILE.yaml`. (#9)
- The TruffleHog parity harness now honors the same quarantine list when
  reading `provider_map.json`, so a provider whose only rules are
  quarantined is skipped instead of having its positive cases fail
  against an empty engine. Net effect on the harness: 201 → 187 known
  cross-provider FPs.

### Added

- `scrump-rules` integration test `fp_regression` asserts the active
  ruleset stays bounded on a synthetic noise corpus (log lines, source
  code, config files, alphanumeric blob, tar padding ≈ 8 MB): no rule
  may fire more than 10 times or capture more than 1024 bytes, and
  `scrub` on the corpus must overwrite ≤ 0.1% of the bytes. A separate
  `noise_audit` test (`#[ignore]`d by default) prints the full
  per-rule distribution for diagnosing future regressions.

## [0.1.2] — 2026-05-19

### Added

- Release binary matrix grew from 3 to 7 targets. New: Windows
  `x86_64-pc-windows-msvc`, Windows `aarch64-pc-windows-msvc`, macOS
  Intel `x86_64-apple-darwin`, Linux static `x86_64-unknown-linux-musl`.
  Windows builds package as `.zip`; all others as `.tar.gz`. Each
  artifact ships with a matching `.sha256` sidecar.

No code change — same crates as 0.1.1.

## [0.1.1] — 2026-05-19

### Fixed

- Every published crate now declares `readme = "../../README.md"`, so
  the crates.io page renders the workspace README instead of an empty
  description card. No code change.

## [0.1.0] — 2026-05-19

The first tagged release. Covers every format scrump was designed for,
plus two third-party-compat test corpora.

### Added

- **Workspace skeleton** — 14 crates split by concern: `scrump-core`
  (trait surface), `scrump-detect` (regex + entropy + post-filter
  engine), `scrump-rules` (curated + auto-extracted ruleset),
  `scrump-cli` (the binary), 8 format crates, 2 compat-harness crates,
  and a test-fixture crate that generates spec-compliant inputs at
  runtime.
- **Format coverage** (Phase 0..7 e2e gates pass):
  - `passthrough` — raw scan fallback for any file
  - `perf` — `PERFILE2`, header feature sections + data section
  - `tar` — `tar` / `tar.gz` / `tar.zst` / `zip`, recursively
    dispatched per-member
  - `sqlite` — `SQLite format 3`, TEXT/BLOB cells via `UPDATE` + `VACUUM`
  - `nsys` — `.nsys-rep` / `.ncu-rep`, tar-envelope + inner SQLite
  - `elf-core` — 64-bit LE `ET_CORE`, `PT_NOTE/NT_PRPSINFO` cmdline
    + `PT_LOAD` env pages
  - `hprof` — Java HPROF `JAVA PROFILE`, STRING record stream
  - `jfr` — Java Flight Recorder `FLR\0` chunks (structural-safe)
  - `pcap` — tcpdump pcap + pcapng packet payloads
- **Detection engine** — `regex::bytes` + Shannon entropy floor +
  `capture_index` for group-redact patterns + `post_filter` slot for
  Rust-side semantic checks (currently `JwtHsAware` rejects
  HMAC-signed JWTs to mirror TruffleHog's filter).
- **CLI** — `scan`, `scrub`, `verify`, `explain` subcommands; flags
  for `--format`, `--rule` / `--exclude-rule`, `--rules-path`,
  `--backup`, `--no-recursive`, `--threads`, `-q` / `-v` / `--json`.
- **Atomic in-place redaction** — every format crate's `apply` writes
  to a tmp path and renames over the destination; no half-redacted
  files on crash.
- **TruffleHog compat harness** — auto-extracts patterns +
  `PrefixRegex` keyword sets from `pkg/detectors/` and runs scrump
  against every `*_test.go` test case across **864 providers** (2,536
  cases). 2,335 pass; the 201-failure floor is gated by
  `SCRUMP_TH_MAX_FAILURES` so any regression breaks CI.
- **Presidio cross-format harness** — runs Microsoft Presidio's
  52-recognizer test manifest (671 cases) through every binary format
  scrump supports. 617 pass on each of the 8 formats; the 54 failures
  are uniformly Presidio patterns that use lookbehind / backreferences
  that Rust's `regex` doesn't support.
- **CI** — fmt + clippy + tests; phase 0..7 e2e gates; both compat
  harnesses; release pipeline for `x86_64-linux`, `aarch64-linux`,
  `aarch64-darwin` on `v*.*.*` tags.
- **Docs** — README with format table + install + compat results;
  `CONTRIBUTING.md` with detector + format add-a-new-X checklists;
  `SECURITY.md` private-disclosure policy with scope; this changelog.

### Security

This is a fresh repo — no CVEs against earlier versions to backport.
For the disclosure policy, see [`SECURITY.md`](SECURITY.md).

[Unreleased]: https://github.com/avifenesh/scrump/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/avifenesh/scrump/releases/tag/v0.1.2
[0.1.1]: https://github.com/avifenesh/scrump/releases/tag/v0.1.1
[0.1.0]: https://github.com/avifenesh/scrump/releases/tag/v0.1.0
