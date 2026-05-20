# Changelog

All notable changes to scrump are documented here. Format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.7] — 2026-05-20

### Fixed

- Real-artifact iteration rounds 11–15 (cloud/devops CLIs, database
  engines, mobile/desktop app packages, scientific/firmware images, and
  more language ecosystems): AWS CLI, minikube, argocd, gitleaks, the
  TruffleHog binary, MongoDB/Redis/InfluxDB/ClickHouse/CockroachDB,
  F-Droid/VLC APKs, uBlock Origin, KeePassXC, Miniconda, OpenWRT
  firmware, geth, composer, elixir, bitcoin-core, VictoriaMetrics, jq.
  Added 22 explicit quarantine entries; with the structural heuristic
  the active auto-extracted ruleset is now ~905 rules (244 quarantined).
  - New broken providers were almost all bare-character-class rules
    firing on Go/AWS-SDK symbol tables (geocodio, maxmindlicense,
    sugester, scalr, billomat, textmagic, artsy, customerguru, …) and
    browser-extension filter lists (youtube channel IDs, tracking
    domains).
  - **Policy:** bare-hostname domain/URL detectors (`*.okta.com`,
    `*.zendesk.com`, `cdn.auth0.com`, `*.hashicorp.cloud`) are now
    quarantined — they capture identifiers, not secrets. Credential-
    bearing connection strings (`postgres://`, `mongodb://user:pass@`,
    `ldap://`) stay active.
  - TruffleHog parity harness: 156 → 130 known cross-provider FPs.
  - FP rate on representative real artifacts is at the floor: most Go
    binaries, DB engines, firmware, ML installers, and language runtimes
    scan at 0 hits; the few non-zero outliers are correct detections
    (the `AKIAIOSFODNN7EXAMPLE` doc key in AWS CLI, embedded PEM test
    keys, the dual-use cosmos base64 rule).
- Per-round false-negative validation: marquee secrets planted *inside*
  each round's tarballs (gitleaks, trufflehog, redis, influxdb, geth,
  victoriametrics, bitcoin) and scrubbed — 0 leaks of 18 every time, on
  top of the permanent `fn_marquee` engine-level guard.

## [0.1.6] — 2026-05-20

### Added

- Structural quarantine heuristic in `scrump-rules` — a durable second
  layer beyond the hand-verified `TH_QUARANTINE` list (issue #9). It
  auto-quarantines an auto-extracted rule when (a) the rule's provider
  already has at least one explicitly-quarantined rule and (b) the
  rule's *value* pattern (ignoring the `PrefixRegex` keyword context)
  carries no fixed ≥3-char literal anchor — the bare-character-class
  shape (`\b([0-9a-zA-Z]{32})\b`) that floods compiled binaries and
  minified JS. Once a provider is proven noisy on real artifacts, its
  sibling rules of the same broken shape are swept up without each one
  being named.
  - Deliberately scoped to known-noisy providers: a blanket "no value
    literal" rule would flag ~80% (925/1149) of providers, most of
    which never fire on real inputs — dropping them would only cost
    recall (a silent leak for a scrubber). The provider-scoped form
    sweeps up 39 additional sibling rules and leaves 942 providers
    active.
  - Effect on the TruffleHog parity harness: 184 → 156 known
    cross-provider false positives, with every positive case preserved.
  - Guarded by two tests: `structural_heuristic` (never flags a rule
    with a distinctive literal; always flags bare-charclass siblings)
    and the existing `fn_marquee` (all 21 marquee secret types still
    detected). Dual-use exceptions (`azure_cosmosdb__dbkeypattern`,
    `okta__tokenpat`) are allowlisted.

## [0.1.5] — 2026-05-20

### Fixed

- Continued the issue #9 real-artifact iteration through rounds 6–10,
  expanding `TH_QUARANTINE` from 145 to 170 patterns. New corpus shapes:
  container layers, ONNX/TFLite ML models, JS runtimes (Bun, Deno),
  Firefox, Windows PE binaries (Rust), Jupyter notebooks, k8s manifests,
  Helm charts, CA cert bundles, parquet, Apache PowerShell/.NET, DuckDB,
  Zig, Swift sources, a Haskell binary, SQLite C amalgamation, the
  Terraform AWS provider, and Grafana (Go binary + web assets).
  - Rounds 7 (media/WASM/font/SQL) and 8 (Windows PE/YAML/Jupyter)
    surfaced **zero** new noise — those shapes carry no token-like
    strings.
  - Rounds 6, 9, and 10 surfaced the remaining provider-keyword rules
    that fire on compiled-binary identifier tables and JS bundles
    (`grafana`→`drone.grafana.net`, `roaring`→bitmap-library symbols,
    `polygon`→geometry code, `chatbot`/`customerguru`/`algolia`→AWS-SDK
    Go function names, `redis`→the word `password`, etc.).
  - Worst-case per-MB hit rate on the round 6–10 corpus (excluding the
    deliberately-kept dual-use rules below): media/WASM/PE/source/cert
    artifacts 0/MB; Go binaries ≤0.9/MB.

### Notes

- **Deliberately kept** as real (low-FP, structurally-anchored)
  detectors despite looking broad: `okta__domainpat`, `ldap__uripat`,
  `hashicorpvaultauth__vaulturlpat`, `grafanaserviceaccount__keypat`
  (real `glsa_` tokens), `privatekey__keypat`, `okta__tokenpat` (catches
  real `00…` Okta tokens), and `azure_cosmosdb__dbkeypattern` — the last
  is unanchored (`[A-Za-z0-9]{86}==`) and is the single largest remaining
  hit source on base64-dense artifacts, but it is genuinely dual-use
  (it caught real Grafana API-key JSON blobs in the corpus), so it stays
  pending a keyword-anchored replacement in `default.yaml`.
- The `fn_marquee` false-negative guard continues to pass: all 21
  marquee secret types remain detected after the expanded curation.

## [0.1.4] — 2026-05-20

### Fixed

- Extended the issue #9 rule curation from 82 to 145 quarantined
  patterns by running a download → scan → classify → delete loop across
  ~25 diverse real-world artifacts in five rounds: OSS release tarballs,
  Rust crates, npm packages, Java JARs, Python wheels, a PDF, Debian
  packages, JFR + HPROF dumps, public SQLite databases, pcaps, and Go
  binaries (gh, kubectl, helm, terraform, consul, vault, etcd, k9s,
  prometheus, caddy, restic, the Go + Node.js toolchains). Each round
  used artifact shapes the prior rounds hadn't seen, surfacing new
  broken patterns. The dominant new class was keyword anchors matching
  ordinary identifiers in compiled binaries — e.g. `azure` matching Go
  function names, `secret`/`role` matching UUID-shaped trace IDs, `box`
  matching `inbox`, `lob` matching `global`, `aha` matching `Sahara`,
  and provider keywords matching Go's net/url TLD data tables. Worst-
  case per-MB hit rate on the corpus dropped from 22–509 hits/MB to
  ≤0.27 hits/MB; aggregate ~0.06 hits/MB across ~440 MB of Go binaries.

### Added

- `scrump-rules` integration test `fn_marquee` — a false-negative guard
  that plants real-shaped secrets for all 21 marquee provider types
  (GitHub, HuggingFace, OpenAI, Anthropic, AWS, Google, Slack, NVIDIA,
  WandB, Stripe, JWT) and asserts each is still detected by
  `default_detectors()` after curation. Pins the guarantee that
  quarantining noisy rules never silently turns a true positive into a
  leak. Verified out-of-band that `scrub` removes all 21 from raw text,
  tar members, and SQLite cells with zero leaks.

## [0.1.3] — 2026-05-20

### Fixed

- Suppressed runaway false positives from auto-extracted TruffleHog rules
  on real-world artifacts. `scrump scan` and `scrump scrub` previously
  produced unusable noise on common shapes (~60M hits on a 671 MB
  SQLite log, ~159k hits on a 486 KB public OSS tarball) because a long
  tail of auto-extracted rules either had no keyword anchor, anchored
  on generic tokens like `id`/`name`/`org`/`key`/`password`, used
  unbounded `{N,}` quantifiers that greedy-matched entire alphanumeric
  regions, or matched email / version-string / hostname / fixed-length
  hex shapes that occur throughout any real text. 82 structurally-broken
  rule patterns were moved to a `TH_QUARANTINE` list in `scrump-rules`
  and are no longer loaded into the default detector set. The list was
  derived empirically in three passes:
    1. An in-tree audit (`crates/scrump-rules/tests/noise_audit.rs`) that
       runs every active rule against an ≈ 8 MB synthetic corpus and
       flags any rule firing more than 10 times or capturing more than
       1 KB.
    2. Rescanning a real 682 MB SQLite log artifact end-to-end and
       quarantining any rule with more than 100 hits.
    3. A targeted FP-classification pass using the new `--samples N`
       scan flag to inspect actual matched bytes per rule — that surfaced
       another wave of rules whose captures looked like Go function
       names, git SHA-1 commit hashes, GraphQL identifiers, and
       all-zero UUIDs.
  Post-fix on the same SQLite log: **~300 hits, down from 61,059,863
  (~200,000× reduction)**, with an estimated FP rate of ~1.6% based on
  sample-byte inspection (most remaining hits are valid RS256 JWTs,
  Azure CosmosDB keys, NGC keys, HuggingFace tokens, PayPal IDs, the
  literal `AKIAIOSFODNN7EXAMPLE` test key, and other real-shaped
  provider tokens). Users who depend on any quarantined rule for narrow
  inputs can reintroduce it via `--rules-path FILE.yaml`. (#9)
- The TruffleHog parity harness now honors the same quarantine list when
  reading `provider_map.json`, so a provider whose only rules are
  quarantined is skipped instead of having its positive cases fail
  against an empty engine. Net effect on the harness: 201 → 184 known
  cross-provider FPs.

### Added

- `scrump scan --samples N` flag prints up to N example matched-byte
  slices per rule, printable bytes verbatim and non-printable
  hex-escaped, truncated to 120 chars. Lets users characterize whether
  remaining hits are real tokens or false positives — directly the
  workflow used to converge on the 80-rule quarantine list. (#9)
- `scrump-rules` integration test `fp_regression` asserts the active
  ruleset stays bounded on a synthetic noise corpus (log lines, source
  code, config files, `.env` assignments, alphanumeric blob, real-log
  shapes, tar padding ≈ 8 MB): no rule may fire more than 10 times or
  capture more than 1024 bytes, and `scrub` on the corpus must
  overwrite ≤ 0.1% of the bytes. A separate `noise_audit` test
  (`#[ignore]`d by default) prints the full per-rule distribution for
  diagnosing future regressions.

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

[Unreleased]: https://github.com/avifenesh/scrump/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/avifenesh/scrump/releases/tag/v0.1.7
[0.1.6]: https://github.com/avifenesh/scrump/releases/tag/v0.1.6
[0.1.5]: https://github.com/avifenesh/scrump/releases/tag/v0.1.5
[0.1.4]: https://github.com/avifenesh/scrump/releases/tag/v0.1.4
[0.1.3]: https://github.com/avifenesh/scrump/releases/tag/v0.1.3
[0.1.2]: https://github.com/avifenesh/scrump/releases/tag/v0.1.2
[0.1.1]: https://github.com/avifenesh/scrump/releases/tag/v0.1.1
[0.1.0]: https://github.com/avifenesh/scrump/releases/tag/v0.1.0
