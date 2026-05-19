# Architecture

How scrump is put together, why those choices, and where to look when
the system surprises you.

## The shape

```
                 ┌──────────────────────┐
   scrump CLI ──▶│   Dispatcher         │── picks a Format impl
                 │   (scrump-core)      │   from the file's first bytes
                 └──────────┬───────────┘
                            │
            ┌───────────────┴────────────────┐
            ▼                                ▼
    ┌───────────────┐                ┌──────────────────┐
    │ Format        │                │ Detection Engine │
    │ (per-format   │   chunks()     │ (scrump-detect)  │
    │  crate)       │ ──────────────▶│  regex+entropy+  │
    │               │   apply(hits)  │  post_filter     │
    │               │ ◀──────────────│                  │
    └───────┬───────┘                └──────────────────┘
            │  to_bytes()
            ▼
    atomic tmp+rename write
```

There are three concerns and three crates that own them:

| Concern | Crate | What it owns |
|---|---|---|
| What a "redactable region" looks like | `scrump-core` | `Format`, `Chunk`, `Hit`, `Replacement`, `Dispatcher`, `apply_hits_in_place`, `write_atomic` |
| Whether a byte range *is* a secret | `scrump-detect` | Regex compilation, entropy floor, post-filter slot, parallel scan |
| Which patterns to look for | `scrump-rules` | Curated rules + auto-extracted TruffleHog mirror + hand-coded post-filters |

Per-format details live in the `scrump-format-*` crates. Adding a new
format means writing one crate; the engine and dispatcher don't change.

## The `Format` trait

```rust
pub trait Format: Send {
    fn name(&self) -> &'static str;
    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a>;
    fn apply(&mut self, hits: &[Hit]) -> Result<()>;
    fn to_bytes(&self) -> Result<Vec<u8>>;
}
```

The trait is **dyn-compatible** — `detect` / `open` were lifted out into
free functions held by a `Handler` table because anything `where Self:
Sized` poisons `dyn Format`. The dispatcher walks the table, sniffs the
first 4 KiB of the file, picks the first `Handler` whose `detect` returns
true, and calls `open`.

### Why iterators, not a callback

`chunks()` yields `Chunk { bytes: &[u8], offset: u64, origin: ChunkOrigin }`
on demand. The detection engine consumes them in parallel via Rayon. A
callback API would have couple'd format state to engine state — instead,
the format owns the bytes and the engine borrows them.

### Why `apply` takes hits by slice, not stream

Hits arrive after a full scan because some post-filters (JWT alg
inspection) need to look at multiple captures together. Streaming
redaction in the middle of an unfinished scan would let one rule's
zero-fill silently invalidate another rule's pattern.

## The redaction guarantee

Every format crate's `apply` calls into `scrump_core::apply_hits_in_place`
on whichever buffer represents the file. That helper:

1. Validates each hit's `offset + len` is inside the buffer.
2. Validates the hit doesn't straddle a structural region (the format
   declares those as `StructuralRange`s on its `Chunk`s).
3. Zero-fills `[offset, offset+len)` (default) — **length-preserving**.
   No offset shifts means no checksum/index recompute is required
   for any of the supported formats; the file remains structurally
   valid to its native parser.

The crate **refuses to redact structural bytes** even if a regex matches
them. This is checked at the apply step, not the chunk step — a chunk
can include both scannable and structural bytes (e.g. an HPROF STRING
record is a varint header followed by UTF-8 content; the varint is
declared structural).

## Detection model

`scrump-detect::Engine` is a flat dispatch over all enabled detectors:

- **Keyword pre-filter** (optional per-rule): a fixed-string prescreen
  before invoking the regex. Used by TruffleHog-mirrored rules where
  the upstream detector requires e.g. the literal `hf_` near the match.
- **Pattern**: `regex::bytes::Regex` (no lookbehind, no backrefs — a
  Rust `regex` crate limit, not a scrump choice; see `SECURITY.md` for
  the known-FN list).
- **Entropy floor**: per-rule Shannon entropy threshold over the matched
  bytes. Suppresses common-word matches against high-entropy patterns.
- **Post-filter**: optional Rust callback that gets the match bytes
  and returns keep/drop. Currently used by `JwtHsAware` to base64-decode
  the JWT header and reject `alg=HS*` tokens, mirroring TruffleHog's
  HMAC filter.
- **`capture_index`**: redact a specific capture group, not the whole
  match. Lets us write rules like "match `WANDB_API_KEY=<value>`,
  redact `<value>`".

## Why no offset rewriting?

A scrubber that re-lengths the file is more powerful but also much more
fragile: every format defines its own offset references (HPROF's string
ID table, SQLite's b-tree page pointers, perf's feature-section index,
ELF's segment headers, pcap's per-packet length, JFR's constant pool…).
A bug in one offset rewrite turns the artifact into a brick. We chose
zero-fill (length-preserving) for every format because:

1. It works for every threat we've seen — leaked secrets are payloads
   inside string-typed regions, not metadata. There's nothing useful
   to *shrink*.
2. Structural validity is automatic. Every supported format passes its
   native parser after `scrump scrub` because no offset moved.
3. The side-channel of "the secret was N bytes long" is documented in
   `SECURITY.md` as out-of-scope; re-encoding the file is the user's
   problem if their threat model includes it.

## Why a separate fixture crate?

`scrump-test-fixtures` generates spec-compliant capture files at runtime
from a single Rust source. The reasoning:

- **Reproducibility**: a generated perf.data is identical bit-for-bit
  between developers and CI; a recorded perf.data has timestamps and
  kernel-version baked in.
- **GitHub push protection**: token literals composed by `tokens.rs`
  are assembled from non-contiguous fragments at runtime. No
  checked-in source contains a contiguous shape like `ghp_…`, which
  is what GHAS scans for at push time.
- **Tooling-free CI**: we can phase-gate against `make-perf`,
  `make-core`, `make-pcap`, `make-sqlite`, etc., without installing
  `perf`, `gdb`, `tcpdump`, or a JDK on the runner.

## Where to start reading

If you want to understand the system end-to-end, read in this order:

1. `crates/scrump-core/src/lib.rs` — trait + dispatcher
2. `crates/scrump-detect/src/lib.rs` — the engine
3. `crates/scrump-format-passthrough/src/lib.rs` — the simplest Format
4. `crates/scrump-format-perf/src/lib.rs` — a realistic Format
5. `tests/e2e_phase1.sh` — what a phase gate looks like
6. `crates/scrump-trufflehog-compat/src/main.rs` — the parity harness

Then look at any format crate matching your interest.
