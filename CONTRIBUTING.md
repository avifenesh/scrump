# Contributing to scrump

## Adding a new detector (token pattern)

Add a YAML entry to `crates/scrump-rules/rules/default.yaml`:

```yaml
- id: my_provider_token
  pattern: 'my-prefix-[A-Za-z0-9]{32}'
  min_entropy: 4.0   # optional; default = no entropy floor
```

Rules:

- `id` must be unique within the file (used in `--rule` / `--exclude-rule`).
- `pattern` is a Rust `regex::bytes::Regex` (no lookaround, no backrefs).
- `min_entropy` is a Shannon-entropy floor in bits/byte applied to the
  matched bytes; useful for high-entropy random keys to suppress false
  positives on words-shaped matches.

Add at least one positive and one negative test fixture under
`fixtures/rules/<id>/` and ensure `cargo test --workspace` passes.

## Adding a new format handler

Each capture format is a separate crate `crates/scrump-format-<name>/`
implementing `scrump_core::Format`:

```rust
pub trait Format: Send {
    fn detect(head: &[u8], path: &Path) -> bool where Self: Sized;
    fn open(path: &Path) -> Result<Self> where Self: Sized;
    fn chunks<'a>(&'a self) -> Box<dyn Iterator<Item = Chunk<'a>> + 'a>;
    fn apply(&mut self, hits: &[Hit]) -> Result<()>;
    fn write(&self, out: &Path) -> Result<()>;
    fn name(&self) -> &'static str;
}
```

Checklist when adding a format:

1. **`detect`** must be cheap (sniff magic bytes / extension).
2. **`chunks`** should yield the sensitive substructures as separate
   `Chunk` values with informative `ChunkOrigin` (`Env`, `Cmdline`,
   `StringTable("Foo")`, etc.). Scanning everything as one big chunk works
   but loses structure for redaction decisions.
3. **`apply`** must preserve structural validity. Prefer length-preserving
   `Replacement::ZeroFill` so offsets/checksums in the format don't need
   to be updated. Drop-style replacement is allowed only for formats that
   absorb length changes.
4. **`write`** must be atomic: write to a temp path, then rename over the
   destination. Never truncate the destination in place — a crash mid-write
   corrupts the user's only copy.
5. Add a golden fixture under `fixtures/phase<N>/` with a planted token
   and an end-to-end test script under `tests/`.

## Code style

- `cargo fmt --all` before committing.
- `cargo clippy --workspace --all-targets -- -D warnings` must pass.
- No `unwrap`/`expect` outside of tests; use `?` and the `ScrumpError` type.
- No `unsafe` without a `// SAFETY:` comment.

## Git hooks

This repo ships hooks under `scripts/git-hooks/`, versioned with the source.
Enable them once after cloning:

```sh
bash scripts/install-hooks.sh
```

This sets `core.hooksPath = scripts/git-hooks` for this repo only — your
global git config is untouched.

### What runs

- **pre-commit**: `cargo fmt --all -- --check` and
  `cargo clippy --workspace --all-targets -- -D warnings`. Skipped
  automatically if no `.rs` / `Cargo.toml` / `Cargo.lock` files are staged.

### Bypass

Only in genuine emergencies:

```sh
git commit --no-verify
```

If you find yourself bypassing repeatedly, fix the underlying issue or open
an issue to relax the rule — don't silently skip.
