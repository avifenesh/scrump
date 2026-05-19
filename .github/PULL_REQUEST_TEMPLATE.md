<!--
Thanks for the PR. Keep this short — the diff is the source of truth.
-->

## What changed

<!-- 1-3 bullets. Skip if the diff is genuinely self-explanatory. -->

## Why

<!-- The problem this fixes or the capability it adds. -->

## How to verify

<!--
- For a new format: which phase-N gate passes? Link the run.
- For a rule change: which compat harness numbers move? Quote before/after.
- For a CLI change: the exact shell snippet a reviewer can run.
-->

## Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] If a phase gate changed: `bash tests/e2e_all.sh` still green
- [ ] If a rule changed: trufflehog-compat floor in CI is unchanged or
      decreases (never increases)
- [ ] If a public CLI / YAML surface changed: README + CHANGELOG updated
