# Common dev commands. Install `just` with:
#   cargo install just --locked

# Default: show available recipes.
default:
    @just --list

# Fast feedback loop: fmt, clippy, tests, docs.
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace --all-targets
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --document-private-items

# Format everything (no --check).
fmt:
    cargo fmt --all

# Build a release binary at ./target/release/scrump.
build:
    cargo build --release -p scrump-cli

# Phase 0..7 end-to-end gates (slow — requires building format helpers).
e2e:
    bash tests/e2e_all.sh

# Run a single phase gate by number.
e2e-phase N:
    bash tests/e2e_phase{{N}}.sh

# TruffleHog parity: clones vendor/trufflehog if missing, extracts patterns,
# runs the harness with the current failure-floor.
compat-trufflehog:
    @if [ ! -d vendor/trufflehog ]; then \
        git clone --depth=1 --filter=blob:none --sparse \
            https://github.com/trufflesecurity/trufflehog.git vendor/trufflehog ; \
        cd vendor/trufflehog && git sparse-checkout set pkg/detectors pkg/common ; \
    fi
    cargo run --release -p scrump-trufflehog-compat --bin th-extract
    SCRUMP_TH_MAX_FAILURES=201 cargo run --release -p scrump-trufflehog-compat --bin trufflehog-compat

# Presidio PII × every binary format we support.
compat-presidio:
    @if [ ! -d vendor/presidio ]; then \
        git clone --depth=1 --filter=blob:none --sparse \
            https://github.com/microsoft/presidio.git vendor/presidio ; \
        cd vendor/presidio && git sparse-checkout set \
            presidio-analyzer/presidio_analyzer presidio-analyzer/tests ; \
    fi
    cargo run --release -p scrump-presidio-compat --bin presidio-extract
    cargo run --release -p scrump-presidio-compat --bin presidio-compat

# Supply-chain audit (requires `cargo install cargo-deny --locked`).
deny:
    cargo deny check --all-features

# Install git hooks (fmt + clippy pre-commit).
hooks:
    bash scripts/install-hooks.sh

# Everything CI runs, locally, in order. Slow but exhaustive.
ci: check e2e compat-trufflehog compat-presidio deny
