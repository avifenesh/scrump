#!/usr/bin/env bash
# Phase 0 end-to-end test.
#
# 1. Copy the planted fixture to a temp dir.
# 2. `scrump scan` reports the planted tokens.
# 3. `scrump scrub` redacts them in place.
# 4. Post-scrub: re-scan reports zero hits, and a raw `grep` for the
#    known token prefixes finds nothing.
#
# Exits non-zero on any failure.

set -euo pipefail

cd "$(dirname "$0")/.."

# Pick the binary: prefer release, fall back to debug, otherwise build debug.
if [[ -x target/release/scrump ]]; then
  BIN=target/release/scrump
elif [[ -x target/debug/scrump ]]; then
  BIN=target/debug/scrump
else
  cargo build -p scrump-cli >/dev/null
  BIN=target/debug/scrump
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Regenerate the planted fixture fresh from the obvious-fake token
# composer in scrump-test-fixtures. The literal token shapes are
# never checked into the repo — see crates/scrump-test-fixtures/src/lib.rs.
# (We're already in the workspace root after the cd above.)
cargo build -p scrump-test-fixtures --quiet
./target/debug/make-planted "$TMP/planted.txt" >/dev/null
PRE_SIZE=$(stat -c%s "$TMP/planted.txt")

echo "==> scrump scan (pre-scrub)"
SCAN_OUT=$("$BIN" scan "$TMP/planted.txt")
echo "$SCAN_OUT"
EXPECTED_RULES=(
  github_pat_classic
  huggingface_user_token
  anthropic_api_key
  aws_access_key_id
  google_api_key
  slack_bot_token
  nvidia_ngc_api_key
  wandb_api_key_prefixed
)
for r in "${EXPECTED_RULES[@]}"; do
  if ! grep -q "rule=$r" <<<"$SCAN_OUT"; then
    echo "FAIL: expected rule $r not fired during initial scan"
    exit 1
  fi
done

echo "==> scrump scrub"
"$BIN" scrub "$TMP/planted.txt"

POST_SIZE=$(stat -c%s "$TMP/planted.txt")
if [[ "$PRE_SIZE" != "$POST_SIZE" ]]; then
  echo "FAIL: file size changed across scrub ($PRE_SIZE -> $POST_SIZE)"
  exit 1
fi

# Post-scrub: confirm every PLANTED rule from EXPECTED_RULES no longer fires.
# We don't require zero hits overall — the 1100+ auto-extracted TruffleHog
# patterns produce occasional FPs on innocuous strings (`EXAMPLE`, `hub`,
# etc.), which is the cost of broad coverage. What matters is that none of
# the curated planted rules survive.
echo "==> scrump scan (post-scrub, planted rules must be gone)"
POST_SCAN=$("$BIN" scan "$TMP/planted.txt")
echo "$POST_SCAN"
for r in "${EXPECTED_RULES[@]}"; do
  if grep -q "rule=$r" <<<"$POST_SCAN"; then
    echo "FAIL: rule $r still fires after scrub"
    exit 1
  fi
done

echo "==> raw grep for token prefixes (must be empty)"
LEFTOVERS=$(grep -aE 'ghp_|hf_[A-Za-z0-9]|sk-ant-|AKIA[0-9A-Z]{16}|AIza|xoxb-|nvapi-|wandb-[A-Fa-f0-9]' "$TMP/planted.txt" || true)
if [[ -n "$LEFTOVERS" ]]; then
  echo "FAIL: token prefixes still present:"
  echo "$LEFTOVERS"
  exit 1
fi

echo
echo "OK: phase 0 e2e passed"
