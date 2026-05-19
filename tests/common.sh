#!/usr/bin/env bash
# Shared helpers for tests/e2e_*.sh. Source from each phase script.
#
# Exposes:
#   ROOT       — absolute path to the scrump workspace root
#   BIN        — path to the scrump binary (built on demand)
#   TMP        — scratch dir, auto-cleaned via trap
#   die        — print red, exit 1
#   ok         — print green
#   info       — print blue
#   need_bin   — fail with a clear message if a command is missing
#   plant_token <name>  — emit a recognisably-shaped fake credential

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Build binary on demand. Prefer release if present.
if [[ -x "$ROOT/target/release/scrump" ]]; then
    BIN="$ROOT/target/release/scrump"
elif [[ -x "$ROOT/target/debug/scrump" ]]; then
    BIN="$ROOT/target/debug/scrump"
else
    ( cd "$ROOT" && cargo build -p scrump-cli >/dev/null )
    BIN="$ROOT/target/debug/scrump"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# tput colours — degrade gracefully when not a TTY.
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    _RED=$(tput setaf 1); _GRN=$(tput setaf 2); _BLU=$(tput setaf 4); _RST=$(tput sgr0)
else
    _RED=""; _GRN=""; _BLU=""; _RST=""
fi

die()  { printf '%s[FAIL]%s %s\n' "$_RED" "$_RST" "$*" >&2; exit 1; }
ok()   { printf '%s[ OK ]%s %s\n' "$_GRN" "$_RST" "$*"; }
info() { printf '%s[info]%s %s\n' "$_BLU" "$_RST" "$*"; }

need_bin() {
    command -v "$1" >/dev/null 2>&1 || die "missing required binary: $1"
}

# Deterministic obvious-fake tokens. NOT real credentials — designed to
# match the corresponding default rule's regex while being unambiguously
# synthetic so upstream secret scanners (GitHub Advanced Security, etc.)
# don't flag the test corpus as a leak.
plant_token() {
    "$ROOT/target/debug/plant-token" "$1"
}

# Assert that the given file no longer contains any token prefix we plant.
assert_clean_of_tokens() {
    local file="$1"
    if grep -aE 'ghp_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{34}|sk-ant-api[0-9]{2}|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{35}|xoxb-|nvapi-[A-Za-z0-9_-]{20}|wandb-[A-Fa-f0-9]{40}' "$file" >/dev/null; then
        local leaks
        leaks="$(grep -aE 'ghp_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{34}|sk-ant-api[0-9]{2}|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{35}|xoxb-|nvapi-[A-Za-z0-9_-]{20}|wandb-[A-Fa-f0-9]{40}' "$file" || true)"
        die "tokens still present in $file:\n$leaks"
    fi
}

# Assert that scrump scan reports the expected format name in its first
# "(format=...)" line.
assert_scrump_format() {
    local file="$1"; local expected="$2"
    local actual
    actual=$("$BIN" scan "$file" 2>&1 | grep -oE '\(format=[^)]+\)' | head -n1 || true)
    if [[ "$actual" != "(format=$expected)" ]]; then
        die "expected format=$expected, got $actual on $file"
    fi
}
