#!/usr/bin/env bash
# Phase 3 gate: SQLite + nsys-rep
#
# 1. Plain `.sqlite` with planted tokens in TEXT columns; scrubbed in
#    place; verified via `sqlite-check` (still openable) and `strings`.
# 2. Synthetic `.nsys-rep` — a tar containing the same SQLite + a noise
#    text file; scrubbed; inner SQLite member still openable; both
#    members clean.

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

need_bin tar
( cd "$ROOT" && cargo build -p scrump-test-fixtures --quiet 2>&1 ) || die "fixture build failed"
MAKE_SQLITE="$ROOT/target/debug/make-sqlite"
SQLITE_CHECK="$ROOT/target/debug/sqlite-check"
[[ -x "$MAKE_SQLITE" && -x "$SQLITE_CHECK" ]] || die "missing fixture binaries"

GH=$(plant_token ghp)
HF=$(plant_token hf)

# ---- 3a: plain sqlite ------------------------------------------------------
DB="$TMP/leaky.sqlite"
"$MAKE_SQLITE" "$DB" "GH_TOKEN=$GH" "HF_TOKEN=$HF" >/dev/null

info "phase3a: $DB"
assert_scrump_format "$DB" "sqlite"
ok "phase3a: auto-detected as 'sqlite'"

"$BIN" scrub "$DB" >/dev/null
ok "phase3a: scrub returned 0"

"$SQLITE_CHECK" "$DB" >/dev/null || die "phase3a: db no longer openable"
ok "phase3a: sqlite still openable"

assert_clean_of_tokens "$DB"
ok "phase3a: no planted token remains in db file"

# ---- 3b: nsys-rep ----------------------------------------------------------
mkdir -p "$TMP/nsys-build"
"$MAKE_SQLITE" "$TMP/nsys-build/profile.sqlite" "GH=$GH" "HF=$HF" >/dev/null
cat >"$TMP/nsys-build/manifest.txt" <<EOF
fake nsys-rep manifest
HF_TOKEN=$HF
GH_TOKEN=$GH
EOF
NSYS="$TMP/leaky.nsys-rep"
tar -C "$TMP/nsys-build" -cf "$NSYS" profile.sqlite manifest.txt

info "phase3b: $NSYS"
assert_scrump_format "$NSYS" "nsys"
ok "phase3b: auto-detected as 'nsys'"

"$BIN" scrub "$NSYS" >/dev/null
ok "phase3b: scrub returned 0"

tar -tf "$NSYS" >/dev/null || die "phase3b: nsys-rep envelope broken"
ok "phase3b: nsys-rep envelope intact"

EX="$TMP/nsys-extract"
mkdir -p "$EX"
tar -xf "$NSYS" -C "$EX"
"$SQLITE_CHECK" "$EX/profile.sqlite" >/dev/null \
    || die "phase3b: inner sqlite no longer openable"
ok "phase3b: inner sqlite still openable"

assert_clean_of_tokens "$EX/profile.sqlite"
assert_clean_of_tokens "$EX/manifest.txt"
ok "phase3b: nsys-rep members are clean"

ok "phase3: GREEN"
