#!/usr/bin/env bash
# Phase 4 gate: ELF core dumps.
#
# We can't drive `gcore` (kernel.yama.ptrace_scope=1 blocks attaching to
# our own descendants in this environment), so we generate a real ELF
# core dump deterministically via `make-core`. It produces a valid
# ET_CORE 64-bit LE x86_64 file with:
#   * NT_PRPSINFO in a PT_NOTE segment (cmdline planted token)
#   * one PT_LOAD segment of fake env-block pages (env planted token)
#
# `readelf -h` and `readelf -n` parse it.

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

need_bin readelf
( cd "$ROOT" && cargo build -p scrump-test-fixtures --quiet 2>&1 ) || die "fixture build failed"
MAKE_CORE="$ROOT/target/debug/make-core"
[[ -x "$MAKE_CORE" ]] || die "missing $MAKE_CORE"

GH=$(plant_token ghp)
HF=$(plant_token hf)
CORE="$TMP/test.core"

"$MAKE_CORE" "$CORE" \
    "sleep arg1 $GH arg3" \
    "HF_TOKEN=$HF" \
    >/dev/null

PRE_SIZE=$(stat -c%s "$CORE")
info "phase4: $CORE ($PRE_SIZE bytes)"

grep -aE 'ghp_|hf_' "$CORE" >/dev/null || die "phase4: planted tokens missing from fixture"

# 1. Format auto-detect.
assert_scrump_format "$CORE" "elf-core"
ok "phase4: auto-detected as 'elf-core'"

# 2. Scrub.
SCRUB_OUT=$("$BIN" scrub "$CORE" 2>&1)
echo "$SCRUB_OUT" | grep -q 'hits redacted' || die "phase4: scrub did not report any redactions:\n$SCRUB_OUT"
ok "phase4: scrub reported redactions"

# 3. Size preserved.
POST_SIZE=$(stat -c%s "$CORE")
[[ "$PRE_SIZE" == "$POST_SIZE" ]] || die "phase4: size changed ($PRE_SIZE -> $POST_SIZE)"
ok "phase4: size preserved"

# 4. ELF structure intact.
readelf -h "$CORE" >/dev/null || die "phase4: readelf -h broken after scrub"
readelf -n "$CORE" >/dev/null || die "phase4: readelf -n broken after scrub"
ok "phase4: ELF structure still parses"

# 5. No token leftover.
assert_clean_of_tokens "$CORE"
ok "phase4: no planted token remains"

ok "phase4: GREEN"
