#!/usr/bin/env bash
# Phase 7 gate: pcap (classic tcpdump format).
#
# Generates a synthetic classic-pcap with one packet whose payload
# carries planted tokens in HTTP `Authorization: Bearer …` headers.
# scrump auto-detects the format, scrubs, and we assert:
#   1. Format reports `pcap`.
#   2. File size preserved.
#   3. Classic pcap magic intact.
#   4. No planted token in raw bytes.

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

( cd "$ROOT" && cargo build -p scrump-test-fixtures --quiet 2>&1 ) || die "fixture build failed"
MAKE_PCAP="$ROOT/target/debug/make-pcap"
[[ -x "$MAKE_PCAP" ]] || die "missing $MAKE_PCAP"

GH=$(plant_token ghp)
HF=$(plant_token hf)
ANT=$(plant_token anthropic)
PCAP="$TMP/test.pcap"

"$MAKE_PCAP" "$PCAP" "$GH" "$HF" "$ANT" >/dev/null

PRE_SIZE=$(stat -c%s "$PCAP")
info "phase7: $PCAP ($PRE_SIZE bytes)"

grep -aE 'ghp_|hf_|sk-ant-' "$PCAP" >/dev/null || die "phase7: planted tokens missing"

assert_scrump_format "$PCAP" "pcap"
ok "phase7: auto-detected as 'pcap'"

SCRUB_OUT=$("$BIN" scrub "$PCAP" 2>&1)
echo "$SCRUB_OUT" | grep -q 'hits redacted' || die "phase7: no redactions reported:\n$SCRUB_OUT"
ok "phase7: scrub reported redactions"

POST_SIZE=$(stat -c%s "$PCAP")
[[ "$PRE_SIZE" == "$POST_SIZE" ]] || die "phase7: size changed ($PRE_SIZE -> $POST_SIZE)"
ok "phase7: size preserved"

# Magic = a1 b2 c3 d4 (little-endian usec variant: on disk d4 c3 b2 a1).
head -c 4 "$PCAP" | od -An -t x1 | tr -d ' \n' | grep -qi '^d4c3b2a1' \
    || die "phase7: pcap magic broken"
ok "phase7: classic pcap magic intact"

assert_clean_of_tokens "$PCAP"
ok "phase7: no planted token remains"

ok "phase7: GREEN"
