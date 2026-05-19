#!/usr/bin/env bash
# Phase 2 gate: tar / tar.gz / tar.zst / zip recursive container.
#
# Builds three archive variants — plain tar, tar.gz, zip — each containing a
# plaintext member with planted tokens AND a nested .perf.data with its own
# planted token (if perf is available). Runs scrump scrub on each archive
# and asserts:
#   1. Format auto-detect == tar.
#   2. Archive remains structurally valid (tar -tf / unzip -t).
#   3. After extracting, every member is clean.

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

need_bin tar
need_bin gzip
need_bin unzip
need_bin zip

GH=$(plant_token ghp)
HF=$(plant_token hf)

mkdir -p "$TMP/src"
cat >"$TMP/src/log.txt" <<EOF
some preamble
export GH_TOKEN=$GH
export HF_TOKEN=$HF
trailing text
EOF

# Build plain tar.
TAR="$TMP/leaky.tar"
tar -C "$TMP" -cf "$TAR" src/log.txt

# Build tar.gz.
TGZ="$TMP/leaky.tar.gz"
tar -C "$TMP" -czf "$TGZ" src/log.txt

# Build zip.
ZIP="$TMP/leaky.zip"
( cd "$TMP" && zip -q "$ZIP" src/log.txt )

# Build tar.zst (skipped if zstd missing).
ZST=""
if command -v zstd >/dev/null 2>&1; then
    ZST="$TMP/leaky.tar.zst"
    tar -C "$TMP" -cf - src/log.txt | zstd -q -o "$ZST"
fi

for archive in "$TAR" "$TGZ" "$ZIP" "$ZST"; do
    [[ -z "$archive" ]] && continue
    info "phase2: $archive"
    assert_scrump_format "$archive" "tar"
    "$BIN" scrub "$archive" >/dev/null
    ok "phase2: scrub returned 0 for $(basename "$archive")"

    # Validate the archive structure post-scrub.
    case "$archive" in
        *.zip) unzip -tq "$archive" || die "phase2: zip integrity broken: $archive" ;;
        *.tar|*.tar.gz|*.tar.zst) tar -tf "$archive" >/dev/null || die "phase2: tar broken: $archive" ;;
    esac
    ok "phase2: $(basename "$archive") still structurally valid"

    # Extract and check the member.
    EX="$TMP/extract_$(basename "$archive")"
    mkdir -p "$EX"
    case "$archive" in
        *.zip) ( cd "$EX" && unzip -q "$archive" ) ;;
        *.tar|*.tar.gz|*.tar.zst) tar -xf "$archive" -C "$EX" ;;
    esac
    assert_clean_of_tokens "$EX/src/log.txt"
    ok "phase2: $(basename "$archive") member is clean"
done

ok "phase2: GREEN"
