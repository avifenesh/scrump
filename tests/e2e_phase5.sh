#!/usr/bin/env bash
# Phase 5 gate: Java HPROF heap dump.
#
# Generates a real HPROF dump via `jcmd <pid> GC.heap_dump`. The captured JVM
# is started with -DGH_TOKEN=<planted> which lands as a String in the dump.
# scrump scrubs; assert:
#   1. Format auto-detect == hprof.
#   2. Header magic intact ("JAVA PROFILE 1.0.X\0").
#   3. File size preserved.
#   4. No planted token in raw bytes.

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

need_bin java
need_bin jcmd

GH=$(plant_token ghp)
HF=$(plant_token hf)

# Tiny program that just sleeps long enough for the dump.
cat >"$TMP/Sleeper.java" <<'EOF'
public class Sleeper {
    public static void main(String[] a) throws Exception {
        String t = System.getProperty("GH_TOKEN");
        String t2 = System.getProperty("HF_TOKEN");
        // Keep references alive so the strings end up on the heap.
        java.util.List<String> hold = new java.util.ArrayList<>();
        hold.add(t); hold.add(t2);
        Thread.sleep(60_000);
        System.out.println(hold.size());
    }
}
EOF

( cd "$TMP" && javac Sleeper.java )

java -cp "$TMP" -DGH_TOKEN="$GH" -DHF_TOKEN="$HF" Sleeper &
PID=$!
trap 'kill -9 "$PID" 2>/dev/null || true' EXIT
# Wait for the JVM to be ready.
for i in $(seq 1 50); do
    if jcmd "$PID" VM.uptime >/dev/null 2>&1; then break; fi
    sleep 0.1
done

HPROF="$TMP/dump.hprof"
jcmd "$PID" GC.heap_dump "$HPROF" >"$TMP/jcmd.log" 2>&1 || {
    cat "$TMP/jcmd.log" >&2
    die "phase5: jcmd heap_dump failed"
}
[[ -f "$HPROF" ]] || die "phase5: hprof not produced"

PRE_SIZE=$(stat -c%s "$HPROF")
info "phase5: $HPROF ($PRE_SIZE bytes)"

assert_scrump_format "$HPROF" "hprof"
ok "phase5: auto-detected as 'hprof'"

"$BIN" scrub "$HPROF" >/dev/null
ok "phase5: scrub returned 0"

POST_SIZE=$(stat -c%s "$HPROF")
[[ "$PRE_SIZE" == "$POST_SIZE" ]] || die "phase5: size changed ($PRE_SIZE -> $POST_SIZE)"
ok "phase5: file size preserved"

# Header magic stays "JAVA PROFILE ".
head -c 12 "$HPROF" | grep -q '^JAVA PROFILE' || die "phase5: HPROF header magic broken"
ok "phase5: HPROF header magic intact"

assert_clean_of_tokens "$HPROF"
ok "phase5: no planted token remains"

ok "phase5: GREEN"
