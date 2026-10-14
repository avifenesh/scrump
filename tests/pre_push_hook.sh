#!/usr/bin/env bash
# Regression tests for hooks/pre-push. Local bare remotes only; no network.
# Tokens come from plant-token at runtime so this file never contains one.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="$ROOT/hooks/pre-push"
[[ -f "$HOOK" ]] || { echo "missing $HOOK" >&2; exit 1; }

PLANT=""
for c in "$ROOT/target/release/plant-token" "$ROOT/target/debug/plant-token"; do
  [[ -x "$c" ]] && PLANT=$c && break
done
if [[ -z "$PLANT" ]]; then
  (cd "$ROOT" && cargo build -p scrump-test-fixtures --bin plant-token --quiet)
  PLANT="$ROOT/target/debug/plant-token"
fi
TOKEN="$("$PLANT" ghp)"
[[ -n "$TOKEN" ]]

pick_scrump() {
  local candidate help
  if [[ -n "${SCRUMP_BIN:-}" ]]; then
    printf '%s\n' "$SCRUMP_BIN"
    return
  fi
  if command -v scrump >/dev/null 2>&1; then
    candidate="$(command -v scrump)"
    help="$("$candidate" scan --help 2>&1 || true)"
    if grep -q -- '--profile' <<<"$help"; then
      printf '%s\n' "$candidate"
      return
    fi
  fi
  if [[ ! -x "$ROOT/target/debug/scrump" ]]; then
    (cd "$ROOT" && cargo build -p scrump-cli --quiet)
  fi
  printf '%s\n' "$ROOT/target/debug/scrump"
}

SCRUMP="$(pick_scrump)"
scrump_dir="$(dirname "$SCRUMP")"
export PATH="$scrump_dir:$PATH"
# The hook must run this binary, not some other scrump earlier on PATH.
hash -r 2>/dev/null || true

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ZERO=0000000000000000000000000000000000000000
n=0

ok() { printf '[ OK ] %s\n' "$*"; }
die() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

new_repo() {
  n=$((n + 1))
  local bare="$TMP/bare-$n" work="$TMP/work-$n"
  git init -q --bare "$bare"
  git init -q -b main "$work"
  git -C "$work" config user.email test@example.com
  git -C "$work" config user.name test
  git -C "$work" config commit.gpgsign false
  git -C "$work" config tag.gpgsign false
  mkdir -p "$work/.git/hooks"
  cp "$HOOK" "$work/.git/hooks/pre-push"
  chmod +x "$work/.git/hooks/pre-push"
  # Isolate from a global core.hooksPath.
  git -C "$work" config core.hooksPath "$work/.git/hooks"
  REPO=$work
  BARE=$bare
}

commit_all() {
  git -C "$REPO" add -A
  git -C "$REPO" commit -qm "$1"
}

# Write $TOKEN into a path inside $REPO. Path may contain newlines.
plant_file() {
  REPO="$REPO" TOKEN="$TOKEN" REL="$1" python3 - <<'PY'
import os
from pathlib import Path
path = Path(os.environ["REPO"]) / os.environ["REL"]
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(os.environ["TOKEN"] + "\n")
PY
}

push_log() {
  local remote=$1 ref=$2
  local log="$TMP/push.log"
  local rc=0
  git -C "$REPO" push "$remote" "HEAD:refs/heads/$ref" >"$log" 2>&1 || rc=$?
  PUSH_RC=$rc
  PUSH_LOG=$log
}

expect_blocked() {
  local remote=$1 ref=$2 needle=$3
  push_log "$remote" "$ref"
  if [[ "$PUSH_RC" -eq 0 ]]; then
    cat "$PUSH_LOG" >&2
    die "push $ref to $remote was allowed; expected a block ($needle)"
  fi
  if ! grep -q "possible secret" "$PUSH_LOG"; then
    cat "$PUSH_LOG" >&2
    die "push $ref to $remote failed, but not because of a secret"
  fi
  if ! grep -F -q "$needle" "$PUSH_LOG"; then
    cat "$PUSH_LOG" >&2
    die "block message did not name $needle"
  fi
}

expect_ok() {
  local remote=$1 ref=$2
  push_log "$remote" "$ref"
  if [[ "$PUSH_RC" -ne 0 ]]; then
    cat "$PUSH_LOG" >&2
    die "push $ref to $remote should have succeeded"
  fi
}

# --- clean first push, then a secret at the tip ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "readme"
expect_ok origin main
plant_file "config.env"
commit_all "leak"
expect_blocked origin main "config.env"
ok "tip secret blocked"

# --- secret added and removed in the same push ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "readme"
expect_ok origin main
plant_file "leak.env"
commit_all "add leak"
rm "$REPO/leak.env"
commit_all "remove leak"
expect_blocked origin main "leak.env"
ok "removed-in-same-push secret blocked"

# --- clean follow-up after a blocked leak is rewritten out ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "readme"
expect_ok origin main
plant_file "leak.env"
commit_all "add leak"
git -C "$REPO" reset -q --hard HEAD~1
printf 'still fine\n' >>"$REPO/readme.txt"
commit_all "follow-up"
expect_ok origin main
ok "clean follow-up pushed"

# --- path with a space ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "readme"
expect_ok origin main
plant_file "my config.env"
commit_all "spaced"
expect_blocked origin main "my config.env"
ok "space in path blocked"

# --- tab and quote in the name; display may be git-quoted, scan must not skip ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "readme"
expect_ok origin main
plant_file "$(printf 'a\tb"c')"
commit_all "odd name"
expect_blocked origin main "possible secret"
ok "tab/quote in path blocked"

# --- newline in the name: a clean one is allowed, a secret one is not ---
new_repo
git -C "$REPO" remote add origin "$BARE"
REPO="$REPO" python3 - <<'PY'
import os
from pathlib import Path
Path(os.environ["REPO"], "a\nb.env").write_text("clean\n")
PY
commit_all "newline name"
expect_ok origin main
ok "newline in path, clean, pushed"
plant_file "$(printf 'c\nd.env')"
commit_all "newline secret"
expect_blocked origin main "possible secret"
ok "newline in path, secret, blocked"

# --- type change: symlink to file. Clean is allowed; a secret introduced
#     by that same commit is not. Status T is dropped by --diff-filter=AM. ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
ln -s readme.txt "$REPO/config"
commit_all "symlink"
expect_ok origin main
rm "$REPO/config"
printf 'plain text, not a credential\n' >"$REPO/config"
commit_all "now a file"
expect_ok origin main
ln -s readme.txt "$REPO/link"
commit_all "another symlink"
expect_ok origin main
rm "$REPO/link"
plant_file "link"
commit_all "symlink becomes a secret"
expect_blocked origin main "link"
ok "type-change secret blocked"

# --- merge that introduces a secret which is in neither parent ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'base\n' >"$REPO/readme.txt"
commit_all "base"
expect_ok origin main
git -C "$REPO" checkout -q -b side
printf 'side\n' >"$REPO/side.txt"
commit_all "side"
git -C "$REPO" checkout -q main
printf 'main\n' >"$REPO/main.txt"
commit_all "main"
git -C "$REPO" merge -q --no-commit side >/dev/null 2>&1 || die "clean merge failed"
commit_all "merge clean"
expect_ok origin main
ok "clean merge pushed"
git -C "$REPO" checkout -q -b topic
printf 'topic\n' >"$REPO/topic.txt"
commit_all "topic"
git -C "$REPO" checkout -q main
git -C "$REPO" merge -q --no-commit topic >/dev/null 2>&1 || die "topic merge failed"
plant_file "only-merge.txt"
git -C "$REPO" add -A
commit_all "merge with secret"
expect_blocked origin main "only-merge.txt"
ok "merge-only secret blocked"

# --- secret already on another remote must still block this one ---
new_repo
priv="$TMP/private-$n.git"
git init -q --bare "$priv"
git -C "$REPO" remote add private "$priv"
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "readme"
expect_ok origin main
plant_file "secret.env"
commit_all "leak"
# Publish to the private remote only, as if the hook was bypassed there.
git -C "$REPO" push --no-verify private HEAD:refs/heads/leak >/dev/null 2>&1 || die "private publish failed"
git -C "$REPO" rev-parse --verify refs/remotes/private/leak >/dev/null
expect_blocked origin leak "secret.env"
ok "other-remote secret blocked on this remote"

# --- already on this remote: a new branch does not re-block ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "readme"
plant_file "secret.env"
commit_all "leak"
git -C "$REPO" push --no-verify origin HEAD:refs/heads/main >/dev/null 2>&1 || die "seeding origin failed"
git -C "$REPO" checkout -q -b feature
expect_ok origin feature
ok "already-published secret does not block a new branch"

# --- force push whose advertised old tip is not in the clone ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "base"
expect_ok origin main
plant_file "secret.env"
commit_all "leak"
local_sha="$(git -C "$REPO" rev-parse HEAD)"
bogus=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
hook_log="$TMP/hook.log"
set +e
(
  cd "$REPO"
  printf 'refs/heads/main %s refs/heads/main %s\n' "$local_sha" "$bogus" |
    .git/hooks/pre-push origin "$BARE"
) >"$hook_log" 2>&1
hook_rc=$?
set -e
[[ "$hook_rc" -ne 0 ]] || die "unknown remote tip with a leak was allowed"
grep -q "possible secret" "$hook_log" || { cat "$hook_log" >&2; die "unknown remote tip did not report a secret"; }
ok "force push over an unknown tip blocked"

# --- deleting a ref is not a publish ---
base_sha="$(git -C "$REPO" rev-parse HEAD~1)"
set +e
(
  cd "$REPO"
  printf 'refs/heads/main %s refs/heads/main %s\n' "$ZERO" "$base_sha" |
    .git/hooks/pre-push origin "$BARE"
) >"$hook_log" 2>&1
hook_rc=$?
set -e
[[ "$hook_rc" -eq 0 ]] || { cat "$hook_log" >&2; die "deleting a ref was blocked"; }
ok "ref deletion allowed"

# --- two refs, clean one first: stdin must not be eaten before the leak ---
new_repo
git -C "$REPO" remote add origin "$BARE"
printf 'hello\n' >"$REPO/readme.txt"
commit_all "clean"
clean_sha="$(git -C "$REPO" rev-parse HEAD)"
git -C "$REPO" checkout -q -b leak
plant_file "secret.env"
commit_all "leak"
leak_sha="$(git -C "$REPO" rev-parse HEAD)"
set +e
(
  cd "$REPO"
  printf 'refs/heads/clean %s refs/heads/clean %s\nrefs/heads/leak %s refs/heads/leak %s\n' \
    "$clean_sha" "$ZERO" "$leak_sha" "$ZERO" |
    .git/hooks/pre-push origin "$BARE"
) >"$hook_log" 2>&1
hook_rc=$?
set -e
[[ "$hook_rc" -ne 0 ]] || die "multi-ref push scanned only the clean ref"
grep -q "secret.env" "$hook_log" || { cat "$hook_log" >&2; die "multi-ref push did not name secret.env"; }
ok "multi-ref push scans the later ref"

# --- scrump missing: warn and allow (documented) ---
new_repo
git -C "$REPO" remote add origin "$BARE"
plant_file "secret.env"
commit_all "leak"
set +e
env PATH="/usr/bin:/bin" git -C "$REPO" push origin HEAD:refs/heads/main >"$hook_log" 2>&1
hook_rc=$?
set -e
[[ "$hook_rc" -eq 0 ]] || { cat "$hook_log" >&2; die "missing scrump should allow the push"; }
grep -q "scrump not installed" "$hook_log" || { cat "$hook_log" >&2; die "missing scrump did not warn"; }
ok "missing scrump warns and allows"

ok "pre-push hook"
