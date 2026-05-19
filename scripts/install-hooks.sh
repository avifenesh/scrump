#!/usr/bin/env bash
# Enable repo-managed git hooks. Run once after cloning.
#
# Equivalent to: `git config core.hooksPath scripts/git-hooks`
# (local to this repo; never touches your global git config).

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

git config core.hooksPath scripts/git-hooks
chmod +x scripts/git-hooks/* scripts/install-hooks.sh

echo "hooks: enabled  (core.hooksPath = scripts/git-hooks)"
echo "active hooks:"
for h in scripts/git-hooks/*; do
    [[ -f "$h" ]] && printf '  - %s\n' "$(basename "$h")"
done
