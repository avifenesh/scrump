#!/usr/bin/env bash
# Master e2e gate: runs phase 0 + 1..6 in order.
#
# Exits 0 only when every phase script succeeds.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    _RED=$(tput setaf 1); _GRN=$(tput setaf 2); _BLU=$(tput setaf 4); _RST=$(tput sgr0)
else
    _RED=""; _GRN=""; _BLU=""; _RST=""
fi

run_phase() {
    local script="$1"
    printf '\n%s================ %s ================%s\n' "$_BLU" "$script" "$_RST"
    if bash "$script"; then
        printf '%s[PASS]%s %s\n' "$_GRN" "$_RST" "$script"
    else
        printf '%s[ABORT]%s %s\n' "$_RED" "$_RST" "$script"
        exit 1
    fi
}

run_phase ./e2e.sh             # phase 0
run_phase ./e2e_phase1.sh
run_phase ./e2e_phase2.sh
run_phase ./e2e_phase3.sh
run_phase ./e2e_phase4.sh
run_phase ./e2e_phase5.sh
run_phase ./e2e_phase6.sh
run_phase ./e2e_phase7.sh

printf '\n%s[OK]%s every phase gate green\n' "$_GRN" "$_RST"
