#!/usr/bin/env bash
# Updates this machine's snapshot in security-watch. Manual action.
#
# Syncs the repo, ensures Trivy is installed, scans repositories and installed
# packages, writes snapshots/<machine>.json, then commits and pushes.
#
# Re-run when dependencies moved or after a system update. Not needed daily:
# the watch reads the snapshot and flags it once it goes stale.
#
#   ./scan.sh
#   ./scan.sh --machine fixe-arch --role "Arch desktop"
#   ./scan.sh --no-push

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$ROOT_DIR/agent"
MACHINE=""
ROLE=""
PUSH=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --machine) MACHINE="$2"; shift 2 ;;
        --role)    ROLE="$2"; shift 2 ;;
        --no-push) PUSH=0; shift ;;
        *) echo "Option inconnue : $1" >&2; exit 2 ;;
    esac
done

step() { printf '\033[36m[*]\033[0m %s\n' "$1"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$1"; }

PYTHON="$(command -v python3 || command -v python || true)"
[[ -n "$PYTHON" ]] || { echo "Python 3 introuvable." >&2; exit 1; }

# Pull other machines' snapshots first so the final push does not conflict.
step "Synchronisation du depot"
git -C "$ROOT_DIR" pull --rebase --autostash >/dev/null 2>&1 \
    || warn "git pull a echoue — on continue, le push pourra demander une resolution"

step "Verification de Trivy"
if ! command -v trivy >/dev/null 2>&1; then
    warn "Trivy absent"
    if command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --needed --noconfirm trivy
    elif command -v dnf >/dev/null 2>&1 && dnf info trivy >/dev/null 2>&1; then
        sudo dnf install -y trivy
    else
        # Official Aqua installer, into ~/.local/bin, no sudo required.
        mkdir -p "$HOME/.local/bin"
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | sh -s -- -b "$HOME/.local/bin"
        export PATH="$HOME/.local/bin:$PATH"
    fi
fi
command -v trivy >/dev/null 2>&1 || { echo "Trivy toujours introuvable." >&2; exit 1; }
ok "Trivy : $(command -v trivy)"

# Trivy has no Arch support: the agent falls back to pacman for the package
# inventory, and matching happens later against security.archlinux.org.
if [[ -r /etc/os-release ]] && grep -qiE '^ID=(arch|manjaro|endeavouros|garuda|cachyos|artix)' /etc/os-release; then
    ok "Distribution Arch detectee — inventaire des paquets via pacman"
fi

if [[ ! -f "$AGENT_DIR/config.json" ]]; then
    cp "$AGENT_DIR/config.example.json" "$AGENT_DIR/config.json"
    ok "config.json cree depuis l'exemple"
    warn "Renseigne machine.label pour distinguer ce poste des autres"
fi

step "Scan en cours (quelques minutes au premier passage)"
ARGS=("$AGENT_DIR/agent.py")
[[ -n "$MACHINE" ]] && ARGS+=(--machine "$MACHINE")
[[ -n "$ROLE" ]] && ARGS+=(--role "$ROLE")
[[ "$PUSH" -eq 1 ]] && ARGS+=(--push)

set +e
"$PYTHON" "${ARGS[@]}"
CODE=$?
set -e

echo
if [[ $CODE -eq 0 ]]; then
    ok "Snapshot a jour. La veille quotidienne s'appuiera dessus."
else
    warn "Le scan s'est termine avec le code $CODE — relis les avertissements ci-dessus."
fi
exit $CODE
