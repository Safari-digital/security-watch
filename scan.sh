#!/usr/bin/env bash
# Audit one or more repositories locally.
#
# Installs Trivy if it is missing, then runs watch/audit.py against each path
# and leaves a Markdown report next to its JSON in out/. Nothing is committed
# and nothing is pushed: the output describes a real dependency tree, so where
# it goes is your call.
#
# Same audit as CI, minus the deduplication and the issue. Hand the JSON to an
# agent afterwards if you want the summary -- see docs/claude-routine.md.
#
#   ./scan.sh ../some-project
#   ./scan.sh ../front ../api --out-dir ~/audits
#   ./scan.sh . --name "Safari-digital/safaridigital.fr" --no-dotnet

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$ROOT_DIR/out"
NAME=""
EXTRA=()
REPOS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir)   OUT_DIR="$2"; shift 2 ;;
        --name)      NAME="$2"; shift 2 ;;
        --no-dotnet) EXTRA+=(--no-dotnet); shift ;;
        --timeout)   EXTRA+=(--timeout "$2"); shift 2 ;;
        -h|--help)   sed -n '2,15p' "$0" | sed 's/^# \?//'; exit 0 ;;
        -*)          echo "Option inconnue : $1" >&2; exit 2 ;;
        *)           REPOS+=("$1"); shift ;;
    esac
done

[[ ${#REPOS[@]} -gt 0 ]] || REPOS=(".")
if [[ -n "$NAME" && ${#REPOS[@]} -gt 1 ]]; then
    echo "--name ne vaut que pour un seul depot." >&2
    exit 2
fi

step() { printf '\033[36m[*]\033[0m %s\n' "$1"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$1"; }

# Each candidate is run, not just located: on Windows `python3` resolves to the
# Microsoft Store stub, which exists on PATH and fails the moment it is called.
PYTHON=""
for candidate in python3 python py; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
        >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done
[[ -n "$PYTHON" ]] || { echo "Python >= 3.9 introuvable." >&2; exit 1; }

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

mkdir -p "$OUT_DIR"
DATE="$(date -u +%Y-%m-%d)"
FAILED=0

for repo in "${REPOS[@]}"; do
    [[ -d "$repo" ]] || { warn "$repo n'est pas un repertoire — ignore"; FAILED=1; continue; }
    label="${NAME:-$(basename "$(cd "$repo" && pwd)")}"
    # Slashes in an org/repo name would open a directory that is not wanted.
    slug="$(printf '%s' "$label" | tr '/ ' '--' | tr -cd '[:alnum:]._-')"

    step "Audit de $label"
    args=("$ROOT_DIR/watch/audit.py" --repo "$repo"
          --out-md  "$OUT_DIR/$slug-$DATE.md"
          --out-json "$OUT_DIR/$slug-$DATE.findings.json")
    [[ -n "$NAME" ]] && args+=(--name "$NAME")
    [[ ${#EXTRA[@]} -gt 0 ]] && args+=("${EXTRA[@]}")

    set +e
    "$PYTHON" "${args[@]}"
    code=$?
    set -e
    [[ $code -eq 0 ]] || { warn "$label : code $code"; FAILED=1; }
done

echo
if [[ $FAILED -eq 0 ]]; then
    ok "Rapports dans $OUT_DIR"
else
    warn "Termine avec des erreurs — relis les avertissements ci-dessus."
fi
exit $FAILED
