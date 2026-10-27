#!/usr/bin/env bash
# Secret Scanning —
#
# Runs gitleaks against the repository to detect secrets committed to git
# history or present in the working tree.
#
# Usage:
#   ./scripts/scan-secrets.sh [--staged | --uncommitted | --full]
#
# Modes:
#   --staged       Scan only staged changes (pre-commit hook mode)
#   --uncommitted  Scan working tree including unstaged changes
#   --full         Scan entire git history (CI mode, slow)
#   (no flag)      Default: scan HEAD commit + staged + uncommitted
#
# Exit codes:
#   0 — clean
#   1 — secrets detected or gitleaks not found
#
# Requirements:
#   gitleaks >= 8.0.0 installed and on PATH
#   (Install: https://github.com/gitleaks/gitleaks#installing)
#
# Configuration:
#   .gitleaks.toml in the repository root

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${REPO_ROOT}/.gitleaks.toml"
REPORT="${REPO_ROOT}/gitleaks-report.json"

# ── Require gitleaks ─────────────────────────────────────────────────────────
if ! command -v gitleaks &>/dev/null; then
  echo "[ERROR] gitleaks not found on PATH."
  echo "  Install: https://github.com/gitleaks/gitleaks#installing"
  echo "  Or via Homebrew: brew install gitleaks"
  echo "  Or via Docker: docker run --rm ghcr.io/gitleaks/gitleaks:latest"
  exit 1
fi

GITLEAKS_VERSION=$(gitleaks version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
echo "[INFO] gitleaks ${GITLEAKS_VERSION}"

# ── Parse mode ───────────────────────────────────────────────────────────────
MODE="${1:---default}"

# ── Run scan ─────────────────────────────────────────────────────────────────
COMMON_ARGS=(
  "--config=${CONFIG}"
  "--report-format=json"
  "--report-path=${REPORT}"
  "--exit-code=1"
  "--verbose"
)

case "${MODE}" in
  --staged)
    echo "[INFO] Scanning staged changes (pre-commit mode)"
    gitleaks protect --staged "${COMMON_ARGS[@]}" --source="${REPO_ROOT}"
    ;;
  --uncommitted)
    echo "[INFO] Scanning working tree (uncommitted changes)"
    gitleaks protect "${COMMON_ARGS[@]}" --source="${REPO_ROOT}"
    ;;
  --full)
    echo "[INFO] Scanning full git history (this may take a while)"
    gitleaks detect "${COMMON_ARGS[@]}" --source="${REPO_ROOT}"
    ;;
  *)
    echo "[INFO] Scanning HEAD + uncommitted changes (default)"
    # detect scans committed history; protect scans working tree
    gitleaks detect "${COMMON_ARGS[@]}" --source="${REPO_ROOT}" && \
    gitleaks protect "${COMMON_ARGS[@]}" --source="${REPO_ROOT}"
    ;;
esac

SCAN_EXIT=$?

if [ ${SCAN_EXIT} -eq 0 ]; then
  echo "[PASS] No secrets detected"
  rm -f "${REPORT}"
  exit 0
else
  echo "[FAIL] Secrets detected — see ${REPORT}"
  # Print findings summary (do not print secret values)
  if [ -f "${REPORT}" ]; then
    node -e "
      const r = JSON.parse(require('fs').readFileSync('${REPORT}', 'utf8'));
      (r || []).forEach(f => {
        console.error(\`  Rule: \${f.RuleID} | File: \${f.File}:\${f.StartLine}\`);
      });
    " 2>/dev/null || true
  fi
  exit 1
fi
