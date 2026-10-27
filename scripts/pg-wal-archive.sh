#!/usr/bin/env bash
# QODIQA PostgreSQL WAL Archive Script
#
# The archive_command target PostgreSQL invokes on every completed WAL
# segment (and, via archive_timeout, even under zero write load — see the
# postgresql.conf prerequisites below). Before this script existed, the
# fastest PostgreSQL-wide recovery point was whatever the periodic
# pg_basebackup snapshot (scripts/pg-backup.sh incremental, every 6h) or the
# hourly qodiqa-dr-backup job produced — this is what turns that into a
# continuously verified 5 minutes for every table PostgreSQL holds,
# including the audit_chain mirror (relevant in the Kubernetes topology,
# where the audit.log FILE itself is unreachable by a standalone backup
# pod — see scripts/backup-audit-log.sh's header comment).
#
# Configure on the PostgreSQL server (postgresql.conf, or the equivalent
# managed-Postgres parameter group — this repo does not own a Postgres
# server manifest; Postgres itself is external/managed here, same
# assumption scripts/pg-backup.sh's run_incremental_backup() already makes
# about wal_level/archive_mode):
#   wal_level = replica
#   archive_mode = on
#   archive_timeout = 300          # forces a segment switch at least every 5 min, even idle
#   archive_command = '/opt/qodiqa/scripts/pg-wal-archive.sh %p %f'
#
# Usage (PostgreSQL invokes this form on every WAL segment):
#   ./scripts/pg-wal-archive.sh <%p full-path-to-wal-file> <%f wal-filename>
#
# Usage (scheduler/operator invokes this form to prove archiving is alive —
# see deploy/systemd/qodiqa-audit-log-backup-verify.timer's sibling
# deploy/kubernetes/base/backup-cronjobs.yaml's qodiqa-pg-backup-verify-wal
# CronJob, both every 5 minutes):
#   ./scripts/pg-wal-archive.sh --verify
#
# Required / relevant env vars:
#   QODIQA_WAL_ARCHIVE_DIR             — where archived segments land
#                                         (default: /var/backups/qodiqa/wal-archive)
#   QODIQA_WAL_ARCHIVE_RETAIN_DAYS     — age-based retention / PITR window (default: 7)
#   QODIQA_WAL_ARCHIVE_TIMEOUT_SECONDS — must match postgresql.conf's archive_timeout (default: 300)
#   QODIQA_WAL_ARCHIVE_MAX_AGE_SECONDS — --verify fails closed if the newest
#                                         archived segment is older than this
#                                         (default: 600 = 2x archive_timeout)
#   QODIQA_WAL_ARCHIVE_METRICS_FILE    — separate from QODIQA_BACKUP_METRICS_FILE
#                                         so a high-frequency per-segment
#                                         invocation never races pg-backup.sh's
#                                         writer (default:
#                                         ${QODIQA_WAL_ARCHIVE_DIR}/metrics/qodiqa_wal_archive.prom)
#   QODIQA_BACKUP_HMAC_KEY             — same integrity-seal key pg-backup.sh uses
#   ALERT_WEBHOOK_URL                  — optional; --verify only. Per-segment
#                                         alerting on every WAL switch would be
#                                         alert-fatigue noise, not signal — only
#                                         the staleness/integrity check alerts.
#
# Restore: see `scripts/pg-backup.sh pitr-restore` for the bounded,
# prepare-and-instruct point-in-time-recovery helper that consumes this
# directory's output alongside a pg_basebackup base backup.

# PL13-03: -E so the --verify ERR trap (installed in Main below) also covers
# failures inside run_verify — without it bash ran no trap for a failing command inside a function.
set -Eeuo pipefail

# ── Configuration ────────────────────────────────────────────────────────

ARCHIVE_DIR="${QODIQA_WAL_ARCHIVE_DIR:-/var/backups/qodiqa/wal-archive}"
RETAIN_DAYS="${QODIQA_WAL_ARCHIVE_RETAIN_DAYS:-7}"
ARCHIVE_TIMEOUT_SECONDS="${QODIQA_WAL_ARCHIVE_TIMEOUT_SECONDS:-300}"
MAX_AGE_SECONDS="${QODIQA_WAL_ARCHIVE_MAX_AGE_SECONDS:-600}"
HMAC_KEY="${QODIQA_BACKUP_HMAC_KEY:-}"
ALERT_URL="${ALERT_WEBHOOK_URL:-}"
METRICS_FILE="${QODIQA_WAL_ARCHIVE_METRICS_FILE:-${ARCHIVE_DIR}/metrics/qodiqa_wal_archive.prom}"
LOG_FILE="${ARCHIVE_DIR}/archive-audit.jsonl"

mkdir -p "${ARCHIVE_DIR}"

# ── Helpers ──────────────────────────────────────────────────────────────

log_json() {
  local level="$1"
  local event="$2"
  shift 2
  local extra="${*:-}"
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"level\":\"${level}\",\"event\":\"${event}\"${extra:+,${extra}}}" \
    | tee -a "${LOG_FILE}" >/dev/null
}

# Emits every metric name on every call (a plain textfile-collector file has
# no partial-update semantics) — whichever caller (per-segment archive vs.
# the 5-minute --verify check) ran most recently wins for the fields it
# doesn't know; both trend toward the same conclusion in practice, and
# node_exporter scrapes on its own interval regardless.
write_wal_metrics() {
  local archive_success="$1" verify_success="${2:--1}" age_seconds="${3:-0}"
  {
    mkdir -p "$(dirname "${METRICS_FILE}")" 2>/dev/null
    local tmp="${METRICS_FILE}.$$.tmp"
    {
      echo "qodiqa_wal_archive_success ${archive_success}"
      echo "qodiqa_wal_archive_last_segment_timestamp_seconds $(date -u +%s)"
      if [[ "${verify_success}" != "-1" ]]; then
        echo "qodiqa_wal_archive_verify_success ${verify_success}"
        echo "qodiqa_wal_archive_verify_age_seconds ${age_seconds}"
      fi
    } > "${tmp}" && mv -f "${tmp}" "${METRICS_FILE}"
  } || true
}

# PL13-13: JSON-escape a value for the structured log line and the webhook body. The
# ERR-trap message embeds ${BASH_COMMAND}, which for e.g. a failing pg_dump contains double quotes
# (--file="${DUMP_PARTIAL}"); unescaped, that made the BACKUP_FAILED log line invalid JSON and the webhook body
# invalid JSON, so the receiver rejected the alert and `|| true` hid it.
# (Pattern and replacement are quoted variables: with bash 5.2's patsub_replacement an unquoted `\\\\` replacement
# collapses to ONE backslash, so the naive form silently failed to escape backslashes — measured on bash 5.2 and 5.3.)
json_escape() {
  local s="$1" bs='\'
  s="${s//"$bs"/"$bs$bs"}"; s="${s//\"/"$bs\""}"
  s="${s//$'\n'/"${bs}n"}"; s="${s//$'\r'/"${bs}r"}"; s="${s//$'\t'/"${bs}t"}"
  printf '%s' "${s}"
}

alert_failure() {
  local msg; msg="$(json_escape "$1")"
  log_json "ERROR" "WAL_ARCHIVE_VERIFY_FAILED" "\"message\":\"${msg}\""
  write_wal_metrics 0 0 0
  # PL13-05: a placeholder / non-http(s) value is treated as unset and said so (the shipped
  # Kubernetes Secret carries a REPLACE_WITH_… placeholder — fixed pg-backup.sh only), and the URL (which
  # embeds the webhook token) reaches curl as a config file on stdin, never on argv (ps / /proc/<pid>/cmdline).
  if [[ -n "${ALERT_URL}" && ( "${ALERT_URL}" == *REPLACE_WITH* || ! "${ALERT_URL}" =~ ^https?:// ) ]]; then
    log_json "WARN" "ALERT_WEBHOOK_PLACEHOLDER" "\"message\":\"ALERT_WEBHOOK_URL is a placeholder or not an http(s) URL — no alert was sent\""
  elif [[ -n "${ALERT_URL}" ]]; then
    local url; url="$(json_escape "${ALERT_URL}")"   # curl-config quoting = JSON's for \\ and \" (PL13-13)
    printf 'url = "%s"\n' "${url}" | curl -s -K - -X POST -H 'Content-type: application/json' \
      -d "{\"text\":\"🚨 QODIQA WAL archiving FAILED verification on $(hostname): ${msg}\"}" || true
  fi
}

# follow-up: the same key-off-argv HMAC as scripts/pg-backup.sh hmac_hex() — the
# former `openssl dgst -sha256 -hmac "$(cat)"` put the seal key in openssl's argv (visible via ps / /proc/<pid>/cmdline;
# this script runs every few minutes). Byte-identical output (trailing newlines of the key stripped, lowercase hex),
# so existing seals still verify. Fails closed if node is missing (no fallback to the argv form).
hmac_hex() {
  command -v node >/dev/null 2>&1 || { echo "hmac_hex: node is required to compute the HMAC seal without exposing the key on a command line" >&2; return 1; }
  QODIQA_SEAL_HMAC_KEY="${HMAC_KEY}" node -e '
    const crypto = require("crypto"), fs = require("fs");
    const key = String(process.env.QODIQA_SEAL_HMAC_KEY || "").replace(/\n+$/, "");
    if (!key) { console.error("hmac_hex: empty key"); process.exit(1); }
    const h = crypto.createHmac("sha256", Buffer.from(key, "utf8"));
    fs.createReadStream(process.argv[1])
      .on("data", (d) => h.update(d))
      .on("end", () => process.stdout.write(h.digest("hex") + "\n"))
      .on("error", (e) => { console.error("hmac_hex: " + e.message); process.exit(1); });
  ' "$1"
}

# PL13-06: the seal is written to a temporary name, flushed and renamed — a crash can no longer leave a truncated .seal.
seal_backup() {
  local backup_file="$1"
  local seal_file="${backup_file}.seal"
  local tmp="${seal_file}.$$.tmp"
  if [[ -z "${HMAC_KEY}" ]]; then
    sha256sum "${backup_file}" | awk '{print $1}' > "${tmp}"
  else
    hmac_hex "${backup_file}" > "${tmp}"
  fi
  flush_file "${tmp}"
  mv -f "${tmp}" "${seal_file}"
}

# PL13-06: PostgreSQL recycles a WAL segment as soon as archive_command returns 0, so the archived copy must be on
# stable storage BEFORE that ("Setting Up WAL Archiving" in the PostgreSQL docs). gzip + mv alone left it in the page
# cache: a host crash after the ack could lose a segment PostgreSQL no longer has — a silent hole in PITR.
flush_file() {
  sync "$1" 2>/dev/null || sync
}

verify_seal() {
  local backup_file="$1"
  local seal_file="${backup_file}.seal"
  [[ -f "${seal_file}" ]] || return 1
  local expected; expected="$(cat "${seal_file}")"
  local actual
  if [[ -z "${HMAC_KEY}" ]]; then
    actual="$(sha256sum "${backup_file}" | awk '{print $1}')"
  else
    actual="$(hmac_hex "${backup_file}")" || actual=""
  fi
  [[ "${expected}" == "${actual}" ]]
}

# ── Per-segment archiving (called by PostgreSQL's archive_command) ──────

archive_segment() {
  local src_path="$1"     # %p — full path to the WAL file to archive
  local wal_filename="$2" # %f — just the filename

  if [[ -z "${src_path}" || -z "${wal_filename}" ]]; then
    echo "ERROR: archive_command requires <%p> <%f> arguments" >&2
    exit 1
  fi
  if [[ ! -f "${src_path}" ]]; then
    echo "ERROR: source WAL file does not exist: ${src_path}" >&2
    exit 1
  fi

  local dest="${ARCHIVE_DIR}/${wal_filename}.gz"

  # PostgreSQL's own archive_command contract: never overwrite an existing
  # archived copy of the same segment name with different content — that
  # would silently corrupt point-in-time recovery. If it already exists,
  # succeed only if the content is identical (a safe re-invocation after a
  # retry); otherwise fail loudly instead of overwriting.
  if [[ -f "${dest}" ]]; then
    if gzip -dc "${dest}" 2>/dev/null | cmp -s - "${src_path}"; then
      # PL13-06: a retry after a failure BETWEEN the copy and its seal (e.g. the seal computation failed) used to exit 0
      # here without ever writing the seal, so the segment stayed unsealed for good. Seal it now when needed.
      verify_seal "${dest}" || seal_backup "${dest}"
      exit 0
    fi
    echo "ERROR: refusing to overwrite existing archived segment with different content: ${dest}" >&2
    exit 1
  fi

  local tmp="${dest}.$$.tmp"
  gzip -c "${src_path}" > "${tmp}"
  flush_file "${tmp}"
  mv -f "${tmp}" "${dest}"
  seal_backup "${dest}"
  flush_file "${ARCHIVE_DIR}"

  write_wal_metrics 1
}

# ── Verification / staleness check ────────────────────────────────────────

run_verify() {
  # PL13-03: `|| true` — with no segment at all `ls` exits non-zero, pipefail failed the assignment and set -e ended
  # the script SILENTLY (exit 2: no WAL_ARCHIVE_VERIFY_FAILED, no alert, no metric) in exactly the
  # "archive_command was never configured" case this check exists to report.
  local latest; latest=$(ls -t "${ARCHIVE_DIR}"/*.gz 2>/dev/null | head -1 || true)
  if [[ -z "${latest}" ]]; then
    alert_failure "No WAL segment has ever been archived to ${ARCHIVE_DIR} — archive_command may not be configured"
    exit 1   # (exit, not return: a failing top-level call would re-fire the ERR trap — one alert per failure)
  fi

  if ! verify_seal "${latest}"; then
    alert_failure "Seal verification FAILED for newest WAL segment ${latest}"
    exit 1   # (exit, not return: a failing top-level call would re-fire the ERR trap — one alert per failure)
  fi
  if ! gzip -t "${latest}" 2>/dev/null; then
    alert_failure "Newest WAL segment is not a valid gzip archive: ${latest}"
    exit 1   # (exit, not return: a failing top-level call would re-fire the ERR trap — one alert per failure)
  fi

  # Staleness — proves continuous archiving is actually happening, not just
  # configured once. archive_timeout forces a segment switch at least every
  # ARCHIVE_TIMEOUT_SECONDS even under zero write load, so a gap bigger than
  # MAX_AGE_SECONDS means the archiver has stalled (a classic, dangerous,
  # silent PostgreSQL failure mode this check exists specifically to catch).
  local latest_epoch; latest_epoch=$(stat -c%Y "${latest}" 2>/dev/null || stat -f%m "${latest}")
  local now_epoch; now_epoch=$(date -u +%s)
  local age_seconds=$((now_epoch - latest_epoch))
  if [[ "${age_seconds}" -gt "${MAX_AGE_SECONDS}" ]]; then
    alert_failure "WAL archiving is stale — newest segment ${latest} is ${age_seconds}s old (max ${MAX_AGE_SECONDS}s, configured archive_timeout=${ARCHIVE_TIMEOUT_SECONDS}s) — archive_command may have stopped firing"
    exit 1   # (exit, not return: a failing top-level call would re-fire the ERR trap — one alert per failure)
  fi

  # Age-based retention (rolling PITR window) — pruned here rather than
  # per-segment, since this runs at a fixed, moderate 5-minute cadence.
  local pruned=0
  while IFS= read -r f; do
    [[ -z "${f}" ]] && continue
    rm -f "${f}" "${f}.seal"
    pruned=$((pruned + 1))
  done < <(find "${ARCHIVE_DIR}" -maxdepth 1 -name "*.gz" -mtime "+${RETAIN_DAYS}" 2>/dev/null)

  log_json "INFO" "WAL_ARCHIVE_VERIFY_OK" \
    "\"file\":\"${latest}\",\"ageSeconds\":${age_seconds},\"prunedCount\":${pruned}"
  write_wal_metrics 1 1 "${age_seconds}"
}

# ── Main ───────────────────────────────────────────────────────────────

if [[ "${1:-}" == "--verify" ]]; then
  # PL13-03: an unexpected failure of the check itself alerts too. (The archive_command form deliberately has no
  # trap: PostgreSQL itself logs and retries a failed archive_command.)
  # PL13-03: with errtrace (set -E) a failing $(...) would also run this trap INSIDE the command substitution (its
  # alert line captured into the variable, the webhook posted twice); the failure always propagates to the parent's
  # assignment, so only the top-level shell (BASH_SUBSHELL 0) alerts — exactly once.
  trap 'if [[ ${BASH_SUBSHELL} -eq 0 ]]; then alert_failure "Unexpected error on line ${LINENO}: ${BASH_COMMAND}"; fi' ERR
  run_verify
else
  archive_segment "${1:-}" "${2:-}"
fi
