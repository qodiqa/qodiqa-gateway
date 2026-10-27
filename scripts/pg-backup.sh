#!/usr/bin/env bash
# QODIQA PostgreSQL Backup Script
# ─────────────────────────────────────────────────────────────────────────────
# Enterprise-grade backup with:
#   - Full logical backups via pg_dump (custom format, parallel)
#   - Backup verification via pg_restore --list (non-destructive)
#   - HMAC-SHA256 integrity seal
#   - Retention enforcement (configurable)
#   - Structured JSON audit log
#   - Alerting hooks (Slack/PagerDuty webhook — set ALERT_WEBHOOK_URL)
#
# Usage:
#   ./scripts/pg-backup.sh full [daily|weekly|monthly]
#   ./scripts/pg-backup.sh incremental
#   ./scripts/pg-backup.sh verify [daily|weekly|monthly]
#   ./scripts/pg-backup.sh restore [backup_file]
#   ./scripts/pg-backup.sh pitr-restore <basebackup.tar.gz> <target_pgdata_dir> [target_time|latest]
#
# `pitr-restore` is the point-in-time-recovery
# counterpart to continuous WAL archiving (scripts/pg-wal-archive.sh): it
# extracts a pg_basebackup produced by `incremental` above into a fresh
# PGDATA directory and wires PostgreSQL's own recovery.signal/
# restore_command mechanism to replay archived WAL up to a target time (or
# "latest"). It deliberately stops at "PGDATA is prepared" and prints the
# exact start command rather than starting the server itself — this repo
# treats PostgreSQL process/service lifecycle as environment-specific and
# operator-owned throughout (the same boundary run_incremental_backup()'s
# own prerequisites already document); full one-command orchestration is a
# disclosed scope boundary, not an oversight (see DR-4-REMEDIATION-REPORT.md).
#
# The optional TIER argument to `full`/`verify` selects a
# COUNT-based retention tier — the backup is written into
# ${QODIQA_BACKUP_DIR}/full/<tier>/ and only the QODIQA_BACKUP_RETAIN_<TIER>
# most recent files in that directory are kept, independent of any other
# tier. Omitting TIER preserves the original untiered, day-cutoff behavior
# (QODIQA_BACKUP_RETAIN_DAYS) exactly as before this remediation — existing
# callers with no tier argument are unaffected.
#
# Required env vars:
#   PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD (or PGPASSFILE)
#   QODIQA_BACKUP_DIR     — base directory for backup files (default: /var/backups/qodiqa)
#   QODIQA_BACKUP_RETAIN_DAYS — days to keep untiered full backups (default: 30)
#   QODIQA_BACKUP_RETAIN_DAILY   — count of daily-tier backups to keep (default: 7)
#   QODIQA_BACKUP_RETAIN_WEEKLY  — count of weekly-tier backups to keep (default: 4)
#   QODIQA_BACKUP_RETAIN_MONTHLY — count of monthly-tier backups to keep (default: 12)
#   QODIQA_BACKUP_HMAC_KEY    — 32+ char secret for backup integrity seal
#   QODIQA_BACKUP_ENCRYPTION_KEY — when set, every full backup is encrypted at rest (openssl AES-256-CBC,
#                                 PBKDF2-SHA256 200 000 iterations, random salt) and the HMAC seal is computed over
#                                 the CIPHERTEXT (encrypt-then-MAC), so QODIQA_BACKUP_HMAC_KEY is then required.
#                                 The plaintext dump never outlives the run. Use a key distinct from the HMAC key.
#   QODIQA_BACKUP_REQUIRE_ENCRYPTION — "true": refuse to write an unencrypted backup (fail closed, alert). The
#                                 shipped Kubernetes backup ConfigMap sets it.: this is now ALSO
#                                 THE DEFAULT — a standalone run without a key no longer writes plaintext.
#   QODIQA_BACKUP_ALLOW_PLAINTEXT — "true" is the explicit opt-in to an UNENCRYPTED backup (and to verifying /
#                                 restoring one), for throwaway targets and legacy plaintext backups only. Logged as a
#                                 WARN (BACKUP_PLAINTEXT_OPT_IN) on every run. It never overrides an explicit
#                                 QODIQA_BACKUP_REQUIRE_ENCRYPTION=true.
#   QODIQA_BACKUP_OFFSITE_COMMAND — optional; after a sealed backup is written, this command is run with the
#                                 backup file and its .seal as its two arguments (e.g. a wrapper around
#                                 `aws s3 cp` / `rclone copy` to customer-held storage). A non-zero exit fails the
#                                 run (alert). The destination and its credentials are the operator's.
#   QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE — OA4-F1: `restore` refuses to run as a superuser (pg_restore --no-owner
#                                 makes the restoring role own every SECURITY DEFINER function). "true" overrides it
#                                 for a throwaway target only (e.g. a CI service container); it is logged as a WARN.
#   QODIQA_BACKUP_METRICS_FILE — path to write Prometheus textfile-collector
#                                 metrics after each run (default:
#                                 ${QODIQA_BACKUP_DIR}/metrics/qodiqa_pg_backup.prom).
#                                 Written atomically; safe to leave unset (no-op).
#   ALERT_WEBHOOK_URL         — optional Slack/PagerDuty URL for failure alerts
#
# Timezone: this script always timestamps and logs in UTC — that is
# unaffected by scheduling. The WALL-CLOCK time a schedule fires at is
# configured entirely at the scheduler layer, never in this script: a
# Kubernetes CronJob sets `spec.timeZone` (Kubernetes >= 1.27), a systemd
# timer sets `Environment=TZ=...` alongside its `OnCalendar=` expression. See
# deploy/kubernetes/base/backup-cronjobs.yaml and deploy/systemd/*.timer.
#
# Cron / systemd-timer schedule (see deploy/kubernetes/base/backup-cronjobs.yaml
# and deploy/systemd/ for the actual production scheduling — this is the
# equivalent plain-cron form for hosts without either):
#   # Daily full backup: 02:00
#   0 2 * * *   /opt/qodiqa/scripts/pg-backup.sh full daily    >> /var/log/qodiqa-backup.log 2>&1
#   # Weekly full backup: Sunday 03:00
#   0 3 * * 0   /opt/qodiqa/scripts/pg-backup.sh full weekly   >> /var/log/qodiqa-backup.log 2>&1
#   # Monthly full backup: 1st of month 04:00
#   0 4 1 * *   /opt/qodiqa/scripts/pg-backup.sh full monthly  >> /var/log/qodiqa-backup.log 2>&1
#   # Incremental (WAL-based via pg_basebackup streaming): every 6 hours
#   0 */6 * * * /opt/qodiqa/scripts/pg-backup.sh incremental   >> /var/log/qodiqa-backup.log 2>&1
#   # Verify last daily backup: 02:30 (after the daily backup completes)
#   30 2 * * *  /opt/qodiqa/scripts/pg-backup.sh verify daily  >> /var/log/qodiqa-backup.log 2>&1

# PL13-03: -E (errtrace). Without it bash does NOT run the ERR trap below for a
# failure INSIDE a function — and every mode runs in one (run_full_backup, run_verify, …). A failing pg_dump
# therefore exited 1 SILENTLY: no
# BACKUP_FAILED line, no webhook alert and no success=0 metric, so QodiqaBackupFailed could never fire for it.
set -Eeuo pipefail

# ── Configuration ──────────────────────────────────────────────────────────────

BACKUP_DIR="${QODIQA_BACKUP_DIR:-/var/backups/qodiqa}"
RETAIN_DAYS="${QODIQA_BACKUP_RETAIN_DAYS:-30}"
RETAIN_DAILY="${QODIQA_BACKUP_RETAIN_DAILY:-7}"
RETAIN_WEEKLY="${QODIQA_BACKUP_RETAIN_WEEKLY:-4}"
RETAIN_MONTHLY="${QODIQA_BACKUP_RETAIN_MONTHLY:-12}"
HMAC_KEY="${QODIQA_BACKUP_HMAC_KEY:-}"
ENC_KEY_SET="${QODIQA_BACKUP_ENCRYPTION_KEY:+yes}"
# encryption is REQUIRED unless plaintext is explicitly opted into. The former default
# (`${QODIQA_BACKUP_REQUIRE_ENCRYPTION:-false}`) made any standalone run without a key — a systemd host, an operator
# shell — silently write every tenant's data in plaintext. An explicit QODIQA_BACKUP_REQUIRE_ENCRYPTION=true always wins.
ALLOW_PLAINTEXT="${QODIQA_BACKUP_ALLOW_PLAINTEXT:-false}"
if [[ "${QODIQA_BACKUP_REQUIRE_ENCRYPTION:-}" == "true" || "${ALLOW_PLAINTEXT}" != "true" ]]; then
  REQUIRE_ENC="true"
else
  REQUIRE_ENC="false"
fi
OFFSITE_CMD="${QODIQA_BACKUP_OFFSITE_COMMAND:-}"
ALERT_URL="${ALERT_WEBHOOK_URL:-}"
METRICS_FILE="${QODIQA_BACKUP_METRICS_FILE:-${BACKUP_DIR}/metrics/qodiqa_pg_backup.prom}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TS_HUMAN="$(date -u +%Y-%m-%d\ %H:%M:%S\ UTC)"
LOG_FILE="${BACKUP_DIR}/backup-audit.jsonl"
PARALLEL_JOBS="${QODIQA_BACKUP_JOBS:-4}"
MODE="${1:-full}"
TIER="${2:-}"

# ── Helpers ───────────────────────────────────────────────────────────────────

log_json() {
  local level="$1"
  local event="$2"
  shift 2
  local extra="${*:-}"
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"level\":\"${level}\",\"event\":\"${event}\"${extra:+,${extra}}}" \
    | tee -a "${LOG_FILE}"
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
  log_json "ERROR" "BACKUP_FAILED" "\"message\":\"${msg}\""
  write_prom_metrics "${MODE}" "${TIER}" 0 0
  # the shipped Kubernetes Secret carries a REPLACE_WITH_… placeholder for the
  # optional alert-webhook-url, so `optional: true` never yields "unset" and every alert was POSTed to a non-URL and
  # silently dropped (`|| true`). A placeholder / non-http(s) value is now treated as unset — and said so.
  if [[ -n "${ALERT_URL}" && ( "${ALERT_URL}" == *REPLACE_WITH* || ! "${ALERT_URL}" =~ ^https?:// ) ]]; then
    log_json "WARN" "ALERT_WEBHOOK_PLACEHOLDER" "\"message\":\"ALERT_WEBHOOK_URL is a placeholder or not an http(s) URL — no alert was sent; set a real webhook or remove the key\""
  elif [[ -n "${ALERT_URL}" ]]; then
    post_webhook "${ALERT_URL}" "{\"text\":\"🚨 QODIQA Backup FAILED on $(hostname): ${msg}\"}"
  fi
}

# PL13-05: the webhook URL (Slack/PagerDuty URLs embed their token) is handed to curl as a
# config file on STDIN (`-K -`), never as an argument — argv is readable by every local user via ps /
# /proc/<pid>/cmdline. Best effort: an unreachable webhook never fails the run (|| true, as before).
post_webhook() {
  local url="$1" body="$2"
  url="$(json_escape "${url}")"   # curl-config quoting = JSON's for \\ and \" (PL13-13)
  printf 'url = "%s"\n' "${url}" | curl -s -K - -X POST -H 'Content-type: application/json' -d "${body}" || true
}

# PL13-03: with errtrace (set -E) a failing $(...) would also run this trap INSIDE the command substitution (its
# alert line captured into the variable, the webhook posted twice); the failure always propagates to the parent's
# assignment, so only the top-level shell (BASH_SUBSHELL 0) alerts — exactly once.
trap 'if [[ ${BASH_SUBSHELL} -eq 0 ]]; then alert_failure "Unexpected error on line ${LINENO}: ${BASH_COMMAND}"; fi' ERR

mkdir -p "${BACKUP_DIR}/full" "${BACKUP_DIR}/wal" "${BACKUP_DIR}/verify"

# ── Prometheus textfile-collector metrics ─────────────────
#
# Written atomically (temp file + mv) so node_exporter's textfile collector
# (or any equivalent scrape agent) never observes a partially written file.
# This CronJob/systemd-timer invocation is a short-lived process that cannot
# itself be scraped, so a metrics file is the standard infrastructure-agnostic
# bridge to Prometheus. No-op-safe: a failure to write metrics must never
# fail the backup itself.
#
# ONE FILE PER MODE/TIER. Every mode used to replace the same METRICS_FILE, so the
# 02:30 `verify daily` run erased a failed 02:00 `full daily` run's success=0 (QodiqaBackupFailed self-resolved),
# QodiqaBackupStale rarely had a mode="full" series to evaluate, and the tiers overwrote each other. Each
# (mode, tier) now owns `<METRICS_FILE minus .prom>_<mode>_<tier>.prom`; node_exporter's textfile collector reads
# every *.prom in the directory, so metric names, labels and the shipped alert rules are unchanged. A leftover
# shared file from before this change is renamed to *.prom.superseded (not read by the collector — its series
# would otherwise collide with the per-mode files' identical series).
metrics_file_for() {
  local mode="${1//[^A-Za-z0-9-]/_}" tier="${2:-none}"
  tier="${tier//[^A-Za-z0-9-]/_}"
  echo "${METRICS_FILE%.prom}_${mode}_${tier}.prom"
}
write_prom_metrics() {
  local mode="$1" tier="$2" success="$3" size_bytes="${4:-0}"
  {
    local file; file="$(metrics_file_for "${mode}" "${tier}")"
    mkdir -p "$(dirname "${file}")" 2>/dev/null
    local tmp="${file}.$$.tmp"
    {
      echo "qodiqa_pg_backup_success{mode=\"${mode}\",tier=\"${tier:-none}\"} ${success}"
      echo "qodiqa_pg_backup_last_run_timestamp_seconds{mode=\"${mode}\",tier=\"${tier:-none}\"} $(date -u +%s)"
      echo "qodiqa_pg_backup_size_bytes{mode=\"${mode}\",tier=\"${tier:-none}\"} ${size_bytes}"
    } > "${tmp}" && chmod 0644 "${tmp}" && mv -f "${tmp}" "${file}"   # PL13-04: readable by the textfile collector whatever the umask
    if [[ "${METRICS_FILE}" == *.prom && "${METRICS_FILE}" != "${file}" && -f "${METRICS_FILE}" ]]; then
      mv -f "${METRICS_FILE}" "${METRICS_FILE}.superseded"
    fi
  } || true
}

# ── Tiered (daily/weekly/monthly) count-based retention ──
#
# Keeps only the N most recent *.dump files in `dir` (N = `keep`), pruning
# the rest along with their .seal companion. Purely count-based — unlike the
# legacy QODIQA_BACKUP_RETAIN_DAYS cutoff below, this is what lets a weekly
# or monthly tier keep meaningfully long history without an enormous
# day-count. Only invoked when a TIER argument is supplied (see MODE
# dispatch at the bottom of this file); untiered callers are unaffected.
enforce_tier_retention() {
  local dir="$1" keep="$2" tier="$3"
  local pruned=0
  local f
  while IFS= read -r f; do
    [[ -z "${f}" ]] && continue
    rm -f "${f}" "${f}.seal"
    pruned=$((pruned + 1))
    log_json "INFO" "BACKUP_TIER_PRUNED" "\"file\":\"${f}\",\"tier\":\"${tier}\""
  done < <(ls -t "${dir}"/*.dump "${dir}"/*.dump.enc 2>/dev/null | tail -n "+$((keep + 1))")
  log_json "INFO" "BACKUP_RETENTION_ENFORCED" "\"tier\":\"${tier}\",\"retainCount\":${keep},\"prunedCount\":${pruned}"
}

# ── Encryption at rest ──────────────────────────────────────────────
# The key is passed to openssl through the environment (-pass env:), never on a command line.
OPENSSL_ENC_ARGS=(-aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -salt -pass env:QODIQA_BACKUP_ENCRYPTION_KEY)

encryption_preflight() {
  if [[ -z "${ENC_KEY_SET}" ]]; then
    if [[ "${REQUIRE_ENC}" == "true" ]]; then
      alert_failure "Encryption is required (QODIQA_BACKUP_REQUIRE_ENCRYPTION=true, or the default without QODIQA_BACKUP_ALLOW_PLAINTEXT=true) but QODIQA_BACKUP_ENCRYPTION_KEY is not set — refusing to write an unencrypted backup"
      log_json "ERROR" "BACKUP_ENCRYPTION_REQUIRED" "\"message\":\"no encryption key; nothing was written\""
      exit 1
    fi
    log_json "WARN" "BACKUP_PLAINTEXT_OPT_IN" "\"message\":\"QODIQA_BACKUP_ALLOW_PLAINTEXT=true — this run writes every tenant's data UNENCRYPTED; throwaway targets only\""
    log_json "WARN" "BACKUP_UNENCRYPTED" "\"message\":\"QODIQA_BACKUP_ENCRYPTION_KEY not set — this backup is stored in plaintext\""
    return 0
  fi
  if [[ "${QODIQA_BACKUP_ENCRYPTION_KEY}" == *REPLACE_WITH* || "${#QODIQA_BACKUP_ENCRYPTION_KEY}" -lt 32 ]]; then
    alert_failure "QODIQA_BACKUP_ENCRYPTION_KEY is a placeholder or shorter than 32 characters — refusing to encrypt with a guessable key"
    log_json "ERROR" "BACKUP_ENCRYPTION_KEY_INVALID" "\"message\":\"nothing was written\""
    exit 1
  fi
  if [[ -z "${HMAC_KEY}" ]]; then
    alert_failure "QODIQA_BACKUP_ENCRYPTION_KEY is set but QODIQA_BACKUP_HMAC_KEY is not — an encrypted backup must be authenticated (encrypt-then-MAC)"
    log_json "ERROR" "BACKUP_ENCRYPTION_NEEDS_HMAC" "\"message\":\"nothing was written\""
    exit 1
  fi
  # the seal key gets the same placeholder/length refusal as the encryption key, and must be a separate key.
  if [[ "${HMAC_KEY}" == *REPLACE_WITH* || "${#HMAC_KEY}" -lt 32 || "${HMAC_KEY}" == "${QODIQA_BACKUP_ENCRYPTION_KEY}" ]]; then
    alert_failure "QODIQA_BACKUP_HMAC_KEY is a placeholder, shorter than 32 characters, or equal to the encryption key — refusing to seal with it"
    log_json "ERROR" "BACKUP_HMAC_KEY_INVALID" "\"message\":\"nothing was written\""
    exit 1
  fi
}

# Plaintext that must not be accepted as a backup (a failed encryption, or a crash between pg_dump and encryption) is
# moved here — kept for the operator, never matched by the *.dump / *.dump.enc globs of verify, restore or retention.
QUARANTINE_DIR="${BACKUP_DIR}/quarantine"
quarantine_plaintext() {
  local f="$1" reason="$2"
  mkdir -p "${QUARANTINE_DIR}"; chmod 700 "${QUARANTINE_DIR}"
  local dest; dest="${QUARANTINE_DIR}/$(basename "${f}").plaintext"
  mv -f "${f}" "${dest}"
  chmod 600 "${dest}"
  log_json "ERROR" "BACKUP_PLAINTEXT_QUARANTINED" "\"file\":\"${f}\",\"quarantined\":\"${dest}\",\"reason\":\"${reason}\""
}

# encrypt_in_place <plaintext> → sets ENCRYPTED_FILE to <plaintext>.enc and removes the plaintext, or FAILS THE BACKUP.
# N1: this used to run inside `$(...)`, where bash disables `set -e` and the ERR trap, so a
# failed or truncated openssl run still deleted the plaintext and the caller sealed, copied off-site and logged
# BACKUP_FULL_COMPLETE. It is now called directly, every step's status is checked explicitly, and the plaintext is
# removed only after the ciphertext is written to a temporary name, decrypted back in full and compared by SHA-256.
ENCRYPTED_FILE=""
ENC_PARTIAL=""
encrypt_in_place() {
  local plain="$1" enc="$1.enc"
  ENCRYPTED_FILE=""
  ENC_PARTIAL="${enc}.partial"
  local fail=""
  if ! ( umask 077; openssl enc -e "${OPENSSL_ENC_ARGS[@]}" -in "${plain}" -out "${ENC_PARTIAL}" ); then
    fail="openssl encryption exited non-zero"
  elif [[ ! -s "${ENC_PARTIAL}" ]]; then
    fail="encrypted output is missing or empty"
  else
    local plain_sha dec_sha
    plain_sha="$(sha256sum "${plain}" | awk '{print $1}')" || fail="could not hash the plaintext dump"
    if [[ -z "${fail}" ]] && ! dec_sha="$(set -o pipefail; openssl enc -d "${OPENSSL_ENC_ARGS[@]}" -in "${ENC_PARTIAL}" | sha256sum | awk '{print $1}')"; then
      fail="encrypted output does not decrypt (truncated or corrupt)"
    elif [[ -z "${fail}" && ( -z "${plain_sha}" || "${dec_sha}" != "${plain_sha}" ) ]]; then
      fail="encrypted output does not decrypt to the dump (truncated or corrupt)"
    fi
  fi
  if [[ -n "${fail}" ]]; then
    rm -f "${ENC_PARTIAL}"; ENC_PARTIAL=""
    quarantine_plaintext "${plain}" "encryption failed: ${fail}"
    alert_failure "Backup encryption FAILED for ${plain}: ${fail} — nothing was sealed, copied off-site or reported complete"
    log_json "ERROR" "BACKUP_ENCRYPTION_FAILED" "\"file\":\"${plain}\",\"reason\":\"${fail}\""
    exit 1
  fi
  mv -f "${ENC_PARTIAL}" "${enc}"
  ENC_PARTIAL=""
  rm -f "${plain}"
  ENCRYPTED_FILE="${enc}"
}

# decrypt_to_temp <file.enc> → prints a private temporary plaintext path (caller removes it; see cleanup_tmp)
DECRYPTED_TMP=""
# PL13-04: pg_dump writes to <dump>.partial; only a COMPLETE dump is renamed to <dump>. A run that fails or is killed
# mid-dump used to leave a truncated plaintext <dump> that the *.dump globs of verify / restore / retention counted as
# a backup (a retention slot spent on garbage, a "latest" backup that cannot be restored). The partial plaintext is
# quarantined (never deleted, never matched by those globs) on any exit, and a SIGKILL leftover by the next run.
DUMP_PARTIAL=""
cleanup_tmp() {
  if [[ -n "${DECRYPTED_TMP}" && -f "${DECRYPTED_TMP}" ]]; then rm -f "${DECRYPTED_TMP}"; fi; DECRYPTED_TMP=""
  if [[ -n "${ENC_PARTIAL}" && -f "${ENC_PARTIAL}" ]]; then rm -f "${ENC_PARTIAL}"; fi; ENC_PARTIAL=""
  if [[ -n "${DUMP_PARTIAL}" && -f "${DUMP_PARTIAL}" ]]; then
    quarantine_plaintext "${DUMP_PARTIAL}" "incomplete pg_dump output (the run failed or was interrupted)" || true
  fi
  DUMP_PARTIAL=""
}
trap cleanup_tmp EXIT

# N2: a crash between pg_dump and encryption (or a SIGKILL during verify/restore) leaves
# plaintext behind that no trap can remove. With encryption configured, a full run quarantines such leftovers before it
# starts, and verify/restore refuse plaintext outright when QODIQA_BACKUP_REQUIRE_ENCRYPTION=true.
quarantine_stale_plaintext() {
  local dir="$1" f
  while IFS= read -r f; do
    [[ -z "${f}" ]] && continue
    quarantine_plaintext "${f}" "plaintext dump left by an interrupted run while encryption is configured"
  done < <(ls "${dir}"/*.dump 2>/dev/null || true)
  while IFS= read -r f; do
    [[ -z "${f}" ]] && continue
    rm -f "${f}"
    log_json "WARN" "BACKUP_PARTIAL_CIPHERTEXT_REMOVED" "\"file\":\"${f}\""
  done < <(ls "${dir}"/*.dump.enc.partial 2>/dev/null || true)
}
# PL13-04: an incomplete pg_dump output left by a killed run (no trap runs on SIGKILL / OOM-kill) is plaintext and
# never a backup — quarantined by the next full run whether or not encryption is configured.
quarantine_stale_partial_dumps() {
  local dir="$1" f
  while IFS= read -r f; do
    [[ -z "${f}" ]] && continue
    quarantine_plaintext "${f}" "incomplete pg_dump output left by an interrupted run"
  done < <(ls "${dir}"/*.dump.partial 2>/dev/null || true)
}
sweep_stale_decrypted() {
  [[ -d "${BACKUP_DIR}/tmp" ]] || return 0
  # older than 60 minutes: never a concurrent run's live temp file
  find "${BACKUP_DIR}/tmp" -maxdepth 1 -name 'restore.*' -type f -mmin +60 -exec rm -f {} \; || true
}
# refuse_plaintext_if_required <file> → non-zero (with the reason logged) when encryption is required and <file> is not .enc
refuse_plaintext_if_required() {
  local f="$1"
  if [[ "${REQUIRE_ENC}" == "true" && "${f}" != *.dump.enc ]]; then
    log_json "ERROR" "BACKUP_PLAINTEXT_REFUSED" "\"file\":\"${f}\",\"message\":\"QODIQA_BACKUP_REQUIRE_ENCRYPTION=true: only an encrypted .dump.enc backup is accepted\""
    return 1
  fi
  return 0
}
decrypt_to_temp() {
  local enc="$1"
  if [[ -z "${ENC_KEY_SET}" ]]; then
    log_json "ERROR" "BACKUP_DECRYPT_NO_KEY" "\"file\":\"${enc}\""
    return 1
  fi
  mkdir -p "${BACKUP_DIR}/tmp"; chmod 700 "${BACKUP_DIR}/tmp"
  DECRYPTED_TMP="$(mktemp "${BACKUP_DIR}/tmp/restore.XXXXXX")"
  chmod 600 "${DECRYPTED_TMP}"
  if ! openssl enc -d "${OPENSSL_ENC_ARGS[@]}" -in "${enc}" -out "${DECRYPTED_TMP}"; then
    log_json "ERROR" "BACKUP_DECRYPT_FAILED" "\"file\":\"${enc}\""
    cleanup_tmp
    return 1
  fi
}

# readable_dump <file> → sets READABLE to a path pg_restore can read (an .enc is decrypted into a private temp file).
# Called directly, never in $(...): the temp file's path must reach this shell so cleanup_tmp can remove it.
READABLE=""
readable_dump() {
  local f="$1"
  if [[ "${f}" == *.enc ]]; then
    decrypt_to_temp "${f}" || return 1
    READABLE="${DECRYPTED_TMP}"
  else
    READABLE="${f}"
  fi
}

offsite_copy() {
  local f="$1"
  [[ -z "${OFFSITE_CMD}" ]] && return 0
  if ${OFFSITE_CMD} "${f}" "${f}.seal"; then
    log_json "INFO" "BACKUP_OFFSITE_COPIED" "\"file\":\"${f}\""
  else
    alert_failure "Off-site copy FAILED for ${f} (QODIQA_BACKUP_OFFSITE_COMMAND exited non-zero)"
    log_json "ERROR" "BACKUP_OFFSITE_FAILED" "\"file\":\"${f}\""
    exit 1
  fi
}

# ── Backup integrity seal ─────────────────────────────────────────────────────

# HMAC-SHA256 (lowercase hex) of file "$1" with the seal key passed through the
# ENVIRONMENT of a node child — never on a command line. The former `openssl dgst -sha256` pipeline passed the key
# as openssl's HMAC-key ARGUMENT ("$(cat)" of an `echo -n` of it), i.e. in argv, readable by anyone on the host via
# ps / /proc/<pid>/cmdline. Output is BYTE-IDENTICAL to that pipeline (same key bytes: the former "$(cat)" stripped
# trailing newlines, so they are stripped here too; same lowercase hex + newline in the .seal file), so every seal
# written before this change still verifies — proven by
# test/pgBackupEncryption.test.js EN-20. node is part of the backup image and of every systemd host (the DR units
# run it); if it is missing the seal fails CLOSED rather than falling back to the argv form.
hmac_hex() {
  if ! command -v node >/dev/null 2>&1; then
    log_json "ERROR" "BACKUP_HMAC_NODE_MISSING" "\"message\":\"node is required to compute the HMAC seal without exposing the key on a command line\"" >&2
    return 1
  fi
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

seal_backup() {
  local backup_file="$1"
  local seal_file="${backup_file}.seal"
  if [[ -z "${HMAC_KEY}" ]]; then
    log_json "WARN" "BACKUP_NO_HMAC_KEY" "\"message\":\"QODIQA_BACKUP_HMAC_KEY not set — backup has no integrity seal\""
    # Hash-only, matching verify_seal's no-HMAC-key comparison below — a bare
    # `sha256sum` line also contains the filename, which would make every
    # verify() fail with BACKUP_SEAL_MISMATCH even for an untampered backup.
    sha256sum "${backup_file}" | awk '{print $1}' > "${seal_file}"
  else
    local mac
    mac="$(hmac_hex "${backup_file}")" || mac=""   # (PL13-03: reach the specific alert below, not the generic trap)
    if [[ ! "${mac}" =~ ^[0-9a-f]{64}$ ]]; then
      alert_failure "Integrity seal could not be computed for ${backup_file}"
      exit 1
    fi
    printf '%s\n' "${mac}" > "${seal_file}"
  fi
}

verify_seal() {
  local backup_file="$1"
  local seal_file="${backup_file}.seal"
  if [[ ! -f "${seal_file}" ]]; then
    log_json "ERROR" "BACKUP_SEAL_MISSING" "\"file\":\"${backup_file}\""
    return 1
  fi
  # Recompute and compare
  local expected; expected="$(cat "${seal_file}")"
  local actual
  if [[ -z "${HMAC_KEY}" ]]; then
    actual="$(sha256sum "${backup_file}" | awk '{print $1}')"
  else
    actual="$(hmac_hex "${backup_file}")" || actual=""
  fi
  if [[ "${expected}" == "${actual}" ]]; then
    return 0
  else
    log_json "ERROR" "BACKUP_SEAL_MISMATCH" "\"file\":\"${backup_file}\""
    return 1
  fi
}

# ── Pilot backup window ──
# QODIQA_BACKUP_WINDOW_UTC="HH:MM-HH:MM" (UTC, end exclusive, may wrap midnight): full/incremental refuse to START
# outside it — loudly (exit 1, alert, failure metric), never a silent skip. Unset = no restriction. Malformed = refused.
# QODIQA_BACKUP_WINDOW_OVERRIDE=true runs one deliberately (logged). Same rule as scripts/dr/backupWindow.js.
backup_window_guard() {
  local spec="${QODIQA_BACKUP_WINDOW_UTC:-}"
  [[ -z "${spec}" ]] && return 0
  if [[ ! "${spec}" =~ ^([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])$ ]]; then
    log_json "ERROR" "BACKUP_WINDOW_INVALID" "\"window\":\"$(json_escape "${spec}")\""
    alert_failure "QODIQA_BACKUP_WINDOW_UTC is not HH:MM-HH:MM — refusing to run"
    exit 1
  fi
  local start=$(( 10#${BASH_REMATCH[1]} * 60 + 10#${BASH_REMATCH[2]} )) end=$(( 10#${BASH_REMATCH[3]} * 60 + 10#${BASH_REMATCH[4]} ))
  local now; now=$(( 10#$(date -u +%H) * 60 + 10#$(date -u +%M) ))
  if (( start == end )); then
    log_json "ERROR" "BACKUP_WINDOW_INVALID" "\"window\":\"${spec}\""; alert_failure "QODIQA_BACKUP_WINDOW_UTC start equals end — refusing to run"; exit 1
  fi
  local inside=0
  if (( start < end )); then (( now >= start && now < end )) && inside=1; else (( now >= start || now < end )) && inside=1; fi
  (( inside == 1 )) && return 0
  if [[ "${QODIQA_BACKUP_WINDOW_OVERRIDE:-}" == "true" ]]; then
    log_json "WARN" "BACKUP_WINDOW_OVERRIDDEN" "\"window\":\"${spec}\""; return 0
  fi
  log_json "ERROR" "BACKUP_OUTSIDE_WINDOW" "\"window\":\"${spec}\""
  alert_failure "outside the backup window ${spec} UTC — backups are off-peak operations; nothing was written"
  exit 1
}

# ──: client/server major guard ───────────────────────────
# A dump from a pg_dump NEWER than the server is restorable by none of the server's own tools — measured with
# postgresql17-client against the shipped postgres:16.15: pg_restore 17 emits `SET transaction_timeout` (rejected by
# 16) and pg_restore 16 cannot read the 1.16 archive. So `full` requires pg_dump's major = the server's, and `restore`
# refuses a pg_restore newer than the target server, BEFORE anything is written (deploy/docker/backup.Dockerfile PG_CLIENT_MAJOR;
# scripts/dr/pgDump.js applies the same rule).
pg_major_guard() {
  local tool="$1" mode="$2" tool_major server_num server_major
  tool_major=$("${tool}" --version 2>/dev/null | sed -n 's/.*(PostgreSQL) \([0-9][0-9]*\).*/\1/p' | head -1 || true)
  server_num=$(psql -X -tA -d "${PGDATABASE:-qodiqa}" -c "SHOW server_version_num" 2>/dev/null | tr -d '[:space:]') || server_num=""
  if [[ -z "${tool_major}" || ! "${server_num}" =~ ^[0-9]+$ ]]; then
    log_json "ERROR" "PG_VERSION_CHECK_FAILED" "\"tool\":\"${tool}\""
    alert_failure "could not determine the ${tool} or server major version — refusing (fail closed)"
    exit 1
  fi
  server_major=$(( server_num / 10000 ))
  if [[ "${mode}" == "full" && "${tool_major}" != "${server_major}" ]] || [[ "${mode}" == "restore" && "${tool_major}" -gt "${server_major}" ]]; then
    log_json "ERROR" "PG_CLIENT_VERSION_MISMATCH" "\"tool\":\"${tool}\",\"toolMajor\":${tool_major},\"serverMajor\":${server_major}"
    alert_failure "${tool} major ${tool_major} does not match server major ${server_major} — use a backup image built with PG_CLIENT_MAJOR=${server_major} (deploy/docker/backup.Dockerfile); nothing was written"
    exit 1
  fi
}

# D-P: the dumping role must be RLS-exempt (superuser or BYPASSRLS) AND hold the predefined,
# read-only pg_read_all_data role (migration 067 grants it where the migrating identity may; otherwise the one-time
# scripts/db/provision-backup-role.superuser.sql). Checked BEFORE anything is written; any other answer — including a
# failed query — refuses the backup (fail closed). The existing per-table fail-closed behaviour of pg_dump is unchanged.
backup_role_preflight() {
  local ok
  ok=$(psql -X -tA -d "${PGDATABASE:-qodiqa}" -c "SELECT /* backup-role-preflight */ (r.rolsuper OR r.rolbypassrls) AND pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') FROM pg_catalog.pg_roles r WHERE r.rolname = current_user" 2>/dev/null | tr -d '[:space:]') || ok=""
  if [[ "${ok}" == "t" ]]; then
    log_json "INFO" "BACKUP_ROLE_PREFLIGHT_OK" "\"role\":\"${PGUSER:-}\""
    return 0
  fi
  if [[ "${ok}" == "f" ]]; then
    log_json "ERROR" "BACKUP_ROLE_READ_ALL_DATA_MISSING" "\"role\":\"${PGUSER:-}\""
    alert_failure "backup refused: role ${PGUSER:-<current>} is not both RLS-exempt and a pg_read_all_data member — run scripts/db/provision-backup-role.superuser.sql once (as a superuser) or back up as qodiqa_backup; nothing was written"
  else
    log_json "ERROR" "BACKUP_ROLE_PREFLIGHT_FAILED" "\"role\":\"${PGUSER:-}\""
    alert_failure "backup refused: could not verify the backup role's privileges (fail closed); nothing was written"
  fi
  exit 1
}

# ── Full backup ───────────────────────────────────────────────────────────────

run_full_backup() {
  local tier_dir="${BACKUP_DIR}/full"
  local retain_count=""
  if [[ -n "${TIER}" ]]; then
    case "${TIER}" in
      daily)   retain_count="${RETAIN_DAILY}"   ;;
      weekly)  retain_count="${RETAIN_WEEKLY}"  ;;
      monthly) retain_count="${RETAIN_MONTHLY}" ;;
      *)
        log_json "ERROR" "BACKUP_INVALID_TIER" "\"tier\":\"${TIER}\",\"message\":\"expected one of daily, weekly, monthly\""
        exit 1
        ;;
    esac
    tier_dir="${BACKUP_DIR}/full/${TIER}"
    mkdir -p "${tier_dir}"
  fi

  backup_window_guard
  encryption_preflight
  pg_major_guard pg_dump full
  backup_role_preflight
  quarantine_stale_partial_dumps "${tier_dir}"
  if [[ -n "${ENC_KEY_SET}" ]]; then quarantine_stale_plaintext "${tier_dir}"; fi
  local output_file="${tier_dir}/qodiqa_${TIMESTAMP}.dump"
  log_json "INFO" "BACKUP_FULL_START" "\"timestamp\":\"${TIMESTAMP}\",\"output\":\"${output_file}\",\"tier\":\"${TIER:-none}\""

  # NOTE: --jobs is intentionally NOT passed here. pg_dump only supports
  # parallel dump jobs with --format=directory; passing --jobs alongside
  # --format=custom is a hard pg_dump error ("parallel backup only supported
  # by the directory format") and made this command fail every single time
  # it ran with the default QODIQA_BACKUP_JOBS=4 — i.e. the full backup was
  # silently producing NO dump file in that configuration. Custom format is
  # kept (single self-contained file, works with seal/verify/restore below,
  # supports --compress and selective/parallel RESTORE via pg_restore --jobs
  # further down); dump-side parallelism is not worth the format tradeoff.
  # PL13-04: written to <dump>.partial and renamed only when pg_dump exits 0 (see DUMP_PARTIAL above). umask 077: the
  # dump is a full BYPASSRLS plaintext copy of every tenant's data — it is created owner-only (0600), not with the
  # process umask (typically 0644, i.e. world-readable on the backup volume while it is encrypted, or for good when
  # encryption is not configured).
  # (Not a ( umask 077; … ) subshell: with errtrace the ERR trap would then alert twice — once in the subshell, once
  # here. write_prom_metrics sets its file's mode explicitly, so a failure metric stays readable to node_exporter.)
  DUMP_PARTIAL="${output_file}.partial"
  local prev_umask; prev_umask="$(umask)"
  umask 077
  pg_dump \
    --format=custom \
    --compress=9 \
    --file="${DUMP_PARTIAL}" \
    --dbname="${PGDATABASE:-qodiqa}" \
    --no-password \
    --verbose \
    2>&1 | while read -r line; do
      log_json "INFO" "PG_DUMP_OUTPUT" "\"line\":\"${line//\"/\\\"}\""
    done
  umask "${prev_umask}"

  if [[ ! -s "${DUMP_PARTIAL}" ]]; then
    alert_failure "pg_dump produced no output for ${output_file}"
    exit 1
  fi
  mv -f "${DUMP_PARTIAL}" "${output_file}"
  DUMP_PARTIAL=""
  if [[ -n "${ENC_KEY_SET}" ]]; then
    encrypt_in_place "${output_file}"   # direct call, never $(...): a failure must exit this shell (N1)
    output_file="${ENCRYPTED_FILE}"
    log_json "INFO" "BACKUP_ENCRYPTED" "\"file\":\"${output_file}\",\"cipher\":\"aes-256-cbc+pbkdf2-sha256(200000)\",\"mac\":\"hmac-sha256 seal over ciphertext\""
  fi
  # Last line of defence before seal / off-site / COMPLETE: never report an empty, missing or (when encryption is
  # configured) unencrypted artifact as a backup.
  if [[ ! -s "${output_file}" ]] || { [[ -n "${ENC_KEY_SET}" ]] && [[ "${output_file}" != *.dump.enc ]]; }; then
    alert_failure "Backup artifact invalid before sealing: ${output_file:-<none>}"
    exit 1
  fi
  local size_bytes; size_bytes=$(stat -c%s "${output_file}" 2>/dev/null || stat -f%z "${output_file}")
  # PL13-08: SHA-256 of the stored artifact (the ciphertext when encrypted) in the completion record — lets an
  # operator or the off-site store check an object's integrity WITHOUT the HMAC key (the seal stays the authenticity
  # check). Never a hash of the plaintext.
  local sha256; sha256="$(sha256sum "${output_file}" | awk '{print $1}')"
  seal_backup "${output_file}"
  offsite_copy "${output_file}"

  log_json "INFO" "BACKUP_FULL_COMPLETE" \
    "\"timestamp\":\"${TIMESTAMP}\",\"file\":\"${output_file}\",\"sizeBytes\":${size_bytes},\"sha256\":\"${sha256}\",\"tier\":\"${TIER:-none}\""

  if [[ -n "${TIER}" ]]; then
    enforce_tier_retention "${tier_dir}" "${retain_count}" "${TIER}"
  else
    # Legacy untiered day-cutoff retention — unchanged from,
    # preserved for callers that invoke `full` with no tier argument.
    find "${BACKUP_DIR}/full" -maxdepth 1 \( -name "*.dump" -o -name "*.dump.enc" \) -mtime "+${RETAIN_DAYS}" -exec rm -f {} \; -exec rm -f {}.seal \; || true
    log_json "INFO" "BACKUP_RETENTION_ENFORCED" "\"retainDays\":${RETAIN_DAYS}"
  fi

  write_prom_metrics "full" "${TIER}" 1 "${size_bytes}"
}

# ── Incremental backup (WAL streaming via pg_basebackup) ─────────────────────

run_incremental_backup() {
  backup_window_guard
  local output_dir="${BACKUP_DIR}/wal/qodiqa_wal_${TIMESTAMP}"
  log_json "INFO" "BACKUP_WAL_START" "\"timestamp\":\"${TIMESTAMP}\",\"output\":\"${output_dir}\""

  # Requires: wal_level=replica, archive_mode=on in postgresql.conf
  # and REPLICATION privilege for the backup user
  pg_basebackup \
    --pgdata="${output_dir}" \
    --format=tar \
    --gzip \
    --checkpoint=fast \
    --wal-method=stream \
    --no-password \
    --progress \
    2>&1 | while read -r line; do
      log_json "INFO" "WAL_BACKUP_OUTPUT" "\"line\":\"${line//\"/\\\"}\""
    done

  tar -czf "${output_dir}.tar.gz" -C "${BACKUP_DIR}/wal" "qodiqa_wal_${TIMESTAMP}" && \
    rm -rf "${output_dir}"
  seal_backup "${output_dir}.tar.gz"

  log_json "INFO" "BACKUP_WAL_COMPLETE" "\"timestamp\":\"${TIMESTAMP}\",\"file\":\"${output_dir}.tar.gz\""

  # Retain last 7 days of WAL backups
  find "${BACKUP_DIR}/wal" -name "*.tar.gz" -mtime +7 -exec rm -f {} \; -exec rm -f {}.seal \; || true

  local wal_size_bytes; wal_size_bytes=$(stat -c%s "${output_dir}.tar.gz" 2>/dev/null || stat -f%z "${output_dir}.tar.gz")
  write_prom_metrics "incremental" "" 1 "${wal_size_bytes}"
}

# ── Backup verification ───────────────────────────────────────────────────────

run_verify() {
  local verify_dir="${BACKUP_DIR}/full"
  if [[ -n "${TIER}" ]]; then
    case "${TIER}" in
      daily|weekly|monthly) verify_dir="${BACKUP_DIR}/full/${TIER}" ;;
      *)
        log_json "ERROR" "BACKUP_INVALID_TIER" "\"tier\":\"${TIER}\",\"message\":\"expected one of daily, weekly, monthly\""
        exit 1
        ;;
    esac
  fi

  sweep_stale_decrypted
  # N2: when encryption is required, plaintext is never a backup — a plaintext dump in the directory (left by a crash
  # between pg_dump and encryption) fails verification loudly, and only *.dump.enc is ever selected.
  if [[ "${REQUIRE_ENC}" == "true" ]]; then
    # PL13-04: an incomplete pg_dump output (<dump>.partial, left by a SIGKILLed / OOM-killed run that no trap could
    # clean up) is plaintext at rest too — reported here, not only at the next full run.
    local stray; stray=$(ls "${verify_dir}"/*.dump "${verify_dir}"/*.dump.partial 2>/dev/null || true)
    if [[ -n "${stray}" ]]; then
      log_json "ERROR" "BACKUP_PLAINTEXT_REFUSED" "\"dir\":\"${verify_dir}\",\"message\":\"plaintext dump(s) present while QODIQA_BACKUP_REQUIRE_ENCRYPTION=true\""
      alert_failure "Plaintext backup artifact(s) present in ${verify_dir} while encryption is required: ${stray//$'\n'/ }"
      exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
    fi
  fi
  # (|| true: with plaintext and encrypted globs, an unmatched one makes ls exit non-zero under pipefail)
  local latest
  if [[ "${REQUIRE_ENC}" == "true" ]]; then
    latest=$(ls -t "${verify_dir}"/*.dump.enc 2>/dev/null | head -1 || true)
  else
    latest=$(ls -t "${verify_dir}"/*.dump "${verify_dir}"/*.dump.enc 2>/dev/null | head -1 || true)
  fi
  if [[ -z "${latest}" ]]; then
    alert_failure "No backup found to verify in ${verify_dir}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi
  if ! refuse_plaintext_if_required "${latest}"; then
    alert_failure "Plaintext backup refused for verification: ${latest}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi

  log_json "INFO" "BACKUP_VERIFY_START" "\"file\":\"${latest}\""

  # 1. Verify integrity seal
  if verify_seal "${latest}"; then
    log_json "INFO" "BACKUP_SEAL_OK" "\"file\":\"${latest}\""
  else
    alert_failure "Seal verification FAILED for ${latest}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi

  # 2. Verify backup is restorable (list contents without restoring). An encrypted backup is decrypted into a private
  # temporary file first — a backup that does not decrypt is a failed backup.
  if ! readable_dump "${latest}"; then
    alert_failure "Decryption FAILED for ${latest}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi
  local verify_output
  verify_output=$(pg_restore --list "${READABLE}" 2>&1 | wc -l)
  if [[ "${verify_output}" -lt 10 ]]; then
    alert_failure "pg_restore --list returned suspicious output (${verify_output} lines) for ${latest}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi

  # 3. Check EVERY production table is present.
  #
  # This used to check only 5 hand-picked "critical" tables, which is exactly
  # the kind of allow-list that silently goes stale as new tables are added
  # (see CONFORMANCE_AUDIT_REPORT.md finding only 8 of ~50 tables were
  # ever actually verified/backed up by the DR framework). `pg_dump` itself
  # already captures the whole database with no --table filter (see
  # run_full_backup above), so this check exists purely to PROVE that full
  # coverage, against the definitive table inventory in
  # scripts/dr/table-registry.js (parsed from the migrations themselves, so
  # it can never drift from what the schema actually defines).
  local dump_contents; dump_contents=$(pg_restore --list "${READABLE}" 2>/dev/null)
  local missing_tables=()
  if command -v node >/dev/null 2>&1; then
    while IFS= read -r table; do
      [[ -z "${table}" ]] && continue
      if ! grep -q "TABLE DATA public ${table} " <<< "${dump_contents}"; then
        missing_tables+=("${table}")
      fi
    done < <(node "$(dirname "${BASH_SOURCE[0]}")/dr/table-registry.js" --list 2>/dev/null)
  else
    log_json "WARN" "BACKUP_VERIFY_NODE_UNAVAILABLE" \
      "\"message\":\"node not found — falling back to a minimal critical-table check instead of full inventory coverage\""
    for table in audit_chain platform_audit_events policies rbac_users signing_keys consent_records investigations compliance_reports; do
      if ! grep -q "TABLE DATA public ${table} " <<< "${dump_contents}"; then
        missing_tables+=("${table}")
      fi
    done
  fi

  if [[ "${#missing_tables[@]}" -gt 0 ]]; then
    alert_failure "Backup coverage gap — table(s) missing from ${latest}: ${missing_tables[*]}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi

  # 4. Staleness. This verify used to pass on the newest backup however OLD it was: if
  # the full-backup schedule silently stopped (CronJob suspended or deleted, timer disabled, the job never scheduled),
  # every 02:30 verify kept re-verifying the last good dump and reported success. Only the Prometheus rule
  # QodiqaBackupStale could notice, and a webhook-only (systemd) install has no Prometheus. pg-wal-archive.sh and
  # backup-audit-log.sh already fail their verify on a stale newest artifact; this is the same check for full dumps.
  # Default maximum age per tier: daily 26 h, weekly 8 d, monthly 32 d (one schedule period + slack). Untiered: off
  # unless set. QODIQA_BACKUP_MAX_AGE_SECONDS overrides; 0 disables.
  local max_age="${QODIQA_BACKUP_MAX_AGE_SECONDS:-}"
  if [[ -z "${max_age}" ]]; then
    case "${TIER}" in
      daily)   max_age=93600 ;;
      weekly)  max_age=691200 ;;
      monthly) max_age=2764800 ;;
      *)       max_age=0 ;;
    esac
  fi
  if [[ ! "${max_age}" =~ ^[0-9]+$ ]]; then
    alert_failure "QODIQA_BACKUP_MAX_AGE_SECONDS must be a whole number of seconds (got '${max_age}')"
    exit 1
  fi
  local latest_epoch; latest_epoch=$(stat -c%Y "${latest}" 2>/dev/null || stat -f%m "${latest}")
  local age_seconds=$(( $(date -u +%s) - latest_epoch ))
  if [[ "${max_age}" -gt 0 && "${age_seconds}" -gt "${max_age}" ]]; then
    alert_failure "Backup is stale — newest backup ${latest} is ${age_seconds}s old (max ${max_age}s); the full-backup schedule may have stopped firing"
    exit 1
  fi

  # Archive metadata from the dump header (PL13-08): which database, from which server and pg_dump version. A restore
  # operator can confirm a candidate backup is the right database and that the restoring client is new enough
  # (pg_restore refuses an archive written by a newer pg_dump) without decrypting it by hand.
  local hdr_db hdr_server hdr_dump
  hdr_db=$(sed -n 's/^;[[:space:]]*dbname: //p' <<< "${dump_contents}" | head -1 || true)
  hdr_server=$(sed -n 's/^;[[:space:]]*Dumped from database version: //p' <<< "${dump_contents}" | head -1 || true)
  hdr_dump=$(sed -n 's/^;[[:space:]]*Dumped by pg_dump version: //p' <<< "${dump_contents}" | head -1 || true)

  local size_bytes; size_bytes=$(stat -c%s "${latest}" 2>/dev/null || stat -f%z "${latest}")
  log_json "INFO" "BACKUP_VERIFY_OK" \
    "\"file\":\"${latest}\",\"sizeBytes\":${size_bytes},\"objectCount\":${verify_output},\"ageSeconds\":${age_seconds},\"maxAgeSeconds\":${max_age},\"dbname\":\"${hdr_db//\"/}\",\"serverVersion\":\"${hdr_server//\"/}\",\"pgDumpVersion\":\"${hdr_dump//\"/}\""

  write_prom_metrics "verify" "${TIER}" 1 "${size_bytes}"
}

# ── Restore procedure ─────────────────────────────────────────────────────────

run_restore() {
  local backup_file="${2:-}"
  sweep_stale_decrypted
  if [[ -z "${backup_file}" ]]; then
    if [[ "${REQUIRE_ENC}" == "true" ]]; then
      backup_file=$(ls -t "${BACKUP_DIR}/full"/*.dump.enc 2>/dev/null | head -1 || true)
    else
      backup_file=$(ls -t "${BACKUP_DIR}/full"/*.dump "${BACKUP_DIR}/full"/*.dump.enc 2>/dev/null | head -1 || true)
    fi
  fi

  if [[ -z "${backup_file}" || ! -f "${backup_file}" ]]; then
    echo "ERROR: No backup file found. Specify path as second argument."
    exit 1
  fi
  # N2: with encryption required, a plaintext file is refused before the confirmation prompt
  refuse_plaintext_if_required "${backup_file}" || { echo "ERROR: QODIQA_BACKUP_REQUIRE_ENCRYPTION=true — refusing to restore a plaintext backup."; exit 1; }

  echo ""
  echo "⚠️  RESTORE CONFIRMATION REQUIRED"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Target database : ${PGDATABASE:-qodiqa}"
  echo "  Backup file     : ${backup_file}"
  echo "  This will DESTROY all existing data in the target database."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  read -r -p "Type 'RESTORE' to proceed: " confirm || confirm=""   # EOF on stdin = not confirmed (plain abort, no alert)
  if [[ "${confirm}" != "RESTORE" ]]; then
    echo "Aborted."
    exit 1
  fi

  # OA4-F1: pg_restore runs with --no-owner, so EVERY restored object — including the 47 SECURITY
  # DEFINER functions — is owned by the role running the restore. As a superuser, every definer function would then
  # execute with superuser rights (the PM-01 privilege comparison would not flag it: it records only the owner's
  # BYPASSRLS). Restore as the bootstrap/migration identity (qodiqa_test), never as a superuser. A throwaway
  # superuser-only environment (e.g. CI's service container) must say so explicitly for that one run.
  local restore_is_super
  restore_is_super=$(psql -X -tA -d "${PGDATABASE:-qodiqa}" -c "SELECT rolsuper FROM pg_roles WHERE rolname = current_user" 2>/dev/null | tr -d '[:space:]') || restore_is_super=""
  if [[ "${restore_is_super}" != "f" ]]; then
    if [[ "${restore_is_super}" == "t" && "${QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE:-}" == "true" ]]; then
      log_json "WARN" "RESTORE_AS_SUPERUSER_ALLOWED" "\"role\":\"${PGUSER:-}\",\"reason\":\"QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE=true\""
    elif [[ "${restore_is_super}" == "t" ]]; then
      log_json "ERROR" "RESTORE_SUPERUSER_REFUSED" "\"role\":\"${PGUSER:-}\""
      echo "ERROR: refusing to restore as a superuser: with --no-owner every restored SECURITY DEFINER function would run as superuser. Restore as qodiqa_test (see docs/operations/database-role-management.md), or set QODIQA_BACKUP_ALLOW_SUPERUSER_RESTORE=true for a throwaway target only."
      exit 1
    else
      log_json "ERROR" "RESTORE_ROLE_CHECK_FAILED" "\"role\":\"${PGUSER:-}\""
      echo "ERROR: could not determine whether the restoring role is a superuser — refusing to restore (fail-closed)."
      exit 1
    fi
  fi

  pg_major_guard pg_restore restore

  # Verify seal before restore
  verify_seal "${backup_file}" || { echo "ERROR: Seal verification failed — refusing to restore."; exit 1; }

  log_json "INFO" "RESTORE_START" "\"file\":\"${backup_file}\""
  readable_dump "${backup_file}" || { echo "ERROR: decryption failed — refusing to restore."; exit 1; }

  # PL13-10: a pg_restore that stops part-way (measured: a restoring role that is not a member of
  # the roles owning the dump's DEFAULT PRIVILEGES fails on `ALTER DEFAULT PRIVILEGES FOR ROLE …` AFTER every table's
  # data is loaded and BEFORE any GRANT) leaves a target that LOOKS restored — all tables, all rows — but carries no
  # application grants. Say so explicitly, so nobody switches the application to it.
  if ! pg_restore \
    --clean \
    --if-exists \
    --exit-on-error \
    --no-owner \
    --jobs="${PARALLEL_JOBS}" \
    --dbname="${PGDATABASE:-qodiqa}" \
    "${READABLE}"; then
    log_json "ERROR" "RESTORE_FAILED" "\"file\":\"${backup_file}\",\"database\":\"${PGDATABASE:-qodiqa}\""
    alert_failure "Restore FAILED part-way into ${PGDATABASE:-qodiqa} from ${backup_file}: the target is INCOMPLETE (it may hold data without its grants) — discard it, never switch the application to it; restore as the bootstrap/migration identity (docs/operations/restore-runbook.md §5.2)"
    exit 1
  fi
  cleanup_tmp

  # --no-owner left every restored object owned by the restoring role — the 47 SECURITY DEFINER
  # functions included, which would then execute as that role. On a schema at migration 079 or later, hand them back to
  # the NOLOGIN, non-superuser qodiqa_definer and verify (scripts/dr/definer-ownership.sql); any failure means the
  # target is INCOMPLETE. An older schema (no 079) is reported, not silently treated as fixed.
  local has_er16
  has_er16=$(psql -X -tA -d "${PGDATABASE:-qodiqa}" -c "SELECT count(*) FROM qodiqa_migrations WHERE version = 79" 2>/dev/null | tr -d '[:space:]') || has_er16=""
  if [[ "${has_er16}" == "1" ]]; then
    # closure (migration 081): first hand every table/sequence/type/non-definer function back to qodiqa_owner and
    # verify backup coverage + default privileges (scripts/dr/schema-ownership.sql), then the definers.
    local has_owner
    has_owner=$(psql -X -tA -d "${PGDATABASE:-qodiqa}" -c "SELECT count(*) FROM qodiqa_migrations WHERE version = 81" 2>/dev/null | tr -d '[:space:]') || has_owner=""
    if [[ "${has_owner}" == "1" ]] && ! psql -X -q -v ON_ERROR_STOP=1 -d "${PGDATABASE:-qodiqa}" -f "$(dirname "${BASH_SOURCE[0]}")/dr/schema-ownership.sql"; then
      log_json "ERROR" "RESTORE_SCHEMA_OWNERSHIP_FAILED" "\"database\":\"${PGDATABASE:-qodiqa}\""
      alert_failure "Restore into ${PGDATABASE:-qodiqa} could not re-establish schema ownership: the target is INCOMPLETE — discard it, never switch the application to it; restore as the bootstrap/migration identity that ran migration 081"
      exit 1
    fi
    if [[ "${has_owner}" != "1" && "${has_owner}" != "0" ]]; then
      log_json "ERROR" "RESTORE_DEFINER_OWNERSHIP_UNKNOWN" "\"database\":\"${PGDATABASE:-qodiqa}\""
      alert_failure "Restore into ${PGDATABASE:-qodiqa}: could not read qodiqa_migrations to check schema ownership — the target is unverified; do not switch the application to it"
      exit 1
    fi
    if ! psql -X -q -v ON_ERROR_STOP=1 -d "${PGDATABASE:-qodiqa}" -f "$(dirname "${BASH_SOURCE[0]}")/dr/definer-ownership.sql"; then
      log_json "ERROR" "RESTORE_DEFINER_OWNERSHIP_FAILED" "\"database\":\"${PGDATABASE:-qodiqa}\""
      alert_failure "Restore into ${PGDATABASE:-qodiqa} could not re-establish SECURITY DEFINER ownership: the target is INCOMPLETE — discard it, never switch the application to it; restore as the bootstrap/migration identity that ran migration 079"
      exit 1
    fi
    log_json "INFO" "RESTORE_DEFINER_OWNERSHIP_OK" "\"owner\":\"qodiqa_definer\""
  elif [[ "${has_er16}" == "0" ]]; then
    log_json "WARN" "RESTORE_DEFINER_OWNERSHIP_PRE_ER16" "\"database\":\"${PGDATABASE:-qodiqa}\",\"message\":\"restored schema predates migration 079 — run node src/infra/postgres/migrate.js before switching the application to it\""
  else
    log_json "ERROR" "RESTORE_DEFINER_OWNERSHIP_UNKNOWN" "\"database\":\"${PGDATABASE:-qodiqa}\""
    alert_failure "Restore into ${PGDATABASE:-qodiqa}: could not read qodiqa_migrations to check SECURITY DEFINER ownership — the target is unverified; do not switch the application to it"
    exit 1
  fi

  log_json "INFO" "RESTORE_COMPLETE" "\"file\":\"${backup_file}\""
  echo ""
  echo "✓ Restore complete. Run validation: node scripts/migrate-files-to-pg.js --validate"
}

# ── Point-in-time recovery restore ─────────────────────
#
# Prepares a PGDATA directory for point-in-time recovery from a
# pg_basebackup base backup plus scripts/pg-wal-archive.sh's continuously
# archived WAL. Deliberately prepare-and-instruct, not fully orchestrated —
# see the header comment above.

run_pitr_restore() {
  local basebackup_file="${2:-}"
  local target_pgdata="${3:-}"
  local target_time="${4:-latest}"

  if [[ -z "${basebackup_file}" || -z "${target_pgdata}" ]]; then
    echo "Usage: $0 pitr-restore <basebackup.tar.gz> <target_pgdata_dir> [target_time|latest]"
    exit 1
  fi
  if [[ ! -f "${basebackup_file}" ]]; then
    echo "ERROR: base backup not found: ${basebackup_file}"
    exit 1
  fi
  if [[ -e "${target_pgdata}" ]]; then
    echo "ERROR: target PGDATA directory already exists — refusing to restore over it: ${target_pgdata}"
    echo "(matches this repo's 'never restore over an existing instance' convention — see scripts/dr/restore.js's TARGET_NOT_CLEAN)"
    exit 1
  fi

  verify_seal "${basebackup_file}" || { echo "ERROR: Seal verification failed for base backup — refusing to restore."; exit 1; }

  log_json "INFO" "PITR_RESTORE_START" "\"basebackup\":\"${basebackup_file}\",\"target\":\"${target_pgdata}\",\"targetTime\":\"${target_time}\""

  mkdir -p "${target_pgdata}"
  tar -xzf "${basebackup_file}" -C "${target_pgdata}"
  chmod 0700 "${target_pgdata}"

  local wal_archive_dir="${QODIQA_WAL_ARCHIVE_DIR:-${BACKUP_DIR}/wal-archive}"

  # PostgreSQL 12+: the presence of recovery.signal alone puts the server
  # into recovery/replay mode on next start; restore_command is a normal GUC.
  touch "${target_pgdata}/recovery.signal"
  {
    echo "restore_command = 'gzip -dc \"${wal_archive_dir}/%f.gz\" > \"%p\"'"
    if [[ "${target_time}" != "latest" ]]; then
      echo "recovery_target_time = '${target_time}'"
      echo "recovery_target_action = 'promote'"
    fi
  } >> "${target_pgdata}/postgresql.auto.conf"

  log_json "INFO" "PITR_RESTORE_PREPARED" "\"target\":\"${target_pgdata}\""

  echo ""
  echo "✓ PGDATA prepared for point-in-time recovery: ${target_pgdata}"
  echo ""
  echo "This script prepares the data directory and stops here — starting the"
  echo "PostgreSQL server process is environment-specific and operator-owned"
  echo "(see this file's header comment). Start it with, e.g.:"
  echo ""
  echo "  pg_ctl -D \"${target_pgdata}\" -l \"${target_pgdata}/recovery.log\" start"
  echo "  # or: systemctl start postgresql@<instance-on-this-pgdata>"
  echo ""
  if [[ "${target_time}" != "latest" ]]; then
    echo "PostgreSQL will replay archived WAL from ${wal_archive_dir} up to"
    echo "${target_time}, then promote to a normal read/write server."
  else
    echo "PostgreSQL will replay every archived WAL segment from"
    echo "${wal_archive_dir}, then promote to a normal read/write server."
  fi
  echo "Monitor progress: tail -f \"${target_pgdata}/recovery.log\" (or the server's configured log)."
}

# ── Main ──────────────────────────────────────────────────────────────────────

case "${MODE}" in
  full)         run_full_backup ;;
  # UNSUPPORTED until a decision is made on REPLICATION for qodiqa_backup —
  # pg_basebackup needs that attribute, which is deliberately not granted (docs/deployment/production-checklist.md §5.4).
  incremental)
    # a refused incremental run must be VISIBLE as a failure to monitoring — success=0 is
    # written (previously no metric at all, so an absent series could be read as "nothing to report").
    write_prom_metrics "incremental" "" 0 0
    log_json "ERROR" "BACKUP_INCREMENTAL_UNSUPPORTED" "\"reason\":\"pg_basebackup needs REPLICATION on the backup role, which is not granted\""
    echo "pg-backup.sh incremental is UNSUPPORTED: pg_basebackup needs the REPLICATION attribute on qodiqa_backup, which is not granted (see docs/deployment/production-checklist.md §5.4)." >&2
    exit 2
    ;;
  verify)       run_verify ;;
  restore)      run_restore "$@" ;;
  pitr-restore) run_pitr_restore "$@" ;;
  *)
    echo "Usage: $0 [full|incremental|verify|restore [backup_file]|pitr-restore <basebackup.tar.gz> <target_pgdata_dir> [target_time|latest]]"
    exit 1
    ;;
esac
