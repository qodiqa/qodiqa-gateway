#!/usr/bin/env bash
# QODIQA Audit Log Backup Script
#
# Builds the script docs/operations/backup-runbook.md §5.1 has documented
# but that never actually existed in the repo (confirmed by
# grep/glob during the audit) — the audit-chain file's 5-minute RPO
# claim was unenforced for exactly the reason found for PostgreSQL: a
# runbook describing a cron job that nothing ever built.
#
# High-frequency (5-minute), non-destructive backup of the authoritative
# audit-chain NDJSON file plus its WAL and anti-deletion-checksum
# companions. Mirrors scripts/pg-backup.sh's conventions exactly (HMAC seal,
# Prometheus textfile metrics, alert webhook, structured JSON log) so
# operators already familiar with one script already know this one.
#
# Usage:
#   ./scripts/backup-audit-log.sh backup                          (default)
#   ./scripts/backup-audit-log.sh verify
#   ./scripts/backup-audit-log.sh restore [backup_file] [target_path]
#
# Required / relevant env vars:
#   QODIQA_AUDIT_LOG                 — path to the live audit log (default: audit.log)
#   QODIQA_AUDIT_BACKUP_DIR          — base directory for backup files
#                                       (default: /var/backups/qodiqa/audit)
#   QODIQA_AUDIT_BACKUP_RETAIN_DAYS  — days to keep (default: 90, matching
#                                       docs/operations/backup-runbook.md §9)
#   QODIQA_AUDIT_BACKUP_MAX_AGE_SECONDS — `verify` mode fails closed if the
#                                       newest backup is older than this
#                                       (default: 600 = 2x the 5-minute
#                                       schedule interval — catches a
#                                       silently-stopped timer/CronJob)
#   QODIQA_BACKUP_HMAC_KEY           — same integrity-seal key pg-backup.sh uses (32+ chars)
#   QODIQA_AUDIT_BACKUP_METRICS_FILE — Prometheus textfile-collector output path
#                                       (default: ${QODIQA_AUDIT_BACKUP_DIR}/metrics/qodiqa_audit_log_backup.prom)
#   ALERT_WEBHOOK_URL                — optional Slack/PagerDuty URL for failure alerts
#
# Scheduling — this is the piece that was missing:
#   deploy/systemd/qodiqa-audit-log-backup.timer   (OnCalendar=*:0/5)
#   docs/operations/backup-scheduling.md §5
#
# Kubernetes: intentionally NOT scheduled as a standalone CronJob. The audit
# log lives on a per-pod-exclusive ReadWriteOnce volume (see
# deploy/kubernetes/overlays/single-node/statefulset.yaml and the "Known scope boundary" note in
# deploy/kubernetes/base/backup-cronjobs.yaml) that a separate pod cannot safely
# reach. In that topology, the audit-chain RPO is met through the
# Postgres-mirrored audit_chain table via continuous WAL archiving
# (scripts/pg-wal-archive.sh) instead — see
# docs/operations/disaster-recovery.md §1 for which mechanism satisfies the
# claim in which topology.

# PL13-03: -E (errtrace) — without it the ERR trap below never ran for a failure
# inside run_backup / run_verify (every mode is a function), so e.g. an unreadable audit log or an empty backup
# directory ended the run silently: no AUDIT_LOG_BACKUP_FAILED, no alert, no success=0 metric.
set -Eeuo pipefail

# ── Configuration ────────────────────────────────────────────────────────

AUDIT_LOG="${QODIQA_AUDIT_LOG:-audit.log}"
BACKUP_DIR="${QODIQA_AUDIT_BACKUP_DIR:-/var/backups/qodiqa/audit}"
RETAIN_DAYS="${QODIQA_AUDIT_BACKUP_RETAIN_DAYS:-90}"
MAX_AGE_SECONDS="${QODIQA_AUDIT_BACKUP_MAX_AGE_SECONDS:-600}"
HMAC_KEY="${QODIQA_BACKUP_HMAC_KEY:-}"
ALERT_URL="${ALERT_WEBHOOK_URL:-}"
METRICS_FILE="${QODIQA_AUDIT_BACKUP_METRICS_FILE:-${BACKUP_DIR}/metrics/qodiqa_audit_log_backup.prom}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${BACKUP_DIR}/backup-audit.jsonl"
MODE="${1:-backup}"

mkdir -p "${BACKUP_DIR}"

# ── Helpers (mirrors scripts/pg-backup.sh exactly) ─────────────────────────

log_json() {
  local level="$1"
  local event="$2"
  shift 2
  local extra="${*:-}"
  echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"level\":\"${level}\",\"event\":\"${event}\"${extra:+,${extra}}}" \
    | tee -a "${LOG_FILE}"
}

write_prom_metrics() {
  local success="$1" size_bytes="${2:-0}"
  {
    mkdir -p "$(dirname "${METRICS_FILE}")" 2>/dev/null
    local tmp="${METRICS_FILE}.$$.tmp"
    {
      echo "qodiqa_audit_log_backup_success ${success}"
      echo "qodiqa_audit_log_backup_last_run_timestamp_seconds $(date -u +%s)"
      echo "qodiqa_audit_log_backup_size_bytes ${size_bytes}"
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
  log_json "ERROR" "AUDIT_LOG_BACKUP_FAILED" "\"message\":\"${msg}\""
  write_prom_metrics 0 0
  # PL13-05: placeholder / non-http(s) value = unset, and
  # the URL (which embeds the webhook token) reaches curl as a config file on stdin, never on argv.
  if [[ -n "${ALERT_URL}" && ( "${ALERT_URL}" == *REPLACE_WITH* || ! "${ALERT_URL}" =~ ^https?:// ) ]]; then
    log_json "WARN" "ALERT_WEBHOOK_PLACEHOLDER" "\"message\":\"ALERT_WEBHOOK_URL is a placeholder or not an http(s) URL — no alert was sent\""
  elif [[ -n "${ALERT_URL}" ]]; then
    local url; url="$(json_escape "${ALERT_URL}")"   # curl-config quoting = JSON's for \\ and \" (PL13-13)
    printf 'url = "%s"\n' "${url}" | curl -s -K - -X POST -H 'Content-type: application/json' \
      -d "{\"text\":\"🚨 QODIQA audit-log backup FAILED on $(hostname): ${msg}\"}" || true
  fi
}

# PL13-03: with errtrace (set -E) a failing $(...) would also run this trap INSIDE the command substitution (its
# alert line captured into the variable, the webhook posted twice); the failure always propagates to the parent's
# assignment, so only the top-level shell (BASH_SUBSHELL 0) alerts — exactly once.
trap 'if [[ ${BASH_SUBSHELL} -eq 0 ]]; then alert_failure "Unexpected error on line ${LINENO}: ${BASH_COMMAND}"; fi' ERR

# Same HMAC-or-SHA256-fallback seal as pg-backup.sh, including the
# hash-only fallback fix (a bare `sha256sum` line also contains the
# filename, which would make verify_seal() fail even for an untampered
# backup when no HMAC key is set).
# follow-up: the same key-off-argv HMAC as scripts/pg-backup.sh hmac_hex() — the
# former `openssl dgst -sha256 -hmac "$(cat)"` put the seal key in openssl's argv (visible via ps / /proc/<pid>/cmdline).
# Byte-identical output (trailing newlines of the key stripped, lowercase hex), so existing seals still verify. Fails
# closed if node is missing (no fallback to the argv form).
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

seal_backup() {
  local backup_file="$1"
  local seal_file="${backup_file}.seal"
  if [[ -z "${HMAC_KEY}" ]]; then
    log_json "WARN" "AUDIT_LOG_BACKUP_NO_HMAC_KEY" "\"message\":\"QODIQA_BACKUP_HMAC_KEY not set — backup has no integrity seal\""
    sha256sum "${backup_file}" | awk '{print $1}' > "${seal_file}"
  else
    hmac_hex "${backup_file}" > "${seal_file}"
  fi
}

verify_seal() {
  local backup_file="$1"
  local seal_file="${backup_file}.seal"
  if [[ ! -f "${seal_file}" ]]; then
    log_json "ERROR" "AUDIT_LOG_BACKUP_SEAL_MISSING" "\"file\":\"${backup_file}\""
    return 1
  fi
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
    log_json "ERROR" "AUDIT_LOG_BACKUP_SEAL_MISMATCH" "\"file\":\"${backup_file}\""
    return 1
  fi
}

# ──: incremental, append-only runs ──────────────────
#
# Measured at 3.15 GB: the former run copied, gzipped and sealed the
# WHOLE log every 5 minutes — 63 s per run, 117 MB per copy (~33.7 GB/day, ~3 TB over the 90-day retention), gateway
# 30-s segment p95 379 ms while it ran; `verify` decompressed the whole newest copy every 5 minutes. And it copied the
# log BEFORE .sum, so a restored .sum could describe a longer log than the restored file (a boot refusal).
#
# Now (default, QODIQA_AUDIT_BACKUP_INCREMENTAL unset or "true"):
#   * .sum and .wal are copied FIRST; then the log's size is taken and only the prefix up to its last complete line is
#     backed up (an in-flight append is not yet acknowledged). Each run's sidecars therefore describe a prefix of what
#     that run's chain holds.
#   * A BASE (audit-<ts>.log.gz, as before) holds the whole prefix; each later run writes a SEGMENT
#     (audit-<base>.seg-NNNNNN.log.gz) holding only the bytes appended since the previous run — I/O proportional to new
#     data, the 5-minute RPO unchanged. Every run writes a metadata file (byte range, data sha256, first/last line sha256,
#     sha256 of the previous run's metadata) and HMAC-seals it, so the sealed chain authenticates every byte and the order.
#   * A new base is taken when the log was rewritten or pruned (shorter than the backed-up range, a different first line,
#     or the last backed-up line no longer at its offset), when there is no usable state, and when the base is older than
#     QODIQA_AUDIT_BACKUP_REBASE_HOURS (default 24) — the planned rebase waits for QODIQA_BACKUP_WINDOW_UTC when one is
#     set (off-peak); a forced rebase (rewrite / no state) never waits.
#   * Retention removes WHOLE chains (a base with all its segments) older than the retention, never the current chain.
# QODIQA_AUDIT_BACKUP_INCREMENTAL=false: every run is a base (the former full copy, with the corrected ordering and a meta).
# Backups written (no .meta.json) still verify and restore exactly as before.

CHAIN_JS="$(cd "$(dirname "$0")" && pwd)/audit-log-backup-chain.js"
WINDOW_JS="$(cd "$(dirname "$0")" && pwd)/dr/backupWindow.js"
STATE_FILE="${BACKUP_DIR}/incremental-state.json"
INCREMENTAL="${QODIQA_AUDIT_BACKUP_INCREMENTAL:-true}"
REBASE_HOURS="${QODIQA_AUDIT_BACKUP_REBASE_HOURS:-24}"

chain_js() { node "${CHAIN_JS}" "$@"; }
jget() { node -e 'const o=JSON.parse(process.argv[1]);const v=process.argv[2].split(".").reduce((a,k)=>a==null?a:a[k],o);process.stdout.write(v==null?"":String(v))' "$1" "$2"; }
seal_meta() { seal_backup "$1"; }                 # same HMAC-or-SHA256 seal as every backup file (meta.seal)

# ── Backup ──────────────────────────────────────────────────────────────

run_backup() {
  if [[ ! -f "${AUDIT_LOG}" ]]; then
    alert_failure "Audit log not found at ${AUDIT_LOG}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_backup re-fired the ERR trap (a second, generic alert)
  fi

  log_json "INFO" "AUDIT_LOG_BACKUP_START" "\"timestamp\":\"${TIMESTAMP}\",\"source\":\"${AUDIT_LOG}\""

  # PL13-12: the copies are created owner-only (umask 077) — with the service's default umask
  # they were 0644, i.e. every audit record (tenant, artifact and request identifiers, decisions) readable by any local
  # user. The metrics textfile is written after the umask is restored, so node_exporter can still read it.
  local prev_umask; prev_umask="$(umask)"
  umask 077

  # sidecars FIRST — each describes a prefix of the log copied below.
  local tmp_sum="${BACKUP_DIR}/.run-${TIMESTAMP}.sum" tmp_wal="${BACKUP_DIR}/.run-${TIMESTAMP}.wal"
  cp "${AUDIT_LOG}.sum" "${tmp_sum}" 2>/dev/null || true
  cp "${AUDIT_LOG}.wal" "${tmp_wal}" 2>/dev/null || true

  local probe; probe="$(chain_js probe "${AUDIT_LOG}")"
  local prefix; prefix="$(jget "${probe}" prefix)"
  local first_sha; first_sha="$(jget "${probe}" firstLineSha)"
  local last_sha; last_sha="$(jget "${probe}" lastLineSha)"

  local state="" kind="base" reason="" base="" seq=0 from=0 prev_meta_sha=""
  [[ -f "${STATE_FILE}" ]] && state="$(cat "${STATE_FILE}")"
  if [[ "${INCREMENTAL}" != "false" && -n "${state}" ]]; then
    base="$(jget "${state}" base)"; seq="$(jget "${state}" seq)"; from="$(jget "${state}" to)"
    local st_first; st_first="$(jget "${state}" firstLineSha)"
    local st_last; st_last="$(jget "${state}" lastLineSha)"
    local st_epoch; st_epoch="$(jget "${state}" baseEpoch)"
    local st_meta; st_meta="$(jget "${state}" lastMeta)"
    if [[ ! -f "${BACKUP_DIR}/${base}.meta.json" || ! -f "${BACKUP_DIR}/${st_meta}" ]]; then reason="state-without-chain"
    elif (( prefix < from )); then reason="log-shorter-than-backed-up"
    elif [[ "${first_sha}" != "${st_first}" ]]; then reason="first-line-changed"
    elif (( from > 0 )) && [[ "$(chain_js lineSha "${AUDIT_LOG}" "${from}")" != "${st_last}" ]]; then reason="backed-up-tail-changed"
    elif (( $(date -u +%s) - st_epoch >= REBASE_HOURS * 3600 )) && node "${WINDOW_JS}" 2>/dev/null; then reason="scheduled-rebase"
    else kind="segment"; prev_meta_sha="$(chain_js fileSha "${BACKUP_DIR}/${st_meta}")"
    fi
  else
    reason=$([[ "${INCREMENTAL}" == "false" ]] && echo "incremental-disabled" || echo "no-state")
  fi

  local name from_b=0 to_b="${prefix}"
  if [[ "${kind}" == "base" ]]; then
    base="audit-${TIMESTAMP}"; name="${base}"; seq=0; from_b=0
  else
    seq=$((seq + 1)); name="$(printf '%s.seg-%06d' "${base}" "${seq}")"; from_b="${from}"
  fi
  local out="${BACKUP_DIR}/${name}.log.gz"
  # byte range [from_b, to_b) of the log, streamed (no whole-file copy for a segment)
  # dd reads exactly [from_b, to_b) and stops (tail|head would SIGPIPE under pipefail while the log grows)
  dd if="${AUDIT_LOG}" iflag=skip_bytes,count_bytes skip="${from_b}" count="$((to_b - from_b))" bs=1M status=none | gzip -c > "${out}"
  [[ -f "${tmp_sum}" ]] && { gzip -c "${tmp_sum}" > "${BACKUP_DIR}/${name}.log.sum.gz"; rm -f "${tmp_sum}"; }
  # The WAL was copied before the log was measured: keep it only if its batch continues the backed-up prefix (boot
  # replays it); a batch already committed inside the prefix is omitted (restoring it makes boot refuse — every entry is
  # in the log already); a WAL that is neither fails the run (see audit-log-backup-chain.js walFit).
  local wal_disp="absent"
  if [[ -f "${tmp_wal}" ]]; then
    local fit
    if ! fit="$(chain_js wal-fit "${AUDIT_LOG}" "${to_b}" "${tmp_wal}" 2>&1)"; then
      rm -f "${tmp_wal}" "${out}" "${BACKUP_DIR}/${name}.log.sum.gz"; umask "${prev_umask}"
      alert_failure "The copied WAL does not belong with the backed-up log prefix: ${fit}"
      exit 1
    fi
    wal_disp="$(jget "${fit}" disposition)"
    if [[ "${wal_disp}" == "committed" ]]; then rm -f "${tmp_wal}"
    else gzip -c "${tmp_wal}" > "${BACKUP_DIR}/${name}.log.wal.gz"; rm -f "${tmp_wal}"; fi
  fi
  seal_backup "${out}"

  local meta="${BACKUP_DIR}/${name}.meta.json"
  chain_js meta "${meta}" "{\"v\":1,\"kind\":\"${kind}\",\"base\":\"${base}\",\"seq\":${seq},\"from\":${from_b},\"to\":${to_b},\"dataFile\":\"${name}.log.gz\",\"dataSha256\":\"$(chain_js fileSha "${out}")\",\"firstLineSha256\":$([[ -n "${first_sha}" ]] && echo "\"${first_sha}\"" || echo null),\"lastLineSha256\":$([[ -n "${last_sha}" ]] && echo "\"${last_sha}\"" || echo null),\"prevMetaSha256\":$([[ -n "${prev_meta_sha}" ]] && echo "\"${prev_meta_sha}\"" || echo null),\"sumFile\":$([[ -f "${BACKUP_DIR}/${name}.log.sum.gz" ]] && echo "\"${name}.log.sum.gz\"" || echo null),\"walFile\":$([[ -f "${BACKUP_DIR}/${name}.log.wal.gz" ]] && echo "\"${name}.log.wal.gz\"" || echo null),\"walDisposition\":\"${wal_disp}\",\"createdAt\":\"${TIMESTAMP}\"}"
  seal_meta "${meta}"
  umask "${prev_umask}"

  local base_epoch
  if [[ "${kind}" == "base" ]]; then base_epoch="$(date -u +%s)"; else base_epoch="$(jget "${state}" baseEpoch)"; fi
  local st_tmp="${STATE_FILE}.$$.tmp"
  printf '{"base":"%s","seq":%s,"to":%s,"firstLineSha":"%s","lastLineSha":"%s","baseEpoch":%s,"lastMeta":"%s"}\n' \
    "${base}" "${seq}" "${to_b}" "${first_sha}" "${last_sha}" "${base_epoch}" "${name}.meta.json" > "${st_tmp}" && mv -f "${st_tmp}" "${STATE_FILE}"

  local size_bytes; size_bytes=$(stat -c%s "${out}" 2>/dev/null || stat -f%z "${out}")
  log_json "INFO" "AUDIT_LOG_BACKUP_COMPLETE" "\"timestamp\":\"${TIMESTAMP}\",\"file\":\"${out}\",\"sizeBytes\":${size_bytes},\"kind\":\"${kind}\",\"base\":\"${base}\",\"seq\":${seq},\"from\":${from_b},\"to\":${to_b}${reason:+,\"reason\":\"${reason}\"}"

  # Retention: WHOLE chains older than the retention (never the current one); earlier full copies by their own age.
  local pruned=0
  while IFS= read -r m; do
    [[ -z "${m}" ]] && continue
    local b; b="$(basename "${m}" .meta.json)"
    [[ "${b}" == "${base}" ]] && continue
    # a chain is pruned only when its NEWEST file is past the retention (its segments may be younger than its base)
    [[ -n "$(find "${BACKUP_DIR}" -maxdepth 1 -name "${b}.*" -mtime "-${RETAIN_DAYS}" -print -quit 2>/dev/null)" ]] && continue
    rm -f "${BACKUP_DIR}/${b}".* 2>/dev/null
    pruned=$((pruned + 1))
    log_json "INFO" "AUDIT_LOG_BACKUP_PRUNED" "\"chain\":\"${b}\""
  done < <(find "${BACKUP_DIR}" -maxdepth 1 -name "audit-*.meta.json" ! -name "*.seg-*" -mtime "+${RETAIN_DAYS}" 2>/dev/null)
  while IFS= read -r f; do
    [[ -z "${f}" ]] && continue
    [[ -f "${f%.log.gz}.meta.json" ]] && continue          # part of a chain: handled above
    rm -f "${f}" "${f}.seal" "${f%.log.gz}.log.wal.gz" "${f%.log.gz}.log.sum.gz"
    pruned=$((pruned + 1))
    log_json "INFO" "AUDIT_LOG_BACKUP_PRUNED" "\"file\":\"${f}\""
  done < <(find "${BACKUP_DIR}" -maxdepth 1 -name "audit-*.log.gz" ! -name "*.seg-*" -mtime "+${RETAIN_DAYS}" 2>/dev/null)
  log_json "INFO" "AUDIT_LOG_BACKUP_RETENTION_ENFORCED" "\"retainDays\":${RETAIN_DAYS},\"prunedCount\":${pruned}"

  write_prom_metrics 1 "${size_bytes}"
}

# ── Verification (non-destructive; also the staleness/liveness check) ───

# Verify one chain: every meta's seal, then the chain itself (contiguous ranges, order, previous-meta hashes, every data
# file's sha256 — helper). Runs in the CURRENT shell (never inside $(…), so no alert is duplicated and no log line ends
# up in a captured value): sets CHAIN_JSON on success; returns 1 with CHAIN_ERROR set otherwise. The caller alerts once.
CHAIN_JSON=""; CHAIN_ERROR=""
verify_chain() {
  local base="$1" m
  CHAIN_JSON=""; CHAIN_ERROR=""
  for m in "${BACKUP_DIR}/${base}.meta.json" "${BACKUP_DIR}/${base}".seg-*.meta.json; do
    [[ -f "${m}" ]] || continue
    if ! verify_seal "${m}"; then CHAIN_ERROR="seal verification failed for ${m}"; return 1; fi
  done
  local out="${BACKUP_DIR}/.chain-check.$$"
  if node "${CHAIN_JS}" check-chain "${BACKUP_DIR}" "${base}" > "${out}" 2>&1; then
    CHAIN_JSON="$(cat "${out}")"; rm -f "${out}"; return 0
  fi
  CHAIN_ERROR="$(jget "$(cat "${out}")" error 2>/dev/null || cat "${out}")"; rm -f "${out}"; return 1
}

run_verify() {
  # PL13-03: `|| true` — with no backup at all `ls` exits non-zero and (pipefail + set -e) the run ended before the
  # alert below could ever fire.
  local latest; latest=$(ls -t "${BACKUP_DIR}"/audit-*.log.gz 2>/dev/null | head -1 || true)
  if [[ -z "${latest}" ]]; then
    alert_failure "No audit log backup found to verify in ${BACKUP_DIR}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi

  log_json "INFO" "AUDIT_LOG_BACKUP_VERIFY_START" "\"file\":\"${latest}\""

  if verify_seal "${latest}"; then
    log_json "INFO" "AUDIT_LOG_BACKUP_SEAL_OK" "\"file\":\"${latest}\""
  else
    alert_failure "Seal verification FAILED for ${latest}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi

  if ! gzip -t "${latest}" 2>/dev/null; then
    alert_failure "Backup file is not a valid gzip archive: ${latest}"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi

  local line_count chain=""
  if [[ -f "${latest%.log.gz}.meta.json" ]]; then
    # a chain run — the sealed metadata chain of its base is verified end to end (every data file's sha256); the
    # newest run's data is decompressed (bounded by one run's new bytes), not the whole log.
    local base; base="$(jget "$(cat "${latest%.log.gz}.meta.json")" base)"
    if ! verify_chain "${base}"; then
      alert_failure "Audit log backup chain ${base} failed verification: ${CHAIN_ERROR}"
      exit 1
    fi
    chain="${CHAIN_JSON}"
    line_count=$(zcat "${latest}" 2>/dev/null | wc -l)
    if [[ "${line_count}" -lt 1 && "$(jget "${chain}" bytes)" -lt 1 ]]; then
      alert_failure "Audit log backup chain ${base} holds zero lines"
      exit 1
    fi
  else
    line_count=$(zcat "${latest}" 2>/dev/null | wc -l)
    if [[ "${line_count}" -lt 1 ]]; then
      alert_failure "Backup file decompresses to zero lines: ${latest}"
      exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
    fi
  fi

  # Staleness check — proves the 5-minute RPO claim is actually being met,
  # rather than assuming a timer/CronJob that was set up once is still
  # firing. A stalled schedule is the exact failure mode this remediation
  # exists to catch.
  local latest_epoch; latest_epoch=$(stat -c%Y "${latest}" 2>/dev/null || stat -f%m "${latest}")
  local now_epoch; now_epoch=$(date -u +%s)
  local age_seconds=$((now_epoch - latest_epoch))
  if [[ "${age_seconds}" -gt "${MAX_AGE_SECONDS}" ]]; then
    alert_failure "Audit log backup is stale — newest backup is ${age_seconds}s old (max ${MAX_AGE_SECONDS}s); the 5-minute schedule may have stopped firing"
    exit 1   # PL13-03: exit, not return — a failing top-level run_verify re-fired the ERR trap (a second, generic alert)
  fi

  local size_bytes; size_bytes=$(stat -c%s "${latest}" 2>/dev/null || stat -f%z "${latest}")
  log_json "INFO" "AUDIT_LOG_BACKUP_VERIFY_OK" \
    "\"file\":\"${latest}\",\"sizeBytes\":${size_bytes},\"lineCount\":${line_count},\"ageSeconds\":${age_seconds}${chain:+,\"chain\":${chain}}"

  write_prom_metrics 1 "${size_bytes}"
}

# ── Restore ────────────────────────────────────────────────────────────

run_restore() {
  local backup_file="${2:-}"
  local target_path="${3:-}"

  if [[ -z "${backup_file}" ]]; then
    # the newest chain's BASE (the chain is restored through its newest run), else the newest full copy
    if [[ -f "${STATE_FILE}" ]]; then backup_file="${BACKUP_DIR}/$(jget "$(cat "${STATE_FILE}")" base).log.gz"
    else backup_file=$(ls -t "${BACKUP_DIR}"/audit-*.log.gz 2>/dev/null | grep -v '\.seg-' | head -1 || true); fi   # PL13-03 (see run_verify)
  fi
  if [[ -z "${backup_file}" || ! -f "${backup_file}" ]]; then
    echo "ERROR: No backup file found. Specify path as the second argument."
    exit 1
  fi
  if [[ -z "${target_path}" ]]; then
    echo "ERROR: Specify a target path as the third argument (must not already exist)."
    exit 1
  fi
  if [[ -e "${target_path}" ]]; then
    echo "ERROR: Target path already exists — refusing to restore over it: ${target_path}"
    exit 1
  fi

  verify_seal "${backup_file}" || { echo "ERROR: Seal verification failed — refusing to restore."; exit 1; }

  local meta="${backup_file%.log.gz}.meta.json"
  if [[ -f "${meta}" ]]; then
    # a chain — restore its base and every segment, in order, after verifying the whole sealed chain
    local base; base="$(jget "$(cat "${meta}")" base)"
    if [[ "$(basename "${backup_file}")" != "${base}.log.gz" ]]; then
      echo "ERROR: ${backup_file} is a segment — restore its base ${base}.log.gz (the chain is restored as a whole)."; exit 1
    fi
    if ! verify_chain "${base}"; then echo "ERROR: backup chain verification failed (${CHAIN_ERROR}) — refusing to restore."; exit 1; fi
    local chain="${CHAIN_JSON}"
    log_json "INFO" "AUDIT_LOG_RESTORE_START" "\"file\":\"${backup_file}\",\"target\":\"${target_path}\",\"chain\":${chain}"
    local tmp="${target_path}.restoring"
    gzip -dc "${backup_file}" > "${tmp}"
    local s
    for s in $(ls "${BACKUP_DIR}/${base}".seg-*.meta.json 2>/dev/null | sort); do
      gzip -dc "${BACKUP_DIR}/$(jget "$(cat "${s}")" dataFile)" >> "${tmp}"
    done
    local want_bytes; want_bytes="$(jget "${chain}" bytes)"
    local got_bytes; got_bytes=$(stat -c%s "${tmp}" 2>/dev/null || stat -f%z "${tmp}")
    local want_last; want_last="$(jget "${chain}" lastLineSha256)"
    if [[ "${got_bytes}" != "${want_bytes}" ]] || { (( want_bytes > 0 )) && [[ "$(chain_js lineSha "${tmp}" "${got_bytes}")" != "${want_last}" ]]; }; then
      echo "ERROR: the assembled log does not match the chain (bytes ${got_bytes}/${want_bytes}) — refusing to restore."; exit 1
    fi
    mv "${tmp}" "${target_path}"
    local last_meta; last_meta="${BACKUP_DIR}/$(jget "${chain}" lastMeta)"
    local sumf; sumf="$(jget "$(cat "${last_meta}")" sumFile)"
    local walf; walf="$(jget "$(cat "${last_meta}")" walFile)"
    [[ -n "${sumf}" ]] && gzip -dc "${BACKUP_DIR}/${sumf}" > "${target_path}.sum"
    if [[ -n "${walf}" ]]; then
      # re-checked against the RESTORED log (the backup-time decision is not trusted blindly)
      gzip -dc "${BACKUP_DIR}/${walf}" > "${target_path}.wal.restoring"
      local fit
      if ! fit="$(chain_js wal-fit "${target_path}" "${got_bytes}" "${target_path}.wal.restoring" 2>&1)"; then
        echo "ERROR: the backed-up WAL does not belong with the restored log (${fit}) — refusing to finish the restore; ${target_path} is left for inspection."; exit 1
      fi
      if [[ "$(jget "${fit}" disposition)" == "committed" ]]; then
        rm -f "${target_path}.wal.restoring"
        log_json "INFO" "AUDIT_LOG_RESTORE_WAL_OMITTED" "\"reason\":\"the WAL batch is already committed in the restored log\",\"fit\":${fit}"
      else mv "${target_path}.wal.restoring" "${target_path}.wal"; fi
    fi
    log_json "INFO" "AUDIT_LOG_RESTORE_COMPLETE" "\"file\":\"${backup_file}\",\"target\":\"${target_path}\",\"bytes\":${got_bytes}"
    echo "✓ Restore complete: ${target_path} (${got_bytes} bytes; base + $(jget "${chain}" segments) segments). Verify it with the production chain check before use."
    return 0
  fi

  log_json "INFO" "AUDIT_LOG_RESTORE_START" "\"file\":\"${backup_file}\",\"target\":\"${target_path}\""

  gzip -dc "${backup_file}" > "${target_path}"
  [[ -f "${backup_file%.gz}.wal.gz" ]] && gzip -dc "${backup_file%.gz}.wal.gz" > "${target_path}.wal"
  [[ -f "${backup_file%.log.gz}.log.sum.gz" ]] && gzip -dc "${backup_file%.log.gz}.log.sum.gz" > "${target_path}.sum"

  log_json "INFO" "AUDIT_LOG_RESTORE_COMPLETE" "\"file\":\"${backup_file}\",\"target\":\"${target_path}\""
  echo "✓ Restore complete: ${target_path}"
}

# ── Main ───────────────────────────────────────────────────────────────

case "${MODE}" in
  backup)  run_backup ;;
  verify)  run_verify ;;
  restore) run_restore "$@" ;;
  *)
    echo "Usage: $0 [backup|verify|restore [backup_file] [target_path]]"
    exit 1
    ;;
esac
