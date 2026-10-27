#!/usr/bin/env bash
# QODIQA DR backup -> verify -> retention sequence.
# Invoked by qodiqa-dr-backup.service — kept as a tiny wrapper script rather
# than an inline systemd ExecStart, since ExecStart does not support a
# multi-line shell pipeline directly. Mirrors the equivalent shell block in
# deploy/kubernetes/base/backup-cronjobs.yaml's qodiqa-dr-backup CronJob exactly.
# 2026-10-06: the backup this run wrote is verified BEFORE retention
# prunes anything, and verify.js writes its own metrics textfile
# (<QODIQA_BACKUP_METRICS_FILE minus .prom>_verify.prom) instead of replacing
# backup.js's metrics in the same file.
set -euo pipefail

QODIQA_DR_BACKUP_DIR="${QODIQA_DR_BACKUP_DIR:-/var/backups/qodiqa-dr}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${QODIQA_DR_BACKUP_DIR}/qodiqa-backup-${TIMESTAMP}"

node /opt/qodiqa/scripts/dr/backup.js "${OUT_DIR}" --with-postgres

QODIQA_BACKUP_METRICS_FILE="${QODIQA_BACKUP_METRICS_FILE:+${QODIQA_BACKUP_METRICS_FILE%.prom}_verify.prom}" \
  node /opt/qodiqa/scripts/dr/verify.js "${OUT_DIR}"

node /opt/qodiqa/scripts/dr/retention.js "${QODIQA_DR_BACKUP_DIR}" \
  --daily="${QODIQA_DR_RETAIN_DAILY:-7}" \
  --weekly="${QODIQA_DR_RETAIN_WEEKLY:-4}" \
  --monthly="${QODIQA_DR_RETAIN_MONTHLY:-12}"
