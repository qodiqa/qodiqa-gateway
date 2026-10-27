# QODIQA Backup / DR Image — remediation
#
# A separate, purpose-built image for the scheduled backup, verification,
# and restore-validation CronJobs (deploy/kubernetes/base/backup-cronjobs.yaml
# and deploy/systemd/*.service).
#
# Why a second image rather than reusing the production Dockerfile's image:
# that image deliberately strips `scripts/` and `docs/` from the final layer
# to minimize
# the request-serving gateway's attack surface. scripts/pg-backup.sh and the
# entire scripts/dr/ family live exactly there, and scripts/dr/cycle.js's
# restore-validation probes (scripts/dr/probes/*.js) load the REAL
# production modules (src/core/audit/audit-log.js, policy/policyStore.js,
# services/artifact/keyStore.js) to prove a restore is actually functional,
# not just byte-identical — so this image otherwise mirrors the production
# image's COPY set (same modules available, same non-root hardening) and
# only differs in what it keeps vs. strips, plus the addition of
# PostgreSQL client tools and bash.
#
# Build:
#   docker build -f deploy/docker/backup.Dockerfile -t qodiqa-backup:1.0.0 .
#
# Run (see deploy/kubernetes/base/backup-cronjobs.yaml for the Kubernetes form):
#   docker run --rm --user 1000:1000 --cap-drop ALL \
#     --security-opt no-new-privileges:true \
#     -v qodiqa-pg-backups:/backups/pg \
#     --env-file deploy/env/production.env.example \
#     qodiqa-backup:1.0.0 /app/scripts/pg-backup.sh full daily

ARG NODE_VERSION=22
ARG ALPINE_VERSION=3.21
# the base image is pinned by DIGEST, like the production Dockerfile — a
# rebuild uses exactly the layers that were tested. Value = RepoDigest of node:22-alpine3.21 (Node 22.21.1, image
# built 2025-10-29) as cached on the build host; the alpine3.21 tag line no longer moves. Bump deliberately:
# docker pull node:<ver>-alpine<alpine>, then copy `docker image inspect --format '{{index .RepoDigests 0}}'` here.
ARG NODE_IMAGE=node:22.21.1-alpine3.21@sha256:af8023ec879993821f6d5b21382ed915622a1b0f1cc03dbeb6804afaf01f8885

# ── Stage 1: dependency installation (identical to the production Dockerfile) ─
FROM ${NODE_IMAGE} AS deps
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

# ── Stage 2: final runtime image ──────────────────────────────────────────────
FROM ${NODE_IMAGE} AS final

# re-declared for this stage — ARGs declared before the first FROM are
# visible to FROM instructions themselves but not to instructions AFTER a
# FROM unless re-declared, so without this the org.opencontainers.image.base.name
# LABEL below silently expanded ALPINE_VERSION to an empty string
# (BuildKit's own "UndefinedVar" lint warning, confirmed via direct build).
# Purely cosmetic (label precision only) — no functional or security impact.
ARG NODE_VERSION
ARG ALPINE_VERSION
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="QODIQA Backup / DR Tooling" \
      org.opencontainers.image.description="Scheduled PostgreSQL backup, verification, and DR restore-validation for QODIQA" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="QODIQA" \
      org.opencontainers.image.base.name="node:${NODE_VERSION}-alpine${ALPINE_VERSION}"

# postgresql-client: pg_dump / pg_restore / pg_basebackup / psql / pg_isready
#   (scripts/pg-backup.sh). bash: scripts/pg-backup.sh requires real bash
#   (`set -euo pipefail`), not Alpine's default ash/busybox sh. openssl +
#   coreutils: its HMAC/SHA-256 integrity seal. curl: ALERT_WEBHOOK_URL posts.
# the client major MUST equal the server's. With postgresql17-client against the shipped
# postgres:16.15 (deploy/docker/docker-compose.prod.yml) the dump was restorable by no shipped tool: pg_restore 17
# emits `SET transaction_timeout`, which PostgreSQL 16 rejects, and pg_restore 16 cannot read a 17 archive
# ("unsupported version (1.16) in file header"). Default = 16, the shipped compose server. For another server major
# (the distributed overlay runs postgres:17.11; a managed server may differ) build a matching image:
#   docker build -f deploy/docker/backup.Dockerfile --build-arg PG_CLIENT_MAJOR=17 -t qodiqa-backup:<ver>-pg17 .
# scripts/dr/pgDump.js and scripts/pg-backup.sh refuse a major mismatch at backup time instead of at disaster time.
ARG PG_CLIENT_MAJOR=16
RUN apk add --no-cache bash "postgresql${PG_CLIENT_MAJOR}-client" openssl coreutils curl

# — the same hardening as the production Dockerfile's which this image never
# received (its HIGH/CRITICAL trivy gate failed identically at rc-5e7eef77 and rc-fb600df1):
#  1. No backup, verify, restore-validation or WAL job runs npm/npx/corepack/yarn (every command is `node scripts/…` or
#     `bash scripts/…`; dependencies come from the deps stage) — the npm bundled with the base image carried the image's
#     node-package findings (tar CRITICAL, glob, minimatch, brace-expansion, picomatch, pacote, sigstore, ip-address).
#     Removed from the runtime image.
#  2. The base digest stays pinned (tested layers, same Node 22.21.1); the OS packages with a published Alpine 3.21 fix
#     are upgraded to EXACT versions so the build stays reproducible — if Alpine withdraws them the build fails loudly,
#     which is the signal to bump NODE_IMAGE: musl/musl-utils 1.2.5-r9 → 1.2.5-r11 (CVE-2026-40200),
#     zlib 1.3.1-r2 → 1.3.2-r1 (CVE-2026-22184).
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
           /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && apk add --no-cache --upgrade musl=1.2.5-r11 musl-utils=1.2.5-r11 zlib=1.3.2-r1

# (post-H113 integration audit): node:22-alpine already ships a "node"
# user/group at uid/gid 1000, colliding with this RUN's own addgroup/adduser
# at the same ids — reproduced by direct build (`addgroup: gid '1000' in
# use`, exit 1). This is the EXACT defect already found and fixed for
# the main production Dockerfile (see its own "final" stage's identical
# comment) — that fix was never propagated to this second image, meaning
# this image had never successfully built's era. Same fix:
# remove the base image's pre-existing account first so the dedicated
# "qodiqa" account can claim uid/gid 1000, matching the K8s CronJob
# manifests' runAsUser/runAsGroup/fsGroup: 1000 (deploy/kubernetes/base/
# backup-cronjobs.yaml) exactly as the production image's account does.
RUN deluser node 2>/dev/null; delgroup node 2>/dev/null; \
    addgroup --system --gid 1000 qodiqa \
 && adduser  --system --uid 1000 --ingroup qodiqa \
             --no-create-home --shell /sbin/nologin qodiqa

WORKDIR /app

# the build context is now an ALLOW-LIST (deploy/docker/backup.Dockerfile.dockerignore) and the
# permissions are set AT COPY TIME (root:qodiqa, 0750 — the qodiqa process can read and execute, never modify, its
# code; this also makes scripts/pg-wal-archive.sh executable, which the former 0640 `find … chmod` pass did not).
# The former sequence — `COPY . .` of a deny-listed context, then `RUN rm -rf`, then `find /app -exec chmod` —
# (a) could not remove anything from the earlier COPY layer (secret material from a developer tree stayed in the
# image) and (b) rewrote every file, storing the tree twice. Same fix as for the production Dockerfile.
COPY --from=deps --chown=root:qodiqa --chmod=0750 /build/node_modules ./node_modules
COPY --chown=root:qodiqa --chmod=0750 . .

# Same sensitive-file removal as the production Dockerfile, EXCEPT scripts/
# and docs/ are kept — this image's entire purpose is running scripts/, and
# docs/ is referenced by some backup-scheduling error messages / runbooks.
# now defence in depth only — the allow-listed context should never contain any of these (and a `rm` in a
# later layer cannot un-ship a file anyway); the build-time content gate below is what actually fails the build.
RUN rm -rf \
    .env \
    .env.* \
    .gitleaks.toml \
    private.pem \
    *.pem \
    *.key \
    data/ \
    appendonlydir/ \
    dump.rdb \
    *.rdb \
    *.aof \
    *.backup \
    audit.log \
    audit.log.wal \
    audit.log.sum \
    adversarial.harness.js \
    pipeline.harness.js \
    guarantee.demo.js \
    examples/quickstart.js \
    test/support/jest.setup.js \
    jest_output.txt \
    redteam.*.js \
    failclosed.test.js \
    tools/verify/verify.external.js \
    tools/verify/verify_external.py \
    sbom.cdx.json \
    gitleaks-report.json \
    test/ \
    .github/

# (post-H113 integration audit): /app itself is created by the earlier
# WORKDIR instruction as root:root — every COPY --chown above only chowns
# what it COPIES, never the pre-existing /app directory entry itself. Left
# unfixed, /app stays group=root mode 750, and the qodiqa user (USER qodiqa
# below) — not in group root — falls through to the "other" permission
# class, which has zero access: every single command this image exists to
# run (node scripts/dr/*.js, scripts/pg-backup.sh) would fail immediately,
# unable to read anything under /app at all. This is the exact same defect
# already found and fixed for the main production Dockerfile (see its
# own "/app itself is created by the earlier WORKDIR..." comment) —
# never propagated to this second image, and never previously reachable to
# discover here since the addgroup/adduser collision fixed above prevented
# this image from ever completing a build in the first place. Fixed the
# same way, before the chmod pass below.
RUN chown root:qodiqa /app && chmod 750 /app

# build-time content gate (same as the production Dockerfile's gate) — the build FAILS if any
# private key, certificate, keystore, MAC keyring, signing-identity store or env file reached the application tree.
RUN set -e; \
    bad="$(find /app -path /app/node_modules -prune -o -type f \( -name '*.pem' -o -name '*.key' -o -name '*.crt' \
          -o -name '*.p12' -o -name '*.pfx' -o -name 'keys.json' -o -name '*-keys.json' -o -name 'mac-keys*.json' \
          -o -name 'signing-identities.json' -o -name '.env' -o -name '.env.*' \) -print)"; \
    if [ -n "$bad" ]; then echo "IMAGE CONTENT GATE FAILED - forbidden files in /app:"; echo "$bad"; exit 1; fi

# the former `find /app -exec chmod` pass is gone (modes are set by COPY --chmod above; rewriting every
# file stored the whole tree a second time). Only the writable runtime mount points are created here.
RUN mkdir -p /opt/qodiqa/data /opt/qodiqa/logs /opt/qodiqa/config \
 && chown -R qodiqa:qodiqa /opt/qodiqa

USER qodiqa

# No CMD/ENTRYPOINT — each CronJob/systemd unit's own command selects which
# script to run: scripts/pg-backup.sh {full|incremental|verify} [tier],
# node scripts/dr/backup.js, node scripts/dr/verify.js, node scripts/dr/cycle.js.
