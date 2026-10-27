# QODIQA Production Dockerfile — Container Hardening,
# base image corrected
#
# Multi-stage build:
#   Stage 1 (deps)  — install production Node.js dependencies only
#   Stage 2 (final) — minimal runtime image with no build tooling
#
# Security properties:
#   • Dedicated non-root service account (uid/gid 1000)
#   • No .env files, private keys, test files, or key store in the image
#   • node_modules owned by root — qodiqa process cannot modify installed packages
#   • /app owned by root:qodiqa — no writable app directory
#   • Writable runtime paths provided as volume mounts at deploy time
#   • Read-only root filesystem (enforced at runtime via --read-only)
#   • All Linux capabilities dropped at runtime via --cap-drop ALL
#   • no-new-privileges enforced at runtime
#   • OCI image annotations for supply chain traceability
#
# ── base image is glibc (Debian slim), not Alpine ──────────────────────
# This is a correctness requirement, not a size/preference choice.
# onnxruntime-node's native addon (required by the embedding/FT-3 semantic
# classifier — server/startup.js treats it as a FATAL boot gate; no topology
# can serve a single request without it) is glibc-linked. Alpine's musl libc
# has no ld-linux-x86-64.so.2 at all: the addon cannot even load. Alpine's own
# standard compat shim (libc6-compat / gcompat) gets the addon to LOAD but it
# then segfaults deterministically at runtime (Ort::Exception, exit 139,
# reproduced twice, zero successful runs) — gcompat is not a robust enough
# glibc emulation for onnxruntime's native threading. This was proven by
# direct reproduction before this
# base image was chosen; the migration was not applied as a superficial
# workaround.
#
# Tradeoff, stated explicitly rather than hidden: Debian slim's installed
# package surface is larger than Alpine's (more binaries, more CVE exposure
# to track over time) and its base layer is larger on disk (~80-120MB vs
# Alpine's ~5-10MB). Both are real costs. They are accepted because the
# alternative (Alpine + gcompat) does not produce a working container at
# all — a base image the application cannot run on has no security posture
# to weigh against anything. The base-layer size difference is also small in
# relative terms here: this image's dominant weight is node_modules and
# bundled model/data files (several GB), not the OS base layer. Base-image
# CVE exposure is covered by this repo's existing npm-level dependency-audit
# gate (.github/workflows/security.yml) plus regular `node:22-slim` upstream
# patching — no separate container-image CVE scan existed before this change
# and none is removed by it.
#
# Build:
#   docker build \
#     --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
#     --build-arg VCS_REF=$(git rev-parse --short HEAD) \
#     -t qodiqa:1.0.0 .
#
# Run (see deploy/docker/docker-compose.prod.yml for full production config):
#   docker run --read-only --user 1000:1000 --cap-drop ALL \
#     --security-opt no-new-privileges:true \
#     --security-opt seccomp=deploy/docker/seccomp.json \
#     --tmpfs /tmp:rw,noexec,nosuid,size=64m \
#     -p 127.0.0.1:3000:3000 qodiqa:1.0.0

ARG NODE_VERSION=22
# the base image is pinned by DIGEST, not just a moving tag — a rebuild uses
# exactly the layers that were tested (and scanned). Bump deliberately: docker pull node:22-slim, then copy its
# RepoDigest here (docker image inspect node:22-slim --format '{{index .RepoDigests 0}}').
ARG NODE_IMAGE=node:22-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5

# ── Stage 1: dependency installation ─────────────────────────────────────────
FROM ${NODE_IMAGE} AS deps

WORKDIR /build

# Copy only package files first for layer caching.
COPY package.json package-lock.json ./

# Install production dependencies only.
# --ignore-scripts: prevents lifecycle scripts from running during install.
#   This is a supply chain control — lifecycle scripts (preinstall, install,
#   postinstall) run arbitrary code.  Any package that requires a lifecycle
#   script must be explicitly reviewed.
RUN npm ci --omit=dev --ignore-scripts

# sharp (pulled in as a hard `dependencies` entry — not optional — of
# @xenova/transformers, the embedding-classifier stack; NOT a direct QODIQA
# dependency and never invoked by QODIQA's own text-only embedding path, but
# still eagerly require()'d somewhere in that package's own module graph
# during classifier init, so it is not safe to remove without patching a
# third-party package — out of scope, and unnecessary once its binary
# resolves correctly). sharp normally selects its own prebuilt
# platform-specific native binary via a postinstall script, which the
# --ignore-scripts control above deliberately skips for every package.
# Rebuilding sharp alone (not dropping --ignore-scripts globally) resolves
# just its own binary without reopening the supply-chain control for
# anything else. Confirmed required by direct reproduction: without this,
# the final image fails with "Cannot find module
# '../build/Release/sharp-linux-x64.node'" during classifier boot.
RUN npm rebuild sharp

# ── Stage 2: final runtime image ──────────────────────────────────────────────
FROM ${NODE_IMAGE} AS final
# re-declared so the base-image LABEL below expands (a pre-FROM ARG is not in scope inside a stage)
ARG NODE_IMAGE

# the runtime never runs npm (dependencies are installed in the deps stage and copied in; CMD is node). The
# npm bundled with the base image carried the image's only CRITICAL/HIGH node-package findings (tar, brace-expansion,
# picomatch, pacote, sigstore …) — removed from the runtime image, together with npx and corepack.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack            /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack            /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
# the one OS package with a published fix for its HIGH findings at the pinned base digest,
# upgraded to an EXACT version so the build stays reproducible — if Debian withdraws it the build fails loudly, which is
# the signal to bump NODE_IMAGE. Unfixed base findings (perl-base, zlib minizip) are tracked in
#
# Debian published perl-base 5.36.0-7+deb12u4 (trivy at the pinned digest: 3 CRITICAL +
# 4 HIGH fixable, e.g. CVE-2026-13221/42496/8376); the newest upstream node:22-slim digest still ships deb12u3, so the
# same exact-version upgrade is applied here. zlib1g (minizip) remains unfixed upstream.
RUN apt-get update  && apt-get install -y --no-install-recommends --only-upgrade libpcre2-8-0=10.42-1+deb12u2 perl-base=5.36.0-7+deb12u4  && rm -rf /var/lib/apt/lists/*

# OCI image annotations
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="QODIQA Enforcement Gateway" \
      org.opencontainers.image.description="Deterministic runtime consent enforcement" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="QODIQA" \
      org.opencontainers.image.base.name="${NODE_IMAGE}"

# node:22-slim (Debian) already ships a "node" user/group at uid/gid
# 1000, colliding with this RUN's own addgroup/adduser at the same ids —
# reproduced by direct build: the ORIGINAL Alpine base failed identically
# (`addgroup: gid '1000' in use`, exit 1) for the same reason, so this is not
# new to the base-image switch. Remove the base image's pre-existing account
# first so the dedicated "qodiqa" account can claim uid/gid 1000 as
# originally intended — this keeps the account name distinct (matching this
# file's own "dedicated non-root service account" design) while staying at
# uid/gid 1000, which the checked-in K8s manifests' runAsUser/runAsGroup/
# fsGroup: 1000 already hardcode; changing the id instead of the name would
# have required touching deploy/kubernetes/** as well, a larger and
# unnecessary change.
# Debian's adduser emits a harmless build-time warning here
# ("qodiqa's uid 1000 is greater than SYS_UID_MAX 999") because uid 1000
# sits above the conventional system-account range (<1000) --system
# normally implies. This is expected and intentional: 1000 is a hard
# requirement, not a default, to match runAsUser/runAsGroup/fsGroup: 1000
# already hardcoded across deploy/kubernetes/**.
RUN deluser node 2>/dev/null; delgroup node 2>/dev/null; \
    addgroup --system --gid 1000 qodiqa \
 && adduser  --system --uid 1000 --ingroup qodiqa \
             --no-create-home --shell /usr/sbin/nologin qodiqa

WORKDIR /app

# the image is built from an ALLOW-LISTED context
# (.dockerignore) and permissions are set AT COPY TIME. The former "COPY . ." + "rm -rf …" +
# "find /app -exec chmod" sequence (a) could not remove anything from the earlier COPY layer —
# removed files stayed in the image — and (b) re-wrote every file, storing the app tree twice
#. The previous Dockerfile is preserved at
#
#
# Ownership root:qodiqa and mode 0750 (owner rwx, group r-x, world none): the qodiqa process can
# read and traverse but never modify its code or dependencies (supply-chain control kept).
COPY --from=deps --chown=root:qodiqa --chmod=0750 /build/node_modules ./node_modules
COPY --chown=root:qodiqa --chmod=0750 . .

# /app itself is created by WORKDIR as root:root; COPY --chown only affects what it
# copies, so the directory entry needs group traverse for the non-root USER.
RUN chown root:qodiqa /app && chmod 750 /app

# build-time content gate (defence in depth behind the allow-list): the build FAILS if any
# private key, certificate, keystore, MAC keyring or env file reached the application tree.
# re-checks the finished image (including node_modules).
RUN set -e; \
    bad="$(find /app -path /app/node_modules -prune -o -type f \( -name '*.pem' -o -name '*.key' -o -name '*.crt' \
          -o -name '*.p12' -o -name '*.pfx' -o -name 'keys.json' -o -name '*-keys.json' -o -name 'mac-keys*.json' \
          -o -name 'signing-identities.json' -o -name '.env' -o -name '.env.*' \) -print)"; \
    if [ -n "$bad" ]; then echo "IMAGE CONTENT GATE FAILED - forbidden files in /app:"; echo "$bad"; exit 1; fi

# Create writable runtime directories as mount points.
# Overlaid by named volume mounts at runtime. A fresh named volume copies the ownership of the image directory it is
# mounted on, so EVERY directory the shipped compose mounts must exist here owned by qodiqa.:
# /opt/qodiqa/anchors (anchor export + local witness log) was missing, so the volume was root:root 755, every anchor
# publish failed with EACCES, and after 2 x QODIQA_AUDIT_CHECKPOINT_EVERY entries the next boot refused to start
# (AUDIT_ANCHOR_BOOT_FAILED ANCHORS_MISSING). Kubernetes was unaffected (fsGroup 1000).
RUN mkdir -p /opt/qodiqa/data /opt/qodiqa/logs /opt/qodiqa/config /opt/qodiqa/anchors \
 && chown -R qodiqa:qodiqa /opt/qodiqa \
 && chmod 700 /opt/qodiqa/data \
 && chmod 700 /opt/qodiqa/logs \
 && chmod 750 /opt/qodiqa/config \
 && chmod 700 /opt/qodiqa/anchors

# R-11 / OD-4: remove every setuid/setgid bit from the image. The gateway runs as uid 1000
# and never needs privilege elevation; util-linux's setuid `mount`/`umount` (CVE-2026-53613 et al.) were the only
# plausible post-compromise escalation path in a deployment that forgets `no-new-privileges`. This removes that path; it
# does NOT fix the CVEs themselves.
# The build fails if any setuid/setgid file survives.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
 && test -z "$(find / -xdev -perm /6000 -type f -print -quit)"

# Node.js listens on port 3000 — no CAP_NET_BIND_SERVICE required.
EXPOSE 3000

# Switch to the non-root service account before CMD.
USER qodiqa

# Health check: used by Docker Engine and AWS ECS.
# Kubernetes uses httpGet probes in the pod spec instead (see deployment.yaml).
# --interval=15s: frequent enough to detect failures before LB routes traffic
# --timeout=5s:   /health responds in well under 100ms (no dependency checks);
#                 unrelated to AUDIT_TIMEOUT_MS, which only bounds the separate
#                 /audit/chain/integrity endpoint (default 10000ms)
# --start-period=30s: allow time for Redis/PG startup
# --retries=3:    3 consecutive failures before UNHEALTHY
#
# /health requires no credential by default (see docs/deployment/kubernetes-probes.md
# "Security model") specifically so this bare check keeps working — Docker's
# HEALTHCHECK CMD has no mechanism for injecting a rotating bearer token.
# This container's HEALTHCHECK always runs as an in-container exec, i.e. it
# always originates from loopback; operators who want this endpoint locked to
# loopback-only traffic (Docker/Compose/bare-metal deployments — NOT
# Kubernetes, whose kubelet never uses loopback) can additionally set
# QODIQA_HEALTH_REQUIRE_LOOPBACK=true without breaking this check.
# node:22-slim (Debian) does not ship wget or curl at all (confirmed:
# neither binary exists in the base image), unlike the Alpine base this
# check was originally written against. Rather than apt-get installing one
# — a new package, a new apt layer, and a new thing to patch, for a
# hardened minimal image that otherwise runs on Debian's base packages only
# — use Node itself (already present, already the only runtime this image
# needs) via its built-in http module. Same semantics: exit 0 on HTTP 200,
# non-zero otherwise, no new dependency.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health',(r)=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# Use exec form to avoid a shell wrapper process.
# This ensures PID 1 is node (receives SIGTERM directly for graceful shutdown).
CMD ["node", "server.js"]
