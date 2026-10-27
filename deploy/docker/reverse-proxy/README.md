# Reverse-proxy reference

> **`nginx.conf.template` is NOT shipped in this repository.** The compose fragment mounts an **operator-supplied**
> `deploy/docker/reverse-proxy/nginx.conf` — write your own nginx (or other proxy) configuration there, following the
> requirements below. The rest of this page describes the design those requirements come from.

`nginx.conf.template` is a provider-neutral, self-hosted TLS-termination
reference for the `docker-compose.prod.yml` single-host reference topology.
It is **not applied automatically** — `docker-compose.prod.yml` itself is
unchanged, matching its own long-standing header comment ("place a
reverse proxy (nginx/caddy) in front", never mandating a specific one).

## What this is

- A template. Every `REPLACE_WITH_REAL_..._BEFORE_DEPLOY` marker must be
  replaced with a real value before this config is used against real
  traffic.
- Provider-neutral: no cloud, no CA, no domain, no hosting choice is baked
  in. It works identically on any host that can run a container.
- Scoped to the single-host Compose topology. For Kubernetes, see
  `../kubernetes/overlays/examples/tls-ingress/` instead — its Ingress +
  cert-manager path replaces nginx's job.

## What this is not

- Not a substitute for a real TLS certificate. `ssl_certificate`/
  `ssl_certificate_key` are placeholder paths — you must mount real files
  (from your chosen CA, ACME client, or secrets manager) at whatever path
  you point these two directives at.
- Not a substitute for DNS. `server_name` is a placeholder — replace it
  with the real domain once one exists (dimension 4, still an
  external dependency).
- Not a change to QODIQA's own security posture. `/metrics`' auth,
  `/health`/`/ready`'s deliberately-open-by-default behavior, and
  `proxyValidation.js`'s forwarded-header validation are all unchanged —
  this proxy forwards the headers that validation expects and does not
  attempt to duplicate, bypass, or weaken any of it.

## How to use it (once you have a real domain and certificate)

1. Add an nginx service to your own Compose override (see
   `compose-fragment.example.yml` alongside this file for the exact shape
   validated Part D — read-only rootfs, non-root, `cap_drop: ALL`,
   joined only to the `frontend` network, matching `qodiqa`'s own posture).
2. Mount your real certificate and key at the paths you choose, updating
   `ssl_certificate`/`ssl_certificate_key` in your own `nginx.conf`
   (operator-supplied; see the status note above) to match.
3. Replace `REPLACE_WITH_REAL_DOMAIN_BEFORE_DEPLOY` with your real domain in
   both `server_name` directives.
4. Publish 8080/8443 on the host (or 80/443 via your platform's own
   privileged-port handling — this template's internal listen ports are
   unprivileged so the proxy container itself never needs `NET_BIND_SERVICE`
   or root).

## What validated locally

The design was validated locally against: HTTPS termination, HTTP→HTTPS redirect, `/health`/
`/ready`/`/metrics` through the proxy, SSE streaming compatibility,
forwarded-header correctness, continued Postgres/Redis unreachability, TLS
protocol/certificate rejection, and continued read-only-rootfs/seccomp/
capability/network-isolation posture for the proxy container itself — all
using a local-test-only, obviously non-production certificate
(`CN=qodiqa-h105-local-test.invalid`, RFC 2606 reserved TLD), never a real
one.

## seccomp profile

`compose-fragment.example.yml` now pins `security_opt: seccomp:./seccomp-nginx.json`
(`../seccomp-nginx.json` relative to this README, `deploy/docker/seccomp-nginx.json`
from the repo root) instead of leaving the proxy container under Docker's own
unrestricted default profile — a gap had disclosed but not fixed
("proxy container uses Docker's default seccomp profile, not QODIQA's bespoke
one"). `deploy/docker/seccomp.json` (qodiqa's own profile) could not simply be
reused: it is Node-oriented and does not allow the syscalls nginx's
master→worker privilege-drop needs. `seccomp-nginx.json` is a dedicated,
minimal, deny-by-default profile empirically derived and verified — see that
file's own header comment for the full syscall-by-syscall rationale. The evidence behind it
(diagnostic `SCMP_ACT_LOG` run, real `SCMP_ACT_ERRNO` boot-and-serve
verification, worker-privilege-drop confirmation, and a second iteration
after the first real boot surfaced a `io_setup() failed` log-spam defect the
diagnostic run alone had missed).
