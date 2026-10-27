#!/usr/bin/env node
'use strict';

/**
 * — every SHIPPED deployment configuration must pass
 * the product's own production boot validator, and must not ship a memory limit below the measured
 * footprint.
 *
 * For each Kubernetes overlay (rendered with `kubectl kustomize`) and the production compose file:
 *   1. assemble the exact environment the `qodiqa` container receives (ConfigMap envFrom + env[]
 *      values; every secretKeyRef / ${VAR} interpolation becomes a strong random value — what a
 *      correctly provisioned Secret supplies);
 *   2. run the REAL validateBoot() (src/infra/config/bootValidator.js) on it, with the container's
 *      filesystem modelled: a path exists iff it lies under one of the container's volumeMounts
 *      (or /app, the image root);
 *   3. check resources: limits.memory ≥ MIN_MEMORY_LIMIT_MI and requests.memory ≥ MIN_MEMORY_REQUEST_MI
 *.
 * Exit 0 only when every configuration has zero fatal violations and adequate memory.
 * Never changes anything; never prints a secret value.
 *
 *   node scripts/deploy/validate-manifests.js [--json out.json]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const yaml = require('js-yaml');

const REPO = path.join(__dirname, '..', '..');
const { validateBoot } = require(path.join(REPO, 'src/infra/config/bootValidator'));
const { applyDeploymentMode } = require(path.join(REPO, 'src/infra/config/deploymentMode'));

// measured footprint (soak measurement: working set plateau ≈1.66 GB,
// private ≈2.05 GB incl. the ONNX inference pool; 1,537–1,612 MB RSS in the Linux image).
const MIN_MEMORY_LIMIT_MI = 2560;   // ≥ 2.5 GiB limit (plateau + headroom for boot transients)
const MIN_MEMORY_REQUEST_MI = 2048; // ≥ 2 GiB request (scheduler must reserve the steady state)

const OVERLAYS = ['single-node', 'distributed', 'examples/hsm', 'examples/vault-transit', 'examples/monitoring', 'examples/external-secrets', 'examples/tls-ingress']; // + examples
const COMPOSE = 'deploy/docker/docker-compose.prod.yml';

function strong(name) {
  if (/KEY_ENCRYPTION|INVARIANT|PEPPER/.test(name)) return crypto.randomBytes(32).toString('hex');
  if (name === 'OPENAI_API_KEY') return 'sk-' + crypto.randomBytes(30).toString('hex');
  return 'Zq' + crypto.randomBytes(24).toString('base64url');
}
function toMi(q) {
  if (q === undefined || q === null) return null;
  const m = String(q).match(/^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|K|M|G|T)?$/);
  if (!m) return null;
  const n = Number(m[1]); const u = m[2] || '';
  const f = { '': 1 / (1024 * 1024), Ki: 1 / 1024, Mi: 1, Gi: 1024, Ti: 1024 * 1024, K: 1e3 / 1048576, M: 1e6 / 1048576, G: 1e9 / 1048576, T: 1e12 / 1048576 }[u];
  return n * f;
}
function fsModel(mounts) {
  const roots = ['/app', ...mounts];
  // The validator path.resolve()s values; on a Windows host '/etc/x' becomes 'D:\etc\x' — model the
  // container's POSIX filesystem, not the host's.
  const posix = (p) => String(p).replace(/\\/g, '/').replace(/^[A-Za-z]:(?=\/)/, '');
  return (p) => { const q = posix(p); return roots.some((r) => q === r || q.startsWith(r.endsWith('/') ? r : r + '/')); };
}

function checkContainer({ name, env, mounts, resources }) {
  const e = { ...env };
  try { applyDeploymentMode(e, { _exit: (c) => { throw new Error(`deploymentMode exit ${c}`); } }); } catch (err) { return { name, error: err.message }; }
  const res = validateBoot(e, { projectRoot: '/app', fileExists: fsModel(mounts) });
  const lim = toMi(resources && resources.limits && resources.limits.memory);
  const req = toMi(resources && resources.requests && resources.requests.memory);
  const memory = {
    limitMi: lim, requestMi: req,
    ok: lim !== null && lim >= MIN_MEMORY_LIMIT_MI && req !== null && req >= MIN_MEMORY_REQUEST_MI,
    rule: `limits.memory ≥ ${MIN_MEMORY_LIMIT_MI}Mi and requests.memory ≥ ${MIN_MEMORY_REQUEST_MI}Mi`,
  };
  return { name, profile: res.profile, fatal: res.fatal, warningCount: res.warnings.length, memory, ok: res.fatal.length === 0 && memory.ok };
}

function k8s(overlay) {
  const rendered = execFileSync('kubectl', ['kustomize', path.join(REPO, 'deploy/kubernetes/overlays', overlay)], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const docs = yaml.safeLoadAll(rendered).filter(Boolean);
  const cms = Object.fromEntries(docs.filter((d) => d.kind === 'ConfigMap').map((d) => [d.metadata.name, d.data || {}]));
  const wl = docs.find((d) => ['Deployment', 'StatefulSet'].includes(d.kind) && d.spec.template.spec.containers.some((c) => c.name === 'qodiqa'));
  const c = wl.spec.template.spec.containers.find((x) => x.name === 'qodiqa');
  const env = {};
  for (const ef of c.envFrom || []) if (ef.configMapRef) Object.assign(env, cms[ef.configMapRef.name] || {});
  for (const ev of c.env || []) {
    if ('value' in ev) env[ev.name] = String(ev.value);
    else if (ev.valueFrom && ev.valueFrom.secretKeyRef) env[ev.name] = strong(ev.name);
    else if (ev.valueFrom && ev.valueFrom.configMapKeyRef) env[ev.name] = (cms[ev.valueFrom.configMapKeyRef.name] || {})[ev.valueFrom.configMapKeyRef.key];
  }
  const mounts = (c.volumeMounts || []).map((m) => m.mountPath);
  return checkContainer({ name: `k8s:${overlay} (${wl.kind}/${wl.metadata.name})`, env, mounts, resources: c.resources });
}

function compose() {
  const doc = yaml.safeLoad(fs.readFileSync(path.join(REPO, COMPOSE), 'utf8'));
  const svcName = Object.keys(doc.services).find((s) => /qodiqa/.test(s) && doc.services[s].build !== undefined) || Object.keys(doc.services).find((s) => /qodiqa|gateway|app/.test(s));
  const svc = doc.services[svcName];
  const env = {};
  const raw = Array.isArray(svc.environment) ? Object.fromEntries(svc.environment.map((l) => { const i = l.indexOf('='); return [l.slice(0, i), l.slice(i + 1)]; })) : (svc.environment || {});
  for (const [k, v] of Object.entries(raw)) {
    const s = v === null || v === undefined ? '' : String(v);
    // Compose semantics — `${VAR:-default}` / `${VAR-default}` resolve to the default (what an operator
    // gets with the variable unset; e.g. a plane switch that defaults to "false"), while `${VAR}` and `${VAR:?msg}` are
    // operator-supplied values and become strong random secrets, as before.
    env[k] = /\$\{[^}]+\}/.test(s)
      ? s.replace(/\$\{([^}:?\-]+)(:?-([^}]*))?[^}]*\}/g, (_m, n, hasDefault, def) => (hasDefault !== undefined ? def : strong(n)))
      : s;
  }
  const mounts = (svc.volumes || []).map((v) => (typeof v === 'string' ? v.split(':')[1] : v.target)).filter(Boolean);
  const dr = svc.deploy && svc.deploy.resources;
  const resources = dr ? { limits: { memory: dr.limits && dr.limits.memory && String(dr.limits.memory).replace(/^(\d+)([gmk])$/i, (_m, n, u) => n + u.toUpperCase() + 'i') },
    requests: { memory: dr.reservations && dr.reservations.memory && String(dr.reservations.memory).replace(/^(\d+)([gmk])$/i, (_m, n, u) => n + u.toUpperCase() + 'i') } } : null;
  return checkContainer({ name: `compose:${COMPOSE} (${svcName})`, env, mounts, resources });
}

// the distributed overlay is shipped for non-production use and future but production
// REFUSES it (its audit chain has no signed checkpoints or anchors). For that overlay the gate passes only when the
// validator refuses it for EXACTLY that reason and nothing else — any other fatal, or no refusal at all, is a FAIL.
const EXPECTED_REFUSAL = { distributed: { variable: 'QODIQA_DEPLOYMENT_MODE', rule: 'audit.anchoring' } };
function applyExpectedRefusal(overlay, r) {
  const exp = EXPECTED_REFUSAL[overlay];
  if (!exp || r.error) return r;
  const fatal = r.fatal || [];
  // the distributed refusal must be present, and every fatal must come from the same anchoring rule (a distributed
  // chain cannot be anchored, so its missing anchoring config is the same gap) — any OTHER rule failing is a real FAIL
  const exact = fatal.some((f) => f.variable === exp.variable && f.rule === exp.rule) && fatal.every((f) => f.rule === exp.rule);
  return { ...r, ok: !!(exact && r.memory && r.memory.ok), expectedRefusal: exp, refusedAsExpected: exact,
    note: exact ? 'refused in production as expected' : 'EXPECTED a production refusal for exactly the distributed reason' };
}

function main() {
  const results = [];
  for (const o of OVERLAYS) { try { results.push(applyExpectedRefusal(o, k8s(o))); } catch (err) { results.push({ name: `k8s:${o}`, error: err.message.split('\n')[0] }); } }
  try { results.push(compose()); } catch (err) { results.push({ name: `compose:${COMPOSE}`, error: err.message }); }
  let failed = 0;
  for (const r of results) {
    const ok = r.ok === true;
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${r.name}${r.note ? `  — ${r.note}` : ''}`);
    if (r.error) console.log(`      error: ${r.error}`);
    if (!r.refusedAsExpected) for (const f of r.fatal || []) console.log(`      fatal ${f.variable}: ${f.message}`);
    if (r.memory && !r.memory.ok) console.log(`      memory: limit ${r.memory.limitMi}Mi / request ${r.memory.requestMi}Mi — need ${r.memory.rule}`);
  }
  const i = process.argv.indexOf('--json');
  if (i > 0) fs.writeFileSync(process.argv[i + 1], JSON.stringify({ generatedAt: new Date().toISOString(), minMemory: { MIN_MEMORY_LIMIT_MI, MIN_MEMORY_REQUEST_MI }, results }, null, 2));
  console.log(failed ? `\n${failed} configuration(s) FAIL` : '\nALL shipped deployment configurations pass the production boot validator and memory sizing');
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main();
module.exports = { toMi, fsModel, checkContainer, applyExpectedRefusal, EXPECTED_REFUSAL, MIN_MEMORY_LIMIT_MI, MIN_MEMORY_REQUEST_MI };
