'use strict';

/**
 *the SHIPPED deployment configurations (every YAML under deploy/ plus the
 * production compose file) must not quietly weaken production.
 *
 *   SD-01 no shipped config pre-sets QODIQA_TRUSTED_PROXY_BROAD_ACK (an operator attestation must be the operator's)
 *   SD-02 no shipped TRUSTED_PROXY trusts a broad private range / everything
 *   SD-03 the validator still refuses a broad range in production without the acknowledgement, warns with it
 *   SD-04 no shipped config carries an anchoring waiver; every non-distributed production config sets audit anchoring
 *   SD-05 the shipped distributed overlay is refused in production (validate-manifests' expected refusal)
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { validateBoot } = require('../../src/infra/config/bootValidator');
const { applyExpectedRefusal } = require('../deploy/validate-manifests');

const REPO = path.join(__dirname, '..', '..');
function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
    const p = path.join(dir, d.name);
    // Helm chart templates are Go templates, not YAML; their posture is pinned by SD-10 below (text of the templates) and by `helm template` + kubeconform
    if (d.isDirectory() && d.name === 'templates' && /[\\/]helm[\\/]/.test(p)) return [];
    return d.isDirectory() ? walk(p) : (/\.ya?ml$/.test(d.name) ? [p] : []);
  });
}
const FILES = walk(path.join(REPO, 'deploy'));

// every key=value pair from ConfigMap data and container env / compose environment blocks
function envPairs(doc) {
  const out = [];
  const visit = (o) => {
    if (!o || typeof o !== 'object') return;
    if (o.kind === 'ConfigMap' && o.data) for (const [k, v] of Object.entries(o.data)) out.push([k, String(v)]);
    if (Array.isArray(o.env)) for (const e of o.env) if (e && e.name && e.value !== undefined) out.push([e.name, String(e.value)]);
    if (o.environment && typeof o.environment === 'object' && !Array.isArray(o.environment)) for (const [k, v] of Object.entries(o.environment)) out.push([k, String(v)]);
    for (const v of Object.values(o)) visit(v);
  };
  visit(doc);
  return out;
}
const ALL = FILES.flatMap((f) => yaml.loadAll(fs.readFileSync(f, 'utf8')).filter(Boolean).flatMap((d) => envPairs(d).map(([k, v]) => ({ f: path.relative(REPO, f), k, v }))));
const BROAD = /(^|,)\s*(uniquelocal|linklocal|true|\*|all|10\.0\.0\.0\/8|172\.16\.0\.0\/12|192\.168\.0\.0\/16|fc00::\/7|169\.254\.0\.0\/16|fe80::\/10|[^,]*\/0)\s*(,|$)/i;

describe('shipped deployment posture', () => {
  test('the scan actually found the shipped configs', () => {
    expect(FILES.length).toBeGreaterThan(10);
    expect(ALL.some((e) => e.k === 'TRUSTED_PROXY')).toBe(true);
  });

  test('SD-01 no shipped config pre-sets the broad-proxy acknowledgement', () => {
    expect(ALL.filter((e) => e.k === 'QODIQA_TRUSTED_PROXY_BROAD_ACK')).toEqual([]);
  });

  test('SD-02 no shipped TRUSTED_PROXY trusts a broad private range', () => {
    expect(ALL.filter((e) => e.k === 'TRUSTED_PROXY' && BROAD.test(e.v))).toEqual([]);
  });

  test('SD-03 production still refuses a broad range without the acknowledgement, and only warns with it', () => {
    const base = { NODE_ENV: 'production', TRUSTED_PROXY: 'loopback,uniquelocal' };
    expect(validateBoot(base).fatal.some((f) => f.variable === 'TRUSTED_PROXY')).toBe(true);
    const acked = validateBoot({ ...base, QODIQA_TRUSTED_PROXY_BROAD_ACK: 'true' });
    expect(acked.fatal.some((f) => f.variable === 'TRUSTED_PROXY')).toBe(false);
    expect(acked.warnings.some((f) => f.variable === 'TRUSTED_PROXY')).toBe(true);
  });

  test('SD-04 no shipped anchoring waiver; the anchored configs set every anchoring variable', () => {
    expect(ALL.filter((e) => e.k === 'QODIQA_AUDIT_ANCHORING_WAIVER')).toEqual([]);
    for (const f of ['deploy/kubernetes/overlays/single-node/configmap-single-node.yaml', 'deploy/docker/docker-compose.prod.yml']) {
      const keys = new Set(ALL.filter((e) => e.f.replace(/\\/g, '/') === f).map((e) => e.k));
      for (const k of ['QODIQA_ANCHOR_EXPORT_PATH', 'QODIQA_WITNESS_MODE', 'QODIQA_WITNESS_PUBLIC_KEYS']) expect({ f, k, present: keys.has(k) }).toEqual({ f, k, present: true });
    }
    const compose = ALL.filter((e) => e.f.replace(/\\/g, '/') === 'deploy/docker/docker-compose.prod.yml');
    expect(compose.find((e) => e.k === 'QODIQA_DEPLOYMENT_MODE').v).toBe('single-node');
  });

  test('SD-05 the distributed overlay passes only by being refused for the distributed reason', () => {
    const memory = { ok: true };
    const refused = { name: 'k8s:distributed', fatal: [{ variable: 'QODIQA_DEPLOYMENT_MODE', rule: 'audit.anchoring' }, { variable: 'QODIQA_ANCHOR_EXPORT_PATH', rule: 'audit.anchoring' }], memory };
    expect(applyExpectedRefusal('distributed', refused).ok).toBe(true);
    expect(applyExpectedRefusal('distributed', { name: 'k8s:distributed', fatal: [], memory }).ok).toBe(false); // NOT refused → FAIL
    expect(applyExpectedRefusal('distributed', { ...refused, fatal: [...refused.fatal, { variable: 'REDIS_URL', rule: 'redis' }] }).ok).toBe(false);
  });

  test('SD-06 every metric the shipped PrometheusRule alerts on is SERVED by the gateway', () => {
    // 2026-10-06: checked against what GET /metrics actually serialises — the served registry
    // (getRegistrySnapshot(), the set collect() iterates) AND a `# TYPE` line in collect()'s text — not against module
    // exports: seven exported metrics were never served, so QodiqaAdmissionRejecting passed this test and could never fire.
    const rule = yaml.load(fs.readFileSync(path.join(REPO, 'deploy/kubernetes/overlays/examples/monitoring/prometheusrule.yaml'), 'utf8'));
    const metrics = require('../../src/observability/metrics');
    const registered = new Set(metrics.getRegistrySnapshot().map((m) => m.name));
    const typed = new Set([...metrics.collect(0).matchAll(/^# TYPE (\S+) /gm)].map((m) => m[1]));
    const base = (n) => n.replace(/_(bucket|sum|count)$/, ''); // histogram series
    const used = [...new Set(rule.spec.groups.flatMap((g) => g.rules).flatMap((r) => r.expr.match(/qodiqa_[a-z0-9_]+/g) || []))];
    expect(used.length).toBeGreaterThan(5);
    expect(used.filter((n) => !registered.has(n) && !registered.has(base(n)))).toEqual([]);
    expect(used.filter((n) => !typed.has(n) && !typed.has(base(n)))).toEqual([]);
  });

  test('SD-10 the Helm chart keeps the pod hardening of the kustomize overlay and refuses a weakened production render', () => {
    const t = (f) => fs.readFileSync(path.join(REPO, 'deploy/helm/qodiqa/templates', f), 'utf8');
    const dep = t('deployment.yaml');
    for (const needle of ['runAsNonRoot: true', 'readOnlyRootFilesystem: true', 'allowPrivilegeEscalation: false', 'capabilities: { drop: [ALL] }', 'automountServiceAccountToken: false', 'type: RuntimeDefault']) expect({ needle, present: dep.includes(needle) }).toEqual({ needle, present: true });
    expect(dep).not.toMatch(/privileged:\s*true|hostNetwork|hostPID|runAsUser:\s*0/);
    const helpers = t('_helpers.tpl');
    for (const guard of ['secrets.existingSecret is required', 'postgres.ssl must be true', 'redis.tls must be true', 'keystore.useEmptyDir would lose', 'createDevSecret is for the development profile only']) expect({ guard, present: helpers.includes(guard) }).toEqual({ guard, present: true });
    const job = t('migrate-job.yaml');
    expect(job).toContain('migrations.admin.user is required when migrations.rotateRolePasswords is true');   // placeholder role passwords are never left in place by default
    expect(job).toContain('role-credentials.js --check');
    // the chart never writes a production secret: the only Secret template is the development one
    expect(fs.readdirSync(path.join(REPO, 'deploy/helm/qodiqa/templates')).filter((f) => /secret/i.test(f))).toEqual(['secret-dev.yaml']);
    expect(t('secret-dev.yaml')).toMatch(/eq \.Values\.profile "development"/);
  });

  test('SD-11 the chart ships exactly the alert rules of the kustomize monitoring example', () => {
    const a = yaml.load(fs.readFileSync(path.join(REPO, 'deploy/helm/qodiqa/files/prometheus-rules.yaml'), 'utf8'));
    const b = yaml.load(fs.readFileSync(path.join(REPO, 'deploy/kubernetes/overlays/examples/monitoring/prometheusrule.yaml'), 'utf8'));
    expect(a.spec).toEqual(b.spec);
  });

  test('SD-12 (re-audit A5-01) the production chart default can boot: one replica, single-node mode, and more replicas are refused at render time', () => {
    const values = yaml.load(fs.readFileSync(path.join(REPO, 'deploy/helm/qodiqa/values.yaml'), 'utf8'));
    expect(values.profile).toBe('production');
    expect(values.replicaCount).toBe(1);
    const cm = fs.readFileSync(path.join(REPO, 'deploy/helm/qodiqa/templates/configmap.yaml'), 'utf8');
    expect(cm).toMatch(/"QODIQA_DEPLOYMENT_MODE" \(ternary "single-node" "distributed" \$prod\)/);
    const helpers = fs.readFileSync(path.join(REPO, 'deploy/helm/qodiqa/templates/_helpers.tpl'), 'utf8');
    expect(helpers).toMatch(/gt \(int \.Values\.replicaCount\) 1/);
    const tf = fs.readFileSync(path.join(REPO, 'deploy/terraform/modules/qodiqa/variables.tf'), 'utf8');
    expect(tf).toMatch(/variable "replicas"[\s\S]*?default\s*=\s*1/);
  });

  test('SD-07 the ExternalSecret materialises exactly the keys of base/secret.yaml', () => {
    const base = yaml.load(fs.readFileSync(path.join(REPO, 'deploy/kubernetes/base/secret.yaml'), 'utf8'));
    const es = yaml.load(fs.readFileSync(path.join(REPO, 'deploy/kubernetes/overlays/examples/external-secrets/externalsecret.yaml'), 'utf8'));
    expect(es.spec.target.name).toBe(base.metadata.name);
    expect(es.spec.data.map((d) => d.secretKey).sort()).toEqual(Object.keys(base.data || base.stringData).sort());
  });

  // every container env entry of every shipped YAML that is fed from a Secret: { file, name, secretKey }
  const secretRefs = FILES.flatMap((f) => yaml.loadAll(fs.readFileSync(f, 'utf8')).filter(Boolean).flatMap((doc) => {
    const out = [];
    const visit = (o) => {
      if (!o || typeof o !== 'object') return;
      if (Array.isArray(o.env)) for (const e of o.env) if (e && e.valueFrom && e.valueFrom.secretKeyRef) out.push({ f: path.relative(REPO, f), name: e.name, key: e.valueFrom.secretKeyRef.key });
      for (const v of Object.values(o)) visit(v);
    };
    visit(doc);
    return out;
  }));

  test('SD-08 the backup seal key is its own secret, never the application KEK; the encryption key is dedicated too', () => {
    const base = yaml.load(fs.readFileSync(path.join(REPO, 'deploy/kubernetes/base/secret.yaml'), 'utf8'));
    expect(Object.keys(base.data)).toEqual(expect.arrayContaining(['backup-hmac-key', 'backup-encryption-key', 'key-encryption-key']));
    const hmac = secretRefs.filter((r) => r.name === 'QODIQA_BACKUP_HMAC_KEY');
    expect(hmac.length).toBeGreaterThanOrEqual(5); // daily, weekly, monthly, verify, verify-wal
    expect(hmac.filter((r) => r.key !== 'backup-hmac-key')).toEqual([]);
    const enc = secretRefs.filter((r) => r.name === 'QODIQA_BACKUP_ENCRYPTION_KEY');
    expect(enc.length).toBeGreaterThanOrEqual(4);
    expect(enc.filter((r) => r.key !== 'backup-encryption-key')).toEqual([]);
    // the KEK is only ever the KEK
    expect(secretRefs.filter((r) => r.key === 'key-encryption-key' && /BACKUP/.test(r.name))).toEqual([]);
    // three distinct placeholder values (the shipped Secret never aliases one key to another)
    const vals = ['backup-hmac-key', 'backup-encryption-key', 'key-encryption-key'].map((k) => base.data[k]);
    expect(new Set(vals).size).toBe(3);
  });

  test('SD-09 every repository file a shipped Compose file mounts exists, or is an explicitly operator-supplied path', () => {
    // Compose resolves relative host paths against the FIRST -f file's directory: deploy/docker/ for every file here.
    const OPERATOR_SUPPLIED = new Map([
      ['reverse-proxy/nginx.conf', 'operator-written proxy config (no template on main; reverse-proxy/README.md)'],
      ['../../tls-proxy-local-test/server.crt', 'operator TLS certificate (placeholder; local test certs are git-ignored)'],
      ['../../tls-proxy-local-test/server.key', 'operator TLS key (placeholder; local test certs are git-ignored)'],
      ['../../tls', 'operator TLS material — never committed (/tls/ is git-ignored)'],
      ['../../tls/postgres', 'operator PostgreSQL TLS material — never committed'],
      ['../../witness', 'operator witness key + trusted public keys — never committed'],
    ]);
    const composeDir = path.join(REPO, 'deploy', 'docker');
    const sources = FILES.filter((f) => f.startsWith(composeDir)).flatMap((f) => {
      const out = [];
      const visit = (o) => {
        if (!o || typeof o !== 'object') return;
        if (Array.isArray(o.volumes)) for (const v of o.volumes) if (typeof v === 'string' && /^\.\.?\//.test(v)) out.push({ f: path.relative(REPO, f), src: v.split(':')[0] });
        for (const x of Object.values(o)) visit(x);
      };
      yaml.loadAll(fs.readFileSync(f, 'utf8')).filter(Boolean).forEach(visit);
      return out;
    });
    expect(sources.length).toBeGreaterThan(0);
    const missing = sources.filter(({ src }) => {
      const rel = src.replace(/^\.\//, '');
      return !OPERATOR_SUPPLIED.has(rel) && !fs.existsSync(path.resolve(composeDir, src));
    });
    expect(missing).toEqual([]);
    // and nothing still points at the template that main does not ship
    expect(sources.filter(({ src }) => /nginx\.conf\.template/.test(src))).toEqual([]);
  });
});
