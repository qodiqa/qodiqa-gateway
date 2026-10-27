'use strict';

/**
 * non-semantic remediation sprint — regression pins for the deploy/backup LOCAL-FIX items
 * ( agent-observability.md the report of
 * what was fixed is). Text/YAML assertions over the shipped files, in the
 * style of test/dr/backupScheduling.test.js; rendering and the production boot validator are covered by
 * `npm run deploy:validate` and .github/workflows/k8s-manifests.yml.
 *
 * wait-for-redis speaks the TLS/ACL contract, keeps the password off argv, is bounded and resourced
 * deploy/docker/backup.Dockerfile context is an allow-list that excludes nested secrets and includes every runtime input;
 *         the image sets modes at COPY time and gates its own content
 * namespace default-deny + backup egress + in-namespace PostgreSQL ingress
 * the distributed PDB is namespaced and topology-scoped
 * preStop drain delay fits inside the grace period
 * the DR backup CronJob fails when its own backup fails and verifies that backup before retention
 * backup libpq connections refuse plaintext; an optional PG CA mount exists without being required
 * example overlays open the network paths they need; the scrape target is selected once
 * dedicated token-less ServiceAccounts are declared and used
 * every third-party image under deploy/ and the backup base image is digest-pinned
 * bounded emptyDirs, init-container resources, memory request ≥ measured working set
 * Compose Redis/PostgreSQL privilege floor, password off the healthcheck argv
 * systemd units hardened, incremental not enabled by the documented loop, WAL-archive verify timer shipped
 * the DR backup job's verify step writes its own metrics textfile
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const ROOT = path.join(__dirname, '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n');
const loadAll = (rel) => yaml.loadAll(read(rel)).filter(Boolean);
const K = 'deploy/kubernetes';
const WORKLOADS = [`${K}/overlays/single-node/statefulset.yaml`, `${K}/overlays/distributed/deployment.yaml`];
const podSpec = (rel) => loadAll(rel).find((d) => ['StatefulSet', 'Deployment'].includes(d.kind)).spec.template.spec;
const cronJobs = () => loadAll(`${K}/base/backup-cronjobs.yaml`).filter((d) => d.kind === 'CronJob');
const toMi = (q) => { const m = String(q).match(/^(\d+)(Mi|Gi)$/); return m ? Number(m[1]) * (m[2] === 'Gi' ? 1024 : 1) : NaN; };

describe('wait-for-redis init container', () => {
  test.each(WORKLOADS)('%s: TLS + mTLS + ACL user, password via REDISCLI_AUTH, bounded, TLS mount, resources', (rel) => {
    const init = podSpec(rel).initContainers.find((c) => c.name === 'wait-for-redis');
    const script = init.command.join(' ');
    expect(script).toMatch(/redis-cli --tls/);
    for (const f of ['--cacert /etc/qodiqa-tls/ca.crt', '--cert /etc/qodiqa-tls/client.crt', '--key /etc/qodiqa-tls/client.key', '--user "$REDIS_USERNAME"']) expect(script).toContain(f);
    expect(script).toMatch(/REDISCLI_AUTH="\$REDIS_PASSWORD" redis-cli/);
    expect(script).not.toMatch(/\s-a\s/);                 // password never on argv
    expect(script).toMatch(/-ge 100 \]; then .*exit 1/);   // bounded wait, visible failure
    expect(init.env.find((e) => e.name === 'REDIS_PORT').value).toBe('6380');
    expect(init.env.find((e) => e.name === 'REDIS_USERNAME').valueFrom.configMapKeyRef).toEqual({ name: 'qodiqa-config', key: 'REDIS_USERNAME' });
    expect(init.volumeMounts).toEqual([{ name: 'redis-tls', mountPath: '/etc/qodiqa-tls', readOnly: true }]);
    expect(init.resources.requests && init.resources.limits).toBeTruthy();
  });
});

// moby/patternmatcher semantics (what BuildKit applies to a .dockerignore): last matching pattern wins, a pattern
// matching a PARENT directory matches the file, `**` spans directories.
function dockerignore(text) {
  const pats = text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((l) => {
    const exclusion = l.startsWith('!');
    let p = (exclusion ? l.slice(1) : l).trim().replace(/^\/+/, '');
    p = path.posix.normalize(p);
    let re = '^';
    for (let i = 0; i < p.length; i++) {
      const ch = p[i];
      if (ch === '*') {
        if (p[i + 1] === '*') { i++; if (p[i + 1] === '/') i++; re += i + 1 >= p.length ? '.*' : '(.*/)?'; } else re += '[^/]*';
      } else if (ch === '?') re += '[^/]';
      else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    return { exclusion, re: new RegExp(`${re}$`) };
  });
  return (file) => {
    const parts = file.split('/');
    let matched = false;
    for (const pt of pats) {
      if (pt.exclusion !== matched) continue;
      let m = pt.re.test(file);
      for (let i = 1; !m && i < parts.length; i++) m = pt.re.test(parts.slice(0, i).join('/'));
      if (m) matched = !pt.exclusion;
    }
    return matched; // true = excluded from the build context
  };
}

describe('deploy/docker/backup.Dockerfile build context and image', () => {
  const excluded = dockerignore(read('deploy/docker/backup.Dockerfile.dockerignore'));

  test('the matcher reproduces the root .dockerignore allow-list semantics it is modelled on', () => {
    const root = dockerignore(read('.dockerignore'));
    expect(root('src/core/audit/audit-log.js')).toBe(false);
    expect(root('scripts/pg-backup.sh')).toBe(true);
    expect(root('src/core/__tests__/x.test.js')).toBe(true);
  });

  // (K7-D3): the release image must ship every operator tool the deployment runbook tells an operator
  // to run inside the container; a trailing "# comment" on a pattern line silently turned one re-include into a no-op.
  test('root .dockerignore: no inline comments, and the documented operator tools are in the build context', () => {
    const text = read('.dockerignore');
    const inline = text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#') && /\s#/.test(l));
    expect(inline).toEqual([]);
    const root = dockerignore(text);
    for (const f of ['scripts/provision-consent-signer.js', 'scripts/rbac-bootstrap-key.js', 'scripts/provision-signing-identity.js',
      'scripts/security/macKeyring.js', 'scripts/db/role-credentials.js', 'scripts/controlPlane/import.js',
      'scripts/keys/seal-keystore.js']) {   // OA-RC-2: upgrade runbook §3.4
      expect({ f, excluded: root(f) }).toEqual({ f, excluded: false });
    }
  });

  test('is an allow-list: everything is excluded unless re-included', () => {
    const first = read('deploy/docker/backup.Dockerfile.dockerignore').split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'));
    expect(first).toBe('*');
    for (const f of ['evidence/x.md', 'eval/data/a.json', 'audit/x.html', 'tls/ca.key', '.claude/settings.json', 'CLAUDE.md', 'policies.json']) {
      expect({ f, excluded: excluded(f) }).toEqual({ f, excluded: true });
    }
  });

  test('secret material is excluded at ANY depth (the nested paths the deny-list let through)', () => {
    for (const f of [
      '.stryker-tmp-tq05/sandbox-IrswT7/.env', '.stryker-tmp-tq05/sandbox-IrswT7/.env.prod',
      '.stryker-tmp-tq05/sandbox-IrswT7/.scratch-f16/collector-key.pem', '.stryker-tmp-tq05/sandbox-IrswT7/.scratch-f16/kek.txt',
      '.stryker-tmp-tq05/sandbox-IrswT7/data/keys.json', 'quarantine/2026-09-28-w1/secret-suspect/data/signing-identities.json',
      'src/some/nested/dir/server.key', 'services/x/client.crt', 'scripts/dr/fixtures/mac-keys.json', 'src/a/.env.local',
      'src/infra/x/transparency-keys.json', 'scripts/dr/__tests__/backup.test.js', 'src/foo.test.js', 'data/keys.json',
    ]) expect({ f, excluded: excluded(f) }).toEqual({ f, excluded: true });
  });

  test('every runtime input is included: entry scripts and the full require() closure of scripts/dr', () => {
    for (const f of ['package.json', 'package-lock.json', 'scripts/pg-backup.sh', 'scripts/pg-wal-archive.sh', 'scripts/backup-audit-log.sh',
      'scripts/dr/backup.js', 'scripts/dr/probes/postgresProbe.js', 'docs/operations/backup-scheduling.md', 'LICENSE']) {
      expect({ f, excluded: excluded(f) }).toEqual({ f, excluded: false });
    }
    // re-derive the closure so a new DR dependency outside the allow-list fails here, not in a CronJob at 02:00
    const seen = new Set();
    const resolve = (from, spec) => {
      const base = path.resolve(path.dirname(from), spec);
      return [base, `${base}.js`, `${base}.json`, path.join(base, 'index.js')].find((c) => fs.existsSync(c) && fs.statSync(c).isFile());
    };
    const walk = (f) => {
      if (seen.has(f)) return; seen.add(f);
      if (!f.endsWith('.js')) return;
      const src = fs.readFileSync(f, 'utf8');
      for (const m of src.matchAll(/require\(\s*['"](\.[^'"]+)['"]\s*\)/g)) { const r = resolve(f, m[1]); if (r) walk(r); }
      for (const m of src.matchAll(/require\(path\.join\(REPO, ((?:'[^']+',?\s*)+)\)\)/g)) {
        const r = resolve(path.join(ROOT, 'x.js'), `./${m[1].split(',').map((s) => s.trim().replace(/'/g, '')).filter(Boolean).join('/')}`);
        if (r) walk(r);
      }
    };
    for (const d of ['scripts/dr', 'scripts/dr/probes']) for (const n of fs.readdirSync(path.join(ROOT, d))) if (n.endsWith('.js')) walk(path.join(ROOT, d, n));
    const rel = [...seen].map((f) => path.relative(ROOT, f).split(path.sep).join('/'));
    expect(rel.length).toBeGreaterThan(100);
    expect(rel.filter(excluded)).toEqual([]);
  });

  test('the image sets modes at COPY time, gates its own content, and keeps the pinned rm -rf block shape', () => {
    const df = read('deploy/docker/backup.Dockerfile');
    expect(df).toMatch(/^COPY --chown=root:qodiqa --chmod=0750 \. \.$/m);
    expect(df).toMatch(/^COPY --from=deps --chown=root:qodiqa --chmod=0750 /m);
    expect(df).not.toMatch(/find \/app -type f -exec chmod/);
    expect(df).toMatch(/IMAGE CONTENT GATE FAILED/);
    expect(df).toMatch(/-name '\*\.pem' -o -name '\*\.key'/);
    expect(df).toMatch(/^USER qodiqa$/m);
  });
});

describe('NetworkPolicies', () => {
  const pols = Object.fromEntries(loadAll(`${K}/base/networkpolicy.yaml`).map((d) => [d.metadata.name, d.spec]));

  test('a namespace-wide default-deny exists for both directions', () => {
    expect(pols['default-deny-all']).toEqual({ podSelector: {}, policyTypes: ['Ingress', 'Egress'] });
  });

  test('backup pods may reach only PostgreSQL, DNS and public HTTPS, and accept nothing', () => {
    const b = pols['qodiqa-backup-egress'];
    expect(b.podSelector.matchLabels).toEqual({ 'app.kubernetes.io/name': 'qodiqa', 'app.kubernetes.io/component': 'backup' });
    expect(b.policyTypes).toEqual(['Egress']);
    const ports = b.egress.flatMap((r) => r.ports.map((p) => `${p.protocol}/${p.port}`)).sort();
    expect(ports).toEqual(['TCP/443', 'TCP/53', 'TCP/5432', 'UDP/53']);
    const https = b.egress.find((r) => r.ports.some((p) => p.port === 443));
    expect(https.to[0].ipBlock.except).toEqual(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']);
    // the selector matches every backup CronJob's pod template
    for (const cj of cronJobs()) expect(cj.spec.jobTemplate.spec.template.metadata.labels).toMatchObject(b.podSelector.matchLabels);
  });

  test('an in-namespace PostgreSQL accepts only the gateway and the backup jobs', () => {
    const p = pols['postgres-ingress-qodiqa-only'];
    expect(p.podSelector.matchLabels).toEqual({ 'app.kubernetes.io/name': 'postgres' });
    expect(p.ingress[0].from.map((f) => f.podSelector.matchLabels['app.kubernetes.io/component']).sort()).toEqual(['backup', 'gateway']);
    expect(p.ingress[0].ports).toEqual([{ protocol: 'TCP', port: 5432 }]);
  });
});

describe('distributed PodDisruptionBudget', () => {
  test('is namespaced and selects exactly the distributed gateway pods', () => {
    const pdb = loadAll(`${K}/overlays/distributed/pdb.yaml`)[0];
    expect(pdb.metadata.namespace).toBe('qodiqa');
    const sel = loadAll(`${K}/overlays/distributed/deployment.yaml`).find((d) => d.kind === 'Deployment').spec.selector.matchLabels;
    expect(pdb.spec.selector.matchLabels).toEqual(sel);
    expect(sel.topology).toBe('distributed');
  });
});

describe('preStop drain delay', () => {
  const shutdownMs = Number(loadAll(`${K}/base/configmap.yaml`)[0].data.SHUTDOWN_TIMEOUT_MS);
  test.each(WORKLOADS)('%s: sleep before SIGTERM handling, inside the grace period', (rel) => {
    const spec = podSpec(rel);
    const app = spec.containers.find((c) => c.name === 'qodiqa');
    const cmd = app.lifecycle.preStop.exec.command;
    expect(cmd[0]).toBe('sleep');
    const delay = Number(cmd[1]);
    expect(delay).toBeGreaterThanOrEqual(5);
    expect(delay + shutdownMs / 1000).toBeLessThan(spec.terminationGracePeriodSeconds);
  });
});

describe('/ qodiqa-dr-backup CronJob and its systemd twin', () => {
  const job = cronJobs().find((c) => c.metadata.name === 'qodiqa-dr-backup');
  const script = job.spec.jobTemplate.spec.template.spec.containers[0].command[2];
  const lines = script.split('\n').map((l) => l.trim()).filter(Boolean);

  test('fails on any failed step and verifies the backup THIS run wrote, before retention', () => {
    expect(lines[0]).toBe('set -eu');
    expect(script).not.toMatch(/ls -td/);
    const iBackup = lines.findIndex((l) => /scripts\/dr\/backup\.js "\$\{OUT_DIR\}"/.test(l));
    const iVerify = lines.findIndex((l) => /scripts\/dr\/verify\.js "\$\{OUT_DIR\}"/.test(l));
    const iRetention = lines.findIndex((l) => /scripts\/dr\/retention\.js/.test(l));
    expect(iBackup).toBeGreaterThan(0);
    expect(iVerify).toBeGreaterThan(iBackup);
    expect(iRetention).toBeGreaterThan(iVerify);
  });

  test('verify.js writes its own textfile (…_verify.prom), never backup.js\'s', () => {
    expect(script).toMatch(/QODIQA_BACKUP_METRICS_FILE="\$\{QODIQA_BACKUP_METRICS_FILE%\.prom\}_verify\.prom" \\\n\s*node scripts\/dr\/verify\.js/);
    const wrapper = read('deploy/systemd/dr-backup-run.sh');
    expect(wrapper).toMatch(/QODIQA_BACKUP_METRICS_FILE="\$\{QODIQA_BACKUP_METRICS_FILE:\+\$\{QODIQA_BACKUP_METRICS_FILE%\.prom\}_verify\.prom\}" \\\n\s*node \/opt\/qodiqa\/scripts\/dr\/verify\.js "\$\{OUT_DIR\}"/);
    expect(wrapper.indexOf('verify.js')).toBeLessThan(wrapper.indexOf('retention.js'));
  });
});

describe('PostgreSQL TLS for backups', () => {
  test('libpq backup connections refuse plaintext (backup ConfigMap and the systemd template)', () => {
    const cm = loadAll(`${K}/base/backup-configmap.yaml`)[0].data;
    expect(['require', 'verify-ca', 'verify-full']).toContain(cm.PGSSLMODE);
    expect(read('deploy/systemd/backup.env.example')).toMatch(/^PGSSLMODE=(require|verify-ca|verify-full)$/m);
  });

  test('DR (node-postgres) URLs say verify-full explicitly — same parse as today\'s `require`, robust to pg v9', () => {
    const { parse } = require('pg-connection-string');
    const warn = jest.spyOn(process, 'emitWarning').mockImplementation(() => {});
    try {
      expect(parse('postgresql://u:p@h/d?sslmode=verify-full').ssl).toEqual(parse('postgresql://u:p@h/d?sslmode=require').ssl);
    } finally { warn.mockRestore(); }
    const urls = cronJobs().flatMap((cj) => cj.spec.jobTemplate.spec.template.spec.containers[0].env || [])
      .filter((e) => /^QODIQA_PG_(RESTORE_)?URL$/.test(e.name)).map((e) => e.value);
    expect(urls).toHaveLength(3);
    for (const u of urls) expect(u).toMatch(/\?sslmode=verify-full(&|$)/);
    expect(read('deploy/systemd/backup.env.example')).toMatch(/^QODIQA_PG_RESTORE_URL=\S+\?sslmode=verify-full$/m);
  });

  test('an OPTIONAL PostgreSQL CA mount exists for the gateway and every PostgreSQL-touching CronJob', () => {
    const optionalPgTls = (spec) => spec.volumes.find((v) => v.name === 'pg-tls');
    for (const rel of WORKLOADS) {
      const spec = podSpec(rel);
      expect(optionalPgTls(spec).secret).toMatchObject({ secretName: 'qodiqa-pg-tls', optional: true });
      expect(spec.containers.find((c) => c.name === 'qodiqa').volumeMounts).toContainEqual({ name: 'pg-tls', mountPath: '/etc/qodiqa-pg-tls', readOnly: true });
    }
    const pgJobs = cronJobs().filter((c) => c.metadata.name !== 'qodiqa-pg-backup-verify-wal');
    expect(pgJobs).toHaveLength(7);
    for (const cj of pgJobs) {
      const spec = cj.spec.jobTemplate.spec.template.spec;
      expect({ job: cj.metadata.name, secret: optionalPgTls(spec).secret }).toMatchObject({ job: cj.metadata.name, secret: { secretName: 'qodiqa-pg-tls', optional: true } });
    }
  });
});

describe('example overlays', () => {
  test('monitoring: Prometheus may reach :3000, and the ServiceMonitor selects one Service only', () => {
    expect(read(`${K}/overlays/examples/monitoring/kustomization.yaml`)).toMatch(/^\s*- networkpolicy-prometheus\.yaml/m);
    const np = loadAll(`${K}/overlays/examples/monitoring/networkpolicy-prometheus.yaml`)[0];
    expect(np.spec.ingress[0].ports).toEqual([{ protocol: 'TCP', port: 3000 }]);
    const sm = loadAll(`${K}/overlays/examples/monitoring/servicemonitor.yaml`)[0];
    expect(sm.spec.selector.matchLabels['qodiqa.com/scrape']).toBe('true');
    expect(loadAll(`${K}/overlays/single-node/service.yaml`)[0].metadata.labels['qodiqa.com/scrape']).toBe('true');
    expect(loadAll(`${K}/overlays/single-node/headless-service.yaml`)[0].metadata.labels['qodiqa.com/scrape']).toBeUndefined();
  });

  test('vault-transit: the gateway may reach Vault on 8200', () => {
    expect(read(`${K}/overlays/examples/vault-transit/kustomization.yaml`)).toMatch(/^\s*- networkpolicy-vault\.yaml/m);
    const np = loadAll(`${K}/overlays/examples/vault-transit/networkpolicy-vault.yaml`)[0];
    expect(np.spec.policyTypes).toEqual(['Egress']);
    expect(np.spec.egress[0].ports).toEqual([{ protocol: 'TCP', port: 8200 }]);
  });
});

describe('ServiceAccounts', () => {
  test('qodiqa and qodiqa-backup exist, token-less, and are wired into base', () => {
    const sas = Object.fromEntries(loadAll(`${K}/base/serviceaccount.yaml`).map((d) => [d.metadata.name, d]));
    for (const n of ['qodiqa', 'qodiqa-backup']) expect(sas[n].automountServiceAccountToken).toBe(false);
    expect(read(`${K}/base/kustomization.yaml`)).toMatch(/^\s*- serviceaccount\.yaml/m);
  });

  test('gateway workloads run as qodiqa, every CronJob as qodiqa-backup; ESO example annotates the SA it uses', () => {
    for (const rel of WORKLOADS) expect(podSpec(rel).serviceAccountName).toBe('qodiqa');
    for (const cj of cronJobs()) expect({ job: cj.metadata.name, sa: cj.spec.jobTemplate.spec.template.spec.serviceAccountName }).toEqual({ job: cj.metadata.name, sa: 'qodiqa-backup' });
    expect(loadAll(`${K}/overlays/examples/external-secrets/secretstore.yaml`)[0].spec.provider.aws.auth.jwt.serviceAccountRef.name).toBe('qodiqa');
    expect(read(`${K}/overlays/examples/external-secrets/kustomization.yaml`)).toMatch(/kind: ServiceAccount[\s\S]*name: qodiqa[\s\S]*annotations:/);
  });
});

describe('image pinning', () => {
  function walk(dir) {
    return fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true }).flatMap((d) => {
      const rel = `${dir}/${d.name}`;
      return d.isDirectory() ? walk(rel) : (/\.ya?ml$/.test(d.name) ? [rel] : []);
    });
  }
  test('every image under deploy/ is digest-pinned, except the operator-built QODIQA images', () => {
    // the value must be on the SAME line as `image:` (a values file's `image:` mapping is not an image), and a Helm template expression is the operator-built gateway image
    const images = walk('deploy').flatMap((f) => [...read(f).matchAll(/^[ 	]*image:[ 	]*(\S+)/gm)].map((m) => ({ f, image: m[1] })));
    expect(images.length).toBeGreaterThan(8);
    const unpinned = images.filter(({ image }) => !/@sha256:[0-9a-f]{64}$/.test(image) && !/^(YOUR_REGISTRY\/)?qodiqa(-backup)?:/.test(image) && !/^\{\{$/.test(image));
    expect(unpinned).toEqual([]);
  });

  test('deploy/docker/backup.Dockerfile builds from a digest-pinned base', () => {
    const df = read('deploy/docker/backup.Dockerfile');
    expect(df).toMatch(/^ARG NODE_IMAGE=node:[^@\s]+@sha256:[0-9a-f]{64}$/m);
    expect(df.match(/^FROM \S+/gm)).toEqual(['FROM ${NODE_IMAGE}', 'FROM ${NODE_IMAGE}']);
  });
});

describe('pod resource hygiene', () => {
  function emptyDirs(o, out = []) {
    if (o && typeof o === 'object') { if ('emptyDir' in o) out.push(o); for (const v of Object.values(o)) emptyDirs(v, out); }
    return out;
  }
  test('every emptyDir in the shipped manifests has a sizeLimit', () => {
    const files = [...WORKLOADS, `${K}/base/backup-cronjobs.yaml`];
    const vols = files.flatMap((f) => loadAll(f).flatMap((d) => emptyDirs(d).map((v) => ({ f, name: v.name, sizeLimit: v.emptyDir && v.emptyDir.sizeLimit }))));
    expect(vols.length).toBeGreaterThanOrEqual(10);
    expect(vols.filter((v) => !v.sizeLimit)).toEqual([]);
  });

  test.each(WORKLOADS)('%s: init containers are resourced; gateway request covers the measured ~2.2 GB working set', (rel) => {
    const spec = podSpec(rel);
    for (const c of spec.initContainers) expect({ c: c.name, ok: !!(c.resources && c.resources.requests && c.resources.limits) }).toEqual({ c: c.name, ok: true });
    const app = spec.containers.find((c) => c.name === 'qodiqa');
    expect(toMi(app.resources.requests.memory)).toBeGreaterThanOrEqual(2304);
    expect(toMi(app.resources.limits.memory)).toBeGreaterThanOrEqual(toMi(app.resources.requests.memory));
  });
});

describe('Compose Redis / PostgreSQL', () => {
  const compose = yaml.load(read('deploy/docker/docker-compose.prod.yml'));
  test.each(['redis', 'postgres'])('%s: cap_drop ALL and no-new-privileges', (svc) => {
    const s = compose.services[svc];
    expect(s.cap_drop).toEqual(['ALL']);
    expect(s.security_opt).toContain('no-new-privileges:true');
    expect(s.cap_add.every((c) => ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID'].includes(c))).toBe(true);
  });

  // PL13-11: read-only root filesystems, runtime-exercised with
  // the pinned images (phase13-14/raw/compose-readonly-runtime.txt)
  test('PL13-11 redis and postgres run with a read-only root filesystem; PostgreSQL writes only to tmpfs + its volume', () => {
    expect(compose.services.redis.read_only).toBe(true);
    const pg = compose.services.postgres;
    expect(pg.read_only).toBe(true);
    const tmpfs = Object.fromEntries(pg.tmpfs.map((t) => [t.split(':')[0], t.split(':').slice(1).join(':')]));
    expect(Object.keys(tmpfs).sort()).toEqual(['/run/pg-tls', '/tmp', '/var/run/postgresql']);
    expect(tmpfs['/run/pg-tls']).toMatch(/mode=0700/);
    expect(tmpfs['/run/pg-tls']).toMatch(/uid=70,gid=70/);
    const cmd = pg.command.join(' ');
    // the TLS key copy targets the private tmpfs, never the (read-only) image rootfs
    expect(cmd).toMatch(/install -m 0600 -o postgres -g postgres \/etc\/pg-tls-src\/server\.key \/run\/pg-tls\/server\.key/);
    expect(cmd).toMatch(/ssl_key_file=\/run\/pg-tls\/server\.key/);
    expect(cmd).not.toMatch(/\/var\/lib\/postgresql\/server\./);
  });

  test('the Redis healthcheck takes the password from the environment, never argv, and needs a real PONG', () => {
    const t = compose.services.redis.healthcheck.test;
    expect(t[0]).toBe('CMD-SHELL');
    expect(t[1]).toMatch(/^REDISCLI_AUTH="\$\$REDIS_PASSWORD" redis-cli --tls /);
    expect(t[1]).toMatch(/\| grep -q PONG$/);
    expect(t.join(' ')).not.toMatch(/(^|\s)-a(\s|$)/);
    expect(compose.services.qodiqa.ulimits.nofile.soft).toBeGreaterThanOrEqual(65536);
  });
});

describe('systemd units', () => {
  const units = fs.readdirSync(path.join(ROOT, 'deploy/systemd')).filter((f) => f.endsWith('.service'));
  const DIRECTIVES = ['NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes', 'CapabilityBoundingSet=',
    'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectKernelLogs=yes', 'ProtectControlGroups=yes', 'PrivateDevices=yes',
    'RestrictSUIDSGID=yes', 'LockPersonality=yes', 'RestrictNamespaces=yes', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
    'SystemCallArchitectures=native'];

  test.each(units)('%s carries the full hardening set, with no trailing comment on any directive line', (u) => {
    const s = read(`deploy/systemd/${u}`);
    for (const d of DIRECTIVES) expect({ u, d, present: new RegExp(`^${d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm').test(s) }).toEqual({ u, d, present: true });
    // systemd has no inline comments — `Key=value # note` makes the value invalid
    expect(s.split('\n').filter((l) => /^[A-Za-z]+=.*#/.test(l))).toEqual([]);
  });

  test('the WAL-archive verify service/timer exist (parity with the qodiqa-pg-backup-verify-wal CronJob)', () => {
    expect(read('deploy/systemd/qodiqa-pg-wal-archive-verify.service')).toMatch(/^ExecStart=\/opt\/qodiqa\/scripts\/pg-wal-archive\.sh --verify$/m);
    const timer = read('deploy/systemd/qodiqa-pg-wal-archive-verify.timer');
    expect(timer).toMatch(/^OnCalendar=\*:0\/5$/m);
    expect(timer).toMatch(/^Persistent=true$/m);
  });

  test('the documented install loop does not enable the unsupported incremental timer, and does enable WAL verify', () => {
    const doc = read('docs/operations/backup-scheduling.md');
    const loop = doc.match(/for t in ([\s\S]*?); do\n\s*sudo systemctl enable --now "\$\{t\}\.timer"/);
    expect(loop).not.toBeNull();
    expect(loop[1]).not.toMatch(/qodiqa-pg-backup-incremental/);
    expect(loop[1]).toMatch(/qodiqa-pg-wal-archive-verify/);
  });
});
