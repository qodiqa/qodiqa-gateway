'use strict';

/**
 * — the gateway never receives, needs or accepts the migration credential.
 *
 *   GM-01  no shipped gateway manifest passes QODIQA_PG_MIG_PASSWORD (compose service `qodiqa`, both Kubernetes overlays)
 *   GM-02  the compose file still documents the separate one-shot migration job (-e QODIQA_PG_MIG_USER -e QODIQA_PG_MIG_PASSWORD)
 *   GM-03  production boot validation passes WITHOUT the migration password (it is no longer required)
 *   GM-04  production boot validation REFUSES a gateway environment that carries the migration password; non-production warns
 *   GM-05  no runtime module reads QODIQA_PG_MIG_USER / QODIQA_PG_MIG_PASSWORD (only the migration CLI and operator tooling)
 */

const fs = require('fs');
const path = require('path');

const REPO = path.join(__dirname, '..', '..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');
const { validateBoot } = require('../../src/infra/config/bootValidator');

describe('the gateway runs without the migration credential', () => {
  test('GM-01 no shipped gateway manifest passes QODIQA_PG_MIG_PASSWORD', () => {
    const compose = read('deploy/docker/docker-compose.prod.yml');
    const svc = compose.slice(compose.indexOf('\n  qodiqa:'), compose.indexOf('\nvolumes:'));
    expect(svc.length).toBeGreaterThan(1000);
    expect(svc.split('\n').filter((l) => !/^\s*#/.test(l) && /QODIQA_PG_MIG_(PASSWORD|USER)\s*:/.test(l))).toEqual([]);
    for (const f of ['deploy/kubernetes/overlays/single-node/statefulset.yaml', 'deploy/kubernetes/overlays/distributed/deployment.yaml']) {
      const lines = read(f).split('\n').filter((l) => !/^\s*#/.test(l));
      expect({ f, mig: lines.filter((l) => /QODIQA_PG_MIG_PASSWORD|postgres-mig-password/.test(l)) }).toEqual({ f, mig: [] });
      // the other role passwords are still delivered (nothing else was removed)
      for (const n of ['QODIQA_PG_SYSTEM_PASSWORD', 'QODIQA_PG_REPORTING_PASSWORD', 'QODIQA_PG_CONTROL_PASSWORD']) {
        expect({ f, n, present: lines.some((l) => l.includes(`name: ${n}`)) }).toEqual({ f, n, present: true });
      }
    }
    const example = require('dotenv').parse(read('deploy/env/production.env.example'));
    expect('QODIQA_PG_MIG_PASSWORD' in example).toBe(false);
  });

  test('GM-02 the compose file documents the separate one-shot migration job', () => {
    expect(read('deploy/docker/docker-compose.prod.yml'))
      .toMatch(/docker compose run --rm --no-deps -e QODIQA_PG_MIG_USER -e QODIQA_PG_MIG_PASSWORD qodiqa node src\/infra\/postgres\/migrate\.js/);
  });

  const pgEnv = () => ({
    QODIQA_PG_ENABLED: 'true', QODIQA_PG_PASSWORD: 'a'.repeat(8) + 'Zq81mPx3Kd9w', QODIQA_PG_RETENTION_PASSWORD: 'b'.repeat(8) + 'Zq81mPx3Kd9w',
    QODIQA_PG_SYSTEM_PASSWORD: 'c'.repeat(8) + 'Zq81mPx3Kd9w', QODIQA_PG_REPORTING_PASSWORD: 'd'.repeat(8) + 'Zq81mPx3Kd9w',
    QODIQA_PG_CONTROL_PASSWORD: 'e'.repeat(8) + 'Zq81mPx3Kd9w',
  });
  const rulesFor = (env, name) => {
    const r = validateBoot(env);
    return [...r.fatal.map((v) => ({ ...v, severity: 'fatal' })), ...r.warnings.map((v) => ({ ...v, severity: 'warn' }))]
      .filter((v) => v.variable === name);
  };

  test('GM-03 the migration password is no longer required (no violation names it when it is absent)', () => {
    for (const NODE_ENV of ['production', 'development']) {
      expect(rulesFor({ NODE_ENV, ...pgEnv() }, 'QODIQA_PG_MIG_PASSWORD')).toEqual([]);
    }
  });

  test('GM-04 a gateway environment carrying the migration password is refused in production, warned elsewhere', () => {
    const prod = rulesFor({ NODE_ENV: 'production', ...pgEnv(), QODIQA_PG_MIG_PASSWORD: 'f'.repeat(8) + 'Zq81mPx3Kd9w' }, 'QODIQA_PG_MIG_PASSWORD');
    expect(prod.map((v) => v.severity)).toEqual(['fatal']);
    const dev = rulesFor({ NODE_ENV: 'development', ...pgEnv(), QODIQA_PG_MIG_PASSWORD: 'f'.repeat(8) + 'Zq81mPx3Kd9w' }, 'QODIQA_PG_MIG_PASSWORD');
    expect(dev.map((v) => v.severity)).toEqual(['warn']);
  });

  test('GM-05 no runtime module reads the migration credential', () => {
    const offenders = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(path.join(REPO, dir), { withFileTypes: true })) {
        const rel = path.join(dir, e.name);
        if (e.isDirectory()) { if (!/__tests__|migrations|node_modules/.test(e.name)) walk(rel); continue; }
        if (!/\.js$/.test(e.name) || /\.test\.js$/.test(e.name)) continue;
        const src = fs.readFileSync(path.join(REPO, rel), 'utf8').replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, '');
        if (/process\.env\.QODIQA_PG_MIG_(USER|PASSWORD)|env\.QODIQA_PG_MIG_(USER|PASSWORD)|env\[['"]QODIQA_PG_MIG_/.test(src)) offenders.push(rel.replace(/\\/g, '/'));
      }
    };
    for (const d of ['src', 'server', 'services', 'middleware']) if (fs.existsSync(path.join(REPO, d))) walk(d);
    // the migration CLI is the one reader (an operator / one-shot job entry point, never imported by the server)
    expect(offenders.sort()).toEqual(['src/infra/postgres/migrate.js']);
  });
});
