'use strict';

/**
 * `pg-backup.sh incremental` is deliberately UNSUPPORTED (exit 2). That refusal must be
 * visible to monitoring as a FAILURE (qodiqa_pg_backup_success 0) and the systemd unit must not fire on its timer unless the
 * operator has explicitly enabled it.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const bashProbe = spawnSync('bash', ['--version'], { encoding: 'utf8' });
const HAS_BASH = bashProbe.status === 0;

(HAS_BASH ? describe : describe.skip)('pg-backup.sh incremental refusal (item 3.5)', () => {
  test('IB-01 exits 2 and writes qodiqa_pg_backup_success{mode="incremental"} 0', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-ib-'));
    const r = spawnSync('bash', ['scripts/pg-backup.sh', 'incremental'], {
      cwd: ROOT, encoding: 'utf8',
      env: { PATH: process.env.PATH, QODIQA_BACKUP_DIR: dir, QODIQA_BACKUP_METRICS_FILE: path.join(dir, 'm.prom'), PGHOST: 'x', PGDATABASE: 'y', PGUSER: 'z' },
    });
    expect(r.status).toBe(2);
    expect(`${r.stdout}${r.stderr}`).toMatch(/UNSUPPORTED/);
    const proms = [];
    (function walk(d) { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (p.endsWith('.prom')) proms.push(p); } })(dir);
    const body = proms.map((p) => fs.readFileSync(p, 'utf8')).join('\n');
    expect(body).toMatch(/qodiqa_pg_backup_success\{mode="incremental",tier="none"\} 0/);
  });
});

describe('qodiqa-pg-backup-incremental.service (item 3.5)', () => {
  test('IB-02 does not run on its timer unless the operator created the enabling file', () => {
    const unit = fs.readFileSync(path.join(ROOT, 'deploy/systemd/qodiqa-pg-backup-incremental.service'), 'utf8');
    expect(unit).toMatch(/^ConditionPathExists=\/etc\/qodiqa\/enable-incremental-backup$/m);
  });
});
