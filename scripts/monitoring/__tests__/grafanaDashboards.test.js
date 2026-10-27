'use strict';

/**
 * the Grafana dashboards:
 *   GD-01 the committed files are exactly what scripts/monitoring/generate-grafana.js generates
 *   GD-02 structure: unique panel ids, every panel has targets with an expression, every dashboard has a datasource variable and a uid
 *   GD-03 every metric a panel uses is registered AND served by the gateway (the same two checks the alert rules get), so no panel can chart a metric that does not exist
 */

const fs = require('fs');
const path = require('path');
const { build, OUT } = require('../generate-grafana');
const metrics = require('../../../src/observability/metrics');

const built = build();

describe('grafana dashboards', () => {
  test('GD-01 committed dashboards equal the generated ones', () => {
    expect(Object.keys(built).length).toBeGreaterThanOrEqual(3);
    for (const [name, content] of Object.entries(built)) expect({ name, same: fs.readFileSync(path.join(OUT, name), 'utf8').replace(/\r\n/g, '\n') === content }).toEqual({ name, same: true });
  });

  test('GD-02 structure', () => {
    const uids = new Set();
    for (const [name, content] of Object.entries(built)) {
      const d = JSON.parse(content);
      expect(d.uid).toBeTruthy(); expect(uids.has(d.uid)).toBe(false); uids.add(d.uid);
      expect(d.templating.list.some((v) => v.name === 'datasource' && v.type === 'datasource')).toBe(true);
      const ids = d.panels.map((p) => p.id);
      expect({ name, unique: new Set(ids).size === ids.length }).toEqual({ name, unique: true });
      const real = d.panels.filter((p) => p.type !== 'row');
      expect(real.length).toBeGreaterThanOrEqual(4);
      for (const p of real) { expect(p.targets.length).toBeGreaterThan(0); for (const t of p.targets) expect(String(t.expr).length).toBeGreaterThan(5); }
    }
  });

  test('GD-03 every used metric is registered and served', () => {
    const registered = new Set(metrics.getRegistrySnapshot().map((m) => m.name));
    const typed = new Set([...metrics.collect(0).matchAll(/^# TYPE (\S+) /gm)].map((m) => m[1]));
    const base = (n) => n.replace(/_(bucket|sum|count)$/, '');
    const used = [...new Set(Object.values(built).flatMap((c) => JSON.parse(c).panels.flatMap((p) => (p.targets || []).flatMap((t) => t.expr.match(/qodiqa_[a-z0-9_]+/g) || []))))];
    expect(used.length).toBeGreaterThan(25);
    expect(used.filter((n) => !registered.has(n) && !registered.has(base(n)))).toEqual([]);
    expect(used.filter((n) => !typed.has(n) && !typed.has(base(n)))).toEqual([]);
  });
});
