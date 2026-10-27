#!/usr/bin/env node
'use strict';

/**
 * Dependency audit gate: runs `npm audit --json` and fails on any HIGH or CRITICAL advisory
 * that is not listed, with a written justification, in security/audit-exceptions.json.
 *
 * An exception names the advisory (GHSA id), the packages it reaches, why it is not reachable
 * in the shipped configuration, and when it must be reviewed again. An expired exception fails the gate.
 *
 * Exit code: 0 = nothing outstanding, 1 = unexcepted or expired advisories, 2 = the audit itself failed.
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const RANK = { low: 1, moderate: 2, high: 3, critical: 4 };
const THRESHOLD = RANK[process.env.AUDIT_LEVEL || 'high'];

function loadExceptions() {
  const file = path.join(ROOT, 'security', 'audit-exceptions.json');
  if (!fs.existsSync(file)) return new Map();
  const list = JSON.parse(fs.readFileSync(file, 'utf8')).exceptions || [];
  return new Map(list.map((e) => [e.advisory, e]));
}

function runAudit() {
  const r = spawnSync('npm', ['audit', '--json'], { cwd: ROOT, encoding: 'utf8', shell: process.platform === 'win32', maxBuffer: 64 * 1024 * 1024 });
  try { return JSON.parse(r.stdout); } catch { return null; }
}

// every advisory that makes a package vulnerable, following "via" links through dependants
function advisoriesOf(name, vulns, seen = new Set()) {
  if (seen.has(name)) return [];
  seen.add(name);
  const out = [];
  for (const via of (vulns[name] && vulns[name].via) || []) {
    if (typeof via === 'string') out.push(...advisoriesOf(via, vulns, seen));
    else if (via && via.url) out.push({ id: via.url.split('/').pop(), severity: via.severity, title: via.title, pkg: via.name });
  }
  return out;
}

const audit = runAudit();
if (!audit || !audit.vulnerabilities) { console.error('audit-gate: npm audit did not return a report'); process.exit(2); }

const exceptions = loadExceptions();
const today = new Date().toISOString().slice(0, 10);
const outstanding = [];
const excepted = [];
for (const [name, v] of Object.entries(audit.vulnerabilities)) {
  if ((RANK[v.severity] || 0) < THRESHOLD) continue;
  const advisories = advisoriesOf(name, audit.vulnerabilities).filter((a) => (RANK[a.severity] || 0) >= THRESHOLD);
  const unexcused = advisories.filter((a) => !exceptions.has(a.id));
  const expired = advisories.filter((a) => exceptions.has(a.id) && exceptions.get(a.id).reviewBy < today);
  if (advisories.length === 0 || unexcused.length || expired.length) {
    outstanding.push(`${name} (${v.severity}): ${[...unexcused.map((a) => a.id), ...expired.map((a) => `${a.id} exception expired`)].join(', ') || 'no advisory detail'}`);
  } else {
    excepted.push(`${name} (${v.severity}): ${[...new Set(advisories.map((a) => a.id))].join(', ')}`);
  }
}

for (const e of excepted) console.log(`[excepted] ${e}`);
if (outstanding.length) {
  for (const o of outstanding) console.error(`[FAIL] ${o}`);
  console.error(`audit-gate: ${outstanding.length} package(s) with outstanding advisories`);
  process.exit(1);
}
console.log(`audit-gate: no outstanding advisories at '${process.env.AUDIT_LEVEL || 'high'}' or above (${excepted.length} documented exception(s))`);
