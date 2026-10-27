#!/usr/bin/env node
'use strict';

/**
 * Claims registry checker. Source: claims/claims.json. Run: `npm run claims:check` [--run-cmds] [--strict-stale];
 * `--write` regenerates claims/CLAIMS.generated.md; `--stamp` sets verifiedAtCommit of every claim to HEAD (after re-verifying).
 *
 * Rules (each one has a negative test in scripts/claims/__tests__/checkClaims.test.js):
 *  1. A PROVEN / PROVEN-CAVEAT / in-sample / experimental claim needs >= 1 `code` evidence and >= 1 `test` or `run` (or `cmd`) evidence.
 *  2. Every evidence `path` exists and its `regex` matches at least once (empty regex = file/dir exists).
 *  3. `cmd` evidence with runInCI runs (only with --run-cmds) and must exit 0.
 *  4. Forbidden phrases (the `forbiddenIfNot` lists of NOT-DELIVERED / RETRACTED / limited claims, plus `forbiddenGlobal`) must not appear in
 *     a public file unless the same line contains a negation ("not", "no", "never", "without", ...). A claim reference never lifts a ban.
 *  5. A public line that references `claim:C-xxx` must name an existing, non-RETRACTED claim; if the status needs a caveat
 *     (PROVEN-CAVEAT, in-sample, experimental, OWNER-PENDING) the caveat text must be in the same paragraph.
 *  6. Staleness (warning, error with --strict-stale): evidence modified in a commit that is not an ancestor of `verifiedAtCommit`.
 *  7. claims/CLAIMS.generated.md equals render(claims.json).
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const STATUSES = ['PROVEN', 'PROVEN-CAVEAT', 'IN-SAMPLE', 'SIMULATED', 'NOT-DELIVERED', 'OWNER-PENDING', 'RETRACTED'];
const NEEDS_EVIDENCE = new Set(['PROVEN', 'PROVEN-CAVEAT', 'IN-SAMPLE', 'SIMULATED']);
const NEEDS_CAVEAT = new Set(['PROVEN-CAVEAT', 'IN-SAMPLE', 'SIMULATED', 'OWNER-PENDING']);
const NEGATION = /\b(not|no|never|without|cannot|none|nor|neither|lacks?|absent|unavailable)\b|n't\b/i;

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function render(registry) {
  const lines = ['<!-- GENERATED from claims/claims.json by scripts/claims/check-claims.js --write; do not edit -->', '# Claims and their evidence', ''];
  lines.push('Every statement below is backed by evidence checked in CI, or is explicitly marked as not delivered. Status vocabulary: ' + STATUSES.join(', ') + '.', '');
  lines.push('| ID | Claim | Status | Reservation |', '|---|---|---|---|');
  for (const c of registry.claims) {
    lines.push(`| ${c.id} | ${c.claim.replace(/\|/g, '/')} | ${c.status} | ${(c.caveat || '—').replace(/\|/g, '/')} |`);
  }
  lines.push('');
  return lines.join('\n');
}

function readRegistry(root) {
  return JSON.parse(fs.readFileSync(path.join(root, 'claims', 'claims.json'), 'utf8'));
}

function git(root, args) {
  try { return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch (_) { return null; }
}

function checkClaims({ root = path.join(__dirname, '..', '..'), registry = null, runCmds = false, strictStale = false } = {}) {
  const errors = []; const warnings = [];
  const reg = registry || readRegistry(root);
  const byId = new Map();
  for (const c of reg.claims) {
    if (byId.has(c.id)) errors.push(`${c.id}: duplicate id`);
    byId.set(c.id, c);
    if (!STATUSES.includes(c.status)) errors.push(`${c.id}: unknown status ${c.status}`);
    if (!c.claim || typeof c.claim !== 'string') errors.push(`${c.id}: missing claim text`);
    if (NEEDS_CAVEAT.has(c.status) && !c.caveat) errors.push(`${c.id}: status ${c.status} requires a caveat`);
    const ev = Array.isArray(c.evidence) ? c.evidence : [];
    if (NEEDS_EVIDENCE.has(c.status)) {
      const types = new Set(ev.map((e) => e.type));
      if (!types.has('code')) errors.push(`${c.id}: ${c.status} needs at least one code evidence`);
      if (!types.has('test') && !types.has('run') && !types.has('cmd')) errors.push(`${c.id}: ${c.status} needs a test, run or cmd evidence`);
    }
    for (const e of ev) {
      if (e.type === 'cmd') {
        if (e.runInCI && runCmds) {
          try { execFileSync(process.platform === 'win32' ? 'cmd' : 'sh', process.platform === 'win32' ? ['/c', e.cmd] : ['-c', e.cmd], { cwd: root, stdio: 'ignore' }); } catch (_) { errors.push(`${c.id}: command failed: ${e.cmd}`); }
        }
        continue;
      }
      // Evidence that stays in the private source repository is cited as `private:<path>`; the public export lists it, with its sha256 and the
      // regular expressions that were verified against it at export time.
      if (typeof e.path === 'string' && e.path.startsWith('private:')) {
        const indexPath = path.join(root, 'evidence', 'PRIVATE-EVIDENCE-INDEX.json');
        const entry = fs.existsSync(indexPath) ? (JSON.parse(fs.readFileSync(indexPath, 'utf8')).entries || {})[e.path.slice('private:'.length)] : null;
        if (!entry) errors.push(`${c.id}: private evidence is not in evidence/PRIVATE-EVIDENCE-INDEX.json: ${e.path}`);
        else if (e.regex && !(entry.regexMatched || []).includes(e.regex)) errors.push(`${c.id}: regex /${e.regex}/ was not verified against ${e.path} at export time`);
        continue;
      }
      const p = path.join(root, e.path || '');
      if (!e.path || !fs.existsSync(p)) { errors.push(`${c.id}: evidence path missing: ${e.path}`); continue; }
      if (e.regex) {
        if (fs.statSync(p).isDirectory()) { errors.push(`${c.id}: regex on a directory: ${e.path}`); continue; }
        if (!new RegExp(e.regex).test(fs.readFileSync(p, 'utf8'))) errors.push(`${c.id}: regex /${e.regex}/ does not match ${e.path}`);
      }
      if (c.verifiedAtCommit) {
        const last = git(root, ['log', '-1', '--format=%H', '--', e.path]);
        if (last && git(root, ['merge-base', '--is-ancestor', last, c.verifiedAtCommit]) === null) {
          (strictStale ? errors : warnings).push(`${c.id}: evidence ${e.path} changed after verifiedAtCommit ${c.verifiedAtCommit}`);
        }
      }
    }
  }

  // public text rules
  const forbidden = [...(reg.forbiddenGlobal || [])];
  for (const c of reg.claims) for (const ph of c.forbiddenIfNot || []) forbidden.push(ph);
  const files = reg.publicFiles || [];
  for (const rel of files) {
    const p = path.join(root, rel);
    if (!fs.existsSync(p)) { errors.push(`public file missing: ${rel}`); continue; }
    const text = fs.readFileSync(p, 'utf8');
    const lines = text.split(/\r?\n/);
    lines.forEach((line, i) => {
      for (const ph of forbidden) {
        const re = new RegExp('(^|[^A-Za-z0-9])' + escapeRe(ph) + '($|[^A-Za-z0-9])', 'i');
        if (re.test(line) && !NEGATION.test(line)) errors.push(`${rel}:${i + 1}: forbidden phrase "${ph}" without a negation`);
      }
      for (const m of line.matchAll(/claim:(C-\d{3})/g)) {
        const c = byId.get(m[1]);
        if (!c) { errors.push(`${rel}:${i + 1}: unknown claim ${m[1]}`); continue; }
        if (c.status === 'RETRACTED' || c.status === 'NOT-DELIVERED') { errors.push(`${rel}:${i + 1}: ${m[1]} is ${c.status} and cannot be asserted`); continue; }
        if (NEEDS_CAVEAT.has(c.status) && c.caveat) {
          // paragraph = the blank-line delimited block containing the line
          let a = i; while (a > 0 && lines[a - 1].trim() !== '') a--;
          let b = i; while (b < lines.length - 1 && lines[b + 1].trim() !== '') b++;
          if (!lines.slice(a, b + 1).join(' ').replace(/\s+/g, ' ').includes(c.caveat.replace(/\s+/g, ' '))) errors.push(`${rel}:${i + 1}: ${m[1]} (${c.status}) requires its caveat in the same paragraph`);
        }
      }
    });
  }

  // generated page
  const gen = path.join(root, 'claims', 'CLAIMS.generated.md');
  if (!fs.existsSync(gen)) errors.push('claims/CLAIMS.generated.md is missing (run node scripts/claims/check-claims.js --write)');
  else if (fs.readFileSync(gen, 'utf8').replace(/\r\n/g, '\n') !== render(reg)) errors.push('claims/CLAIMS.generated.md is stale (run node scripts/claims/check-claims.js --write)');

  return { errors, warnings, count: reg.claims.length };
}

if (require.main === module) {
  const root = path.join(__dirname, '..', '..');
  if (process.argv.includes('--stamp')) {
    const head = git(root, ['rev-parse', 'HEAD']);
    const reg = readRegistry(root);
    for (const c of reg.claims) c.verifiedAtCommit = head;
    fs.writeFileSync(path.join(root, 'claims', 'claims.json'), JSON.stringify(reg, null, 2) + '\n');
    console.log('stamped verifiedAtCommit', head);
    process.exit(0);
  }
  if (process.argv.includes('--write')) {
    fs.writeFileSync(path.join(root, 'claims', 'CLAIMS.generated.md'), render(readRegistry(root)));
    console.log('written claims/CLAIMS.generated.md');
    process.exit(0);
  }
  const r = checkClaims({ root, runCmds: process.argv.includes('--run-cmds'), strictStale: process.argv.includes('--strict-stale') });
  r.warnings.forEach((w) => console.warn('WARN', w));
  if (r.errors.length) { r.errors.forEach((e) => console.error('FAIL', e)); console.error(`claims:check FAILED (${r.errors.length} problem(s), ${r.count} claims)`); process.exit(1); }
  console.log(`claims:check ok (${r.count} claims)`);
}

module.exports = { checkClaims, render, STATUSES };
