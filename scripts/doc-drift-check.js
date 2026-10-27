#!/usr/bin/env node
'use strict';

/**
 * Documentation Drift Check —.
 *
 * Permanent CI guard against documentation silently going stale. Runs two
 * checks on every push and pull request:
 *
 *   1. Cross-file mapping: if a diff touches any source path in a mapping's
 *      `sourceGlobs` (scripts/doc-drift-map.js), the mapping's `docFile`
 *      must appear in the same diff. `selfDoc: true` mappings instead
 *      require the file's own "Last verified: YYYY-MM-DD" line to change
 *      whenever the rest of the file does.
 *   2. Marker presence: every mapped docFile must contain a parseable
 *      "Last verified: YYYY-MM-DD" line, regardless of what changed in
 *      this diff — this guards against the marker being deleted outright.
 *
 * Extend coverage by adding an entry to scripts/doc-drift-map.js, not by
 * editing this file.
 *
 * When there is no base to compare against — the first commit, a pre-push SHA that no longer exists (history replaced by a
 * force push, a shallow checkout), or a base ref that cannot be resolved — the cross-file comparison is skipped and the
 * marker check below runs over every mapped document instead of failing.
 *
 * Usage: node scripts/doc-drift-check.js [--base <ref>] [--head <ref>]
 * Env fallbacks (used when --base/--head are omitted): GITHUB_EVENT_NAME,
 * GITHUB_BASE_SHA, GITHUB_BEFORE, GITHUB_SHA.
 *
 * Exit codes: 0 = pass, 1 = drift or missing marker detected.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
// Tolerant of markdown emphasis around the label/colon (e.g. "**Last
// verified**: 2026-07-29" or "**Last verified:** 2026-07-29") since
// documents in this repo are not fully consistent about where the bold
// markers sit relative to the colon.
const MARKER_RE = /Last verified[^\d]{0,10}(\d{4}-\d{2}-\d{2})/i;
const NULL_SHA = '0000000000000000000000000000000000000000';

const mappings = require('./doc-drift-map.js');

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
}

// true when `ref` names a commit this checkout has
function commitExists(ref) {
  try {
    execFileSync('git', ['cat-file', '-e', `${ref}^{commit}`], { cwd: ROOT, stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function parseArgs() {
  const argv = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--base') opts.base = argv[++i];
    if (argv[i] === '--head') opts.head = argv[++i];
  }
  return opts;
}

// Determine the (base, head) commit range to diff. In rough priority order:
// explicit CLI flags, then PR base SHA (GitHub Actions), then the pre-push
// SHA on a branch push, then the parent of HEAD for a local/manual run.
function resolveRange() {
  const opts = parseArgs();
  const head = opts.head || process.env.GITHUB_SHA || 'HEAD';

  // A base that this checkout does not have cannot be diffed: fall back to the full marker check (see the header).
  const withBase = (base) => (commitExists(base) && commitExists(head)
    ? { base, head, skip: false }
    : { base: null, head, skip: true, reason: `base commit ${base} is not available in this checkout` });

  if (opts.base) return withBase(opts.base);

  if (process.env.GITHUB_EVENT_NAME === 'pull_request' && process.env.GITHUB_BASE_SHA) {
    return withBase(process.env.GITHUB_BASE_SHA);
  }

  const before = process.env.GITHUB_BEFORE;
  if (before && before !== NULL_SHA) {
    return withBase(before);
  }

  try {
    const parent = git(['rev-parse', `${head}~1`]);
    return { base: parent, head, skip: false };
  } catch {
    // First commit on the repo/branch — nothing to diff against.
    return { base: null, head, skip: true };
  }
}

function changedFiles(base, head) {
  const out = git(['diff', '--name-only', base, head]);
  return out ? out.split('\n').filter(Boolean) : [];
}

function fileAt(ref, file) {
  try {
    return git(['show', `${ref}:${file}`]);
  } catch {
    return null; // file didn't exist at that ref
  }
}

function main() {
  const failures = [];
  const { base, head, skip, reason } = resolveRange();

  if (skip) {
    console.log(
      `doc-drift-check: ${reason || 'no prior commit to diff against'} — skipping the cross-file drift check, ` +
      'running the marker validation over every mapped document instead.'
    );
  } else {
    console.log(`doc-drift-check: comparing ${base} -> ${head}`);
    const changed = changedFiles(base, head);

    for (const mapping of mappings) {
      const sourceHit = changed.some((f) => mapping.sourceGlobs.some((re) => re.test(f)));
      if (!sourceHit) continue;

      if (mapping.selfDoc) {
        const before = fileAt(base, mapping.docFile);
        const after = fileAt(head, mapping.docFile);
        const beforeMatch = before && MARKER_RE.exec(before);
        const afterMatch = after && MARKER_RE.exec(after);
        const beforeVal = beforeMatch ? beforeMatch[1] : null;
        const afterVal = afterMatch ? afterMatch[1] : null;
        if (beforeVal === afterVal) {
          failures.push(
            `[${mapping.name}] ${mapping.docFile} changed but its "Last verified" date was not ` +
            `updated (still ${afterVal || 'missing'}). Bump the date when this file's rules/status change.`
          );
        }
      } else if (!changed.includes(mapping.docFile)) {
        failures.push(
          `[${mapping.name}] a source path matching this mapping changed ` +
          `(${mapping.sourceGlobs.map(String).join(', ')}) but ${mapping.docFile} was not updated ` +
          `in the same change.`
        );
      }
    }
  }

  // Marker presence check — always runs, independent of the diff, so the
  // marker cannot be silently deleted in an otherwise-unrelated change.
  const uniqueDocs = [...new Set(mappings.map((m) => m.docFile))];
  for (const docFile of uniqueDocs) {
    const full = path.join(ROOT, docFile);
    if (!fs.existsSync(full)) {
      failures.push(`[marker] ${docFile} does not exist.`);
      continue;
    }
    const content = fs.readFileSync(full, 'utf8');
    if (!MARKER_RE.test(content)) {
      failures.push(`[marker] ${docFile} is missing a "Last verified: YYYY-MM-DD" marker.`);
    }
  }

  if (failures.length) {
    console.error('\nDocumentation drift check FAILED:\n');
    for (const f of failures) console.error(`  - ${f}`);
    console.error(
      '\nUpdate the documentation listed above (see scripts/doc-drift-map.js for the mapping). ' +
      'If none of the above genuinely applies to your change, extend or adjust the mapping instead.\n'
    );
    process.exitCode = 1;
    return;
  }

  console.log('PASS: no documentation drift detected.');
}

if (require.main === module) main();

module.exports = { commitExists };
