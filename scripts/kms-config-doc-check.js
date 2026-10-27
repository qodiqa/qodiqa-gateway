#!/usr/bin/env node
'use strict';

/**
 * KMS Configuration Documentation Drift Check — Findings Group C, item C2.
 *
 * Extends the documentation-drift guard (see scripts/doc-drift-check.js) to
 * cover content it only tracks structurally: whether the per-provider env
 * var set docs/configuration/reference.md's KMS table documents for each
 * KMS/Vault provider still matches the live set src/infra/keys/kmsConfig.js
 * (item 21) actually validates. This table was the site of a real doc-to-doc
 * drift found during item 21 (Finding C) — this check exists so a future
 * schema change (a var renamed, added, or removed for one provider) cannot
 * silently leave the doc table wrong again, the same failure class
 * onboarding-contract-check.js already guards for docs/guides/quickstart.md.
 *
 * Ground truth, never hand-duplicated: `_FIELDS_BY_PROVIDER` and
 * `KNOWN_PROVIDERS`, imported directly from kmsConfig.js — the same map
 * validateKmsConfig() itself builds its Zod-validated raw object from.
 *
 * Scope note: this compares the full env-var-name SET per provider (doc's
 * "Required" + "Optional" columns combined) against kmsConfig.js's full
 * field list for that provider — it does not attempt to replicate which
 * vars are conditionally required (e.g. Vault's ROLE_ID+SECRET_ID **or**
 * TOKEN, enforced by a superRefine, not per-field Zod .optional()). That
 * mirrors onboarding-contract-check.js's own declared scope limit for a
 * structurally identical reason (required-ness isn't always visible in
 * field shape) — this check catches "a var exists on one side and not the
 * other," which is the actual failure mode item 21 found.
 *
 * Comparison is bidirectional, per provider:
 *   - a var documented in the KMS table but not in kmsConfig.js's field
 *     list for that provider -> FAIL, naming the provider and var
 *   - a var in kmsConfig.js's field list but not documented anywhere in
 *     that provider's table row -> FAIL, naming the provider and var
 *
 * Usage: node scripts/kms-config-doc-check.js
 * Exit codes: 0 = pass, 1 = drift detected.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DOC_PATH = path.join(ROOT, 'docs/configuration/reference.md');

const { _FIELDS_BY_PROVIDER, KNOWN_PROVIDERS } = require('../src/infra/keys/kmsConfig.js');

// Real env var names in this table are always SCREAMING_SNAKE_CASE
// (QODIQA_*/VAULT_*/AWS_*/AZURE_*/GCP_*/HSM_*); every default-value example
// shown alongside a var (URLs, paths, mount names, version numbers) is not
// all-caps in this doc. This is what separates a var name from a shown
// default inside the same backtick-delimited cell — confirmed against the
// current table content before relying on it (see C2 checkpoint evidence).
const VAR_NAME_RE = /^[A-Z][A-Z0-9_]*$/;

function extractVarNames(cellText) {
  const names = new Set();
  const backtickRe = /`([^`]+)`/g;
  let m;
  while ((m = backtickRe.exec(cellText))) {
    if (VAR_NAME_RE.test(m[1])) names.add(m[1]);
  }
  return names;
}

/**
 * Parses docs/configuration/reference.md's
 * "#### KMS-specific variables" table into { provider: Set<varName> }.
 */
function parseDocKmsTable(md) {
  const anchor = '#### KMS-specific variables';
  const anchorIdx = md.indexOf(anchor);
  if (anchorIdx === -1) {
    throw new Error(`kms-config-doc-check: anchor not found in ${DOC_PATH}: "${anchor}"`);
  }
  const tableStart = md.indexOf('| Provider |', anchorIdx);
  if (tableStart === -1) {
    throw new Error('kms-config-doc-check: KMS table header row not found after anchor');
  }
  const tableEnd = md.indexOf('\n\n', tableStart);
  const tableBlock = tableEnd === -1 ? md.slice(tableStart) : md.slice(tableStart, tableEnd);

  const rows = tableBlock.split('\n').filter((line) => line.trim().startsWith('|'));
  const docByProvider = {};

  // rows[0] = header, rows[1] = separator, rows[2..] = data rows
  for (const row of rows.slice(2)) {
    // row shape: | `provider` | Required cell | Optional cell |
    const rawCells = row.split('|');
    // rawCells[0] and [last] are the empty strings outside the leading/trailing '|'
    const providerCell = rawCells[1] || '';
    const requiredCell = rawCells[2] || '';
    const optionalCell = rawCells[3] || '';

    const providerMatch = /`([^`]+)`/.exec(providerCell);
    if (!providerMatch) continue; // not a data row (shouldn't happen given the header/separator slice above)
    const provider = providerMatch[1];

    const varNames = new Set([
      ...extractVarNames(requiredCell),
      ...extractVarNames(optionalCell),
    ]);
    docByProvider[provider] = varNames;
  }

  return docByProvider;
}

function buildLiveByProvider() {
  const liveByProvider = {};
  for (const provider of KNOWN_PROVIDERS) {
    liveByProvider[provider] = new Set(_FIELDS_BY_PROVIDER[provider] || []);
  }
  return liveByProvider;
}

function diff(docByProvider, liveByProvider) {
  const failures = [];

  for (const provider of KNOWN_PROVIDERS) {
    const docVars = docByProvider[provider];
    const liveVars = liveByProvider[provider];

    if (!docVars) {
      failures.push(`[${provider}] no row found in CONFIGURATION_REFERENCE.md's KMS table.`);
      continue;
    }

    for (const varName of docVars) {
      if (!liveVars.has(varName)) {
        failures.push(`[${provider}] documented in CONFIGURATION_REFERENCE.md but not in kmsConfig.js: ${varName}`);
      }
    }
    for (const varName of liveVars) {
      if (!docVars.has(varName)) {
        failures.push(`[${provider}] present in kmsConfig.js but not documented in CONFIGURATION_REFERENCE.md: ${varName}`);
      }
    }
  }

  return failures;
}

function main() {
  console.log('kms-config-doc-check: validating CONFIGURATION_REFERENCE.md\'s KMS table against kmsConfig.js...\n');

  const md = fs.readFileSync(DOC_PATH, 'utf8');
  const docByProvider = parseDocKmsTable(md);
  const liveByProvider = buildLiveByProvider();
  const failures = diff(docByProvider, liveByProvider);

  if (failures.length) {
    console.error('KMS configuration documentation drift check FAILED:\n');
    for (const f of failures) console.error(`  - ${f}`);
    console.error(
      '\nUpdate docs/configuration/reference.md\'s KMS table, or src/infra/keys/kmsConfig.js\'s ' +
      '_FIELDS_BY_PROVIDER, so both sides agree. This check derives the live var set directly from ' +
      'kmsConfig.js — it is never hand-maintained, so a failure here means real drift.\n'
    );
    process.exitCode = 1;
    return;
  }

  console.log('PASS: no KMS configuration documentation drift detected.');
}

if (require.main === module) main();

module.exports = {
  extractVarNames,
  parseDocKmsTable,
  buildLiveByProvider,
  diff,
};
