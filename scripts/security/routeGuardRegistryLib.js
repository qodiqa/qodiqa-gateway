'use strict';
/**
 * step 9 — shared logic for the route-guard registry (writer + test).
 * A route's declaration is the guard facts the generator measures; gaps must be
 * covered by a declared exception.
 */

const key = (row) => `${row.methods.join(',')} ${row.path}${row.conditional ? ' [portal]' : ''}`;

function declaration(row) {
  return {
    access: row.access,
    auth: row.auth,
    optionalAuth: row.optionalAuth,
    permissions: row.permissions,
    rateLimitBuckets: row.rateLimitBuckets,
    ipAllowlist: row.ipAllowlist,
    planeGates: row.planeGates,
    mfaStepUp: row.mfaStepUp || null,
  };
}

/** Exceptions: [{ id, gap (label prefix), routes (RegExp|string) }] */
function coverGaps(row, exceptions) {
  const rk = `${row.methods.join(',')} ${row.path}`;
  const covered = []; const uncovered = [];
  for (const g of row.gaps) {
    const ex = exceptions.find((e) => g.startsWith(e.gap) && new RegExp(e.routes).test(rk));
    if (ex) covered.push(ex.id); else uncovered.push(`${rk}: ${g}`);
  }
  return { covered: [...new Set(covered)], uncovered };
}

function build(rows, exceptions) {
  const declare = {}; const uncovered = [];
  for (const row of rows) {
    // Two routes can share a key when one is declared with a trailing slash (e.g. GET /docs and
    // its /docs/ redirect): number the later ones in mount order, which is deterministic.
    let k = key(row); for (let i = 2; declare[k]; i++) k = `${key(row)} #${i}`;
    const c = coverGaps(row, exceptions);
    uncovered.push(...c.uncovered);
    declare[k] = { ...declaration(row), exceptions: c.covered };
  }
  return { declare, uncovered };
}

module.exports = { key, declaration, coverGaps, build };
