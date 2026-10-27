'use strict';

/**
 * DB-05 (migration 076): audit_chain / policy_history / investigation_audit_events refuse UPDATE, DELETE and TRUNCATE
 * for every role unless the session declares an allowed maintenance intent. Suites that tamper with or reset those
 * tables on their OWN DISPOSABLE database declare the `fixture` intent for every connection they open, through
 * PGOPTIONS (read by node-postgres at connect time), and restore the environment when they finish.
 *
 *   const auditFixture = require('./helpers/auditMaintenance');
 *   beforeAll(auditFixture.enter);
 *   afterAll(auditFixture.leave);
 */

const FIXTURE_OPTION = '-c qodiqa.audit_maintenance=fixture';
let _saved;
let _entered = false;

function enter() {
  if (_entered) return;
  _saved = process.env.PGOPTIONS;
  process.env.PGOPTIONS = _saved ? `${_saved} ${FIXTURE_OPTION}` : FIXTURE_OPTION;
  _entered = true;
}

function leave() {
  if (!_entered) return;
  if (_saved === undefined) delete process.env.PGOPTIONS; else process.env.PGOPTIONS = _saved;
  _entered = false;
}

module.exports = { enter, leave, FIXTURE_OPTION };
