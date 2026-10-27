'use strict';

/**
 * DATA_RETENTION policy rule: retention per DATA CATEGORY (src/core/dataGovernance/categories.js). Like the DLP rule it does not decide on a request: it is the governed,
 * hashed statement of how long each category of data is kept, applied to the stores by `applyRetention` (dataGovernance). As an evaluator it always passes.
 *
 * config: { retentionFormat: 1, byCategory: { audit_security: 730, usage_metering: 400, ... } }   days; 0 = keep (only where the category allows it)
 */

const FORMAT = 1;

function validate(config) {
  const cats = require('../../../src/core/dataGovernance/categories');
  for (const k of Object.keys(config)) if (k !== 'retentionFormat' && k !== 'byCategory') throw new Error(`unknown DATA_RETENTION config key: ${k}`);
  if (config.retentionFormat !== FORMAT) throw new Error(`config.retentionFormat must be ${FORMAT}`);
  const by = config.byCategory;
  if (by === null || typeof by !== 'object' || Array.isArray(by) || Object.keys(by).length === 0) throw new Error('config.byCategory must be a non-empty object { category: days }');
  const problems = cats.validateRetention(by);
  if (problems.length) throw new Error(problems[0]);
}

function preprocess(config) { return config; }
function evaluate() { return { pass: true }; }

module.exports = { validate, preprocess, evaluate, FORMAT };
