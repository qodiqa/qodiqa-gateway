'use strict';

/**
 * Public surface of the DLP module. Everything outside enterprise/dlp/ reaches it ONLY through src/core/dlp/extensionPoint.js (guarded by
 *), so the directory can be moved to another repository or licence without touching the core.
 */
const { scan, transform, normalise, ACTIONS, MAX_SCAN_CHARS, sha256Hex } = require('./engine');
const { DETECTORS } = require('./detectors');
const { classify, exfiltration, LEVELS, rank } = require('./classify');
const profiles = require('./profiles');

const RULE_IDS = Object.freeze(DETECTORS.map((d) => d.id));
const CATEGORIES = Object.freeze([...new Set(DETECTORS.map((d) => d.category))]);
const describe = () => DETECTORS.map((d) => ({ id: d.id, category: d.category, confidence: d.confidence }));

module.exports = { VERSION: 1, scan, transform, normalise, ACTIONS, MAX_SCAN_CHARS, sha256Hex, RULE_IDS, CATEGORIES, describe, classify, exfiltration, LEVELS, rank, profiles };
