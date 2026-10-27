'use strict';

/**
 * V9 auxiliary features — · B-2 (a').
 *
 * The 21 cheap signals the V9 gate consumes alongside the frozen MiniLM
 * embedding. All of them are derived from modules the semantic layer already
 * owns, so none costs a model pass:
 *
 *    5  i18nSignals concept confidences
 *   12  textSignals normalization meta flags
 *    4  surface ratios (log length, uppercase, digit, non-alphanumeric)
 *
 * ONE IMPLEMENTATION, DELIBERATELY. This module is the single definition,
 * required by both the production gate and the offline spikes
 *. A feature computed one way
 * at fit time and another way at inference time would silently invalidate
 * every measured figure, and B-2 (a')'s protocol allows exactly one final
 * measurement in which to notice.
 *
 * ORDER IS LOAD-BEARING. The trained weight vector indexes these features
 * positionally, so CONCEPT_KEYS then META_KEYS then the four surface ratios,
 * in exactly this sequence, is part of the model contract — not a stylistic
 * choice. It is pinned in __tests__/thresholdPinning.test.js.
 */

const { analyzeNormalization, normalize, scoreSignals } = require('../textSignals');
const { CONCEPTS } = require('../i18nSignals');

const CONCEPT_KEYS = Object.keys(CONCEPTS);
const META_KEYS = Object.freeze([
  'changed', 'truncated', 'base64Decoded', 'hexDecoded', 'urlDecoded', 'htmlEntityDecoded',
  'unicodeEscapeDecoded', 'homoglyphFolded', 'pictographicStripped', 'evasionCharsStripped',
  'repetitionCollapsed', 'fragmentsReconstructed',
]);
const SURFACE_COUNT = 4;
const EXTRA = CONCEPT_KEYS.length + META_KEYS.length + SURFACE_COUNT; // 5 + 12 + 4 = 21

/**
 * @param {string} text one window's text (<= MAX_CHARS_PER_WINDOW by contract)
 * @returns {Float64Array} EXTRA raw (un-standardised) feature values
 */
function rawFeatures(text) {
  const f = new Float64Array(EXTRA);
  const norm = normalize(text);
  let k = 0;
  for (const c of CONCEPT_KEYS) f[k++] = scoreSignals(norm, CONCEPTS[c]).confidence || 0;
  const meta = analyzeNormalization(text);
  for (const m of META_KEYS) f[k++] = meta[m] ? 1 : 0;
  const s = String(text);
  const len = s.length || 1;
  let up = 0; let dig = 0; let non = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch >= 'A' && ch <= 'Z') up++;
    if (ch >= '0' && ch <= '9') dig++;
    if (!/[a-zA-Z0-9]/.test(ch)) non++;
  }
  f[k++] = Math.log1p(len);
  f[k++] = up / len;
  f[k++] = dig / len;
  f[k++] = non / len;
  return f;
}

module.exports = { rawFeatures, CONCEPT_KEYS, META_KEYS, EXTRA };
