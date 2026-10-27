'use strict';

/**
 * DLP engine: scan text, then DETECT / REDACT / MASK / BLOCK what was found.
 *
 *   scan(text, { rules?, minConfidence? })            -> { findings, rules }          findings: [{ rule, category, start, end, confidence }] in ORIGINAL offsets
 *   transform(text, { action, rules?, minConfidence?, tokenKey? })
 *                                                    -> { action, blocked, text, findings, rules, inputHashBefore, inputHashAfter }
 *
 * Evasion handling: detectors run on a NORMALISED view (Unicode NFKC, zero-width / soft-hyphen / bidi controls removed, so fullwidth digits, joiners and homoglyph
 * digit forms do not hide a number) and every finding is mapped back to the ORIGINAL offsets, so redaction removes exactly what the user typed. Input is scanned in
 * bounded windows (MAX_SCAN_CHARS); text beyond the cap is reported as `truncated` and, for BLOCK/REDACT, is treated as unscanned (the caller decides - see `onTruncated`).
 *
 * REDACT replaces each finding by a STABLE token  [[<RULE>:<12 hex>]]  =  HMAC-SHA256(tokenKey, rule || 0x00 || normalised value)  - the same value gives the same token
 * (joins and conversation coherence survive redaction) and the token cannot be reversed or rainbow-tabled without the key. MASK keeps a recognisable tail
 * (last 4 of a card/IBAN, first letter + domain of an e-mail). Overlapping findings are merged (the longer / more specific wins).
 *
 * `inputHashBefore` / `inputHashAfter` are SHA-256 over the UTF-8 text before and after the transformation (audit schema v8 `dlp` field), so a log of the transformed
 * request can never be mistaken for the request that was received.
 */

const crypto = require('crypto');
const { DETECTORS } = require('./detectors');

const MAX_SCAN_CHARS = 1_048_576;
const MAX_FINDINGS = 20_000;
const ACTIONS = Object.freeze(['DETECT', 'REDACT', 'MASK', 'BLOCK']);
// characters that carry no visible content and are used to break up a number or a keyword
const INVISIBLE_RANGES = [[0x00AD, 0x00AD], [0x034F, 0x034F], [0x061C, 0x061C], [0x115F, 0x1160], [0x17B4, 0x17B5], [0x180B, 0x180E], [0x200B, 0x200F], [0x202A, 0x202E],
  [0x2060, 0x206F], [0x2800, 0x2800], [0x3164, 0x3164], [0xFE00, 0xFE0F], [0xFEFF, 0xFEFF], [0xFFA0, 0xFFA0], [0xFFFC, 0xFFFC], [0xE0000, 0xE01EF]];   // written as code points: the characters themselves are invisible in a diff
// besides the list: every format character (Cf: Arabic number signs, musical formatting, ...), combining mark (Mn, Me: a combining accent on a digit) and C0/C1 control except the
// whitespace controls. Composed letters survive because NFKC has composed them before the marks are looked at.
const INVISIBLE_CLASS = /^[\p{Cf}\p{Mn}\p{Me}]$/u;
const CONTROL_CLASS = /^[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]$/;
const isInvisible = (cp, ch) => INVISIBLE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi) || INVISIBLE_CLASS.test(ch) || CONTROL_CLASS.test(ch);

// Letters of other scripts that are drawn like Latin ones, folded to the Latin letter for DETECTION only (the original text is what gets redacted). Cyrillic and Greek, the common ones.
const CONFUSABLE_FROM = '\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u043a\u043c\u0442\u0432\u043d\u0456\u0458\u0455\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u0423\u0406\u0408\u0405\u03bf\u03b1\u03b5\u03c1\u03c5\u03bd\u03ba\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7';
const CONFUSABLE_TO = 'aeopcxykmtbhijsABEKMHOPCTXYIJSoaepuvkABEZHIKMNOPTYX';
const CONFUSABLE = new Map([...CONFUSABLE_FROM].map((c, i) => [c, CONFUSABLE_TO[i]]));

const sha256Hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

/** Normalised view + offset map: norm[i] came from original index map[i]; mapEnd[i] is the original index just after that character. */
function normalise(text) {
  let out = ''; const map = []; const mapEnd = [];
  let i = 0; let capped = false;
  const limit = text.length * 2 + 1024;                    // NFKC can expand one character into 18: the view is bounded, the excess counts as unscanned (truncated)
  while (i < text.length) {
    const cp = text.codePointAt(i); const ch = String.fromCodePoint(cp); const len = ch.length;
    if (!isInvisible(cp, ch)) {
      const n = ch.normalize('NFKC');
      for (let k = 0; k < n.length; k++) { out += CONFUSABLE.get(n[k]) || n[k]; map.push(i); mapEnd.push(i + len); }
      if (out.length > limit) { capped = true; break; }
    }
    i += len;
  }
  return { norm: out, map, mapEnd, capped };
}

function activeDetectors(rules) {
  if (!rules || rules.length === 0 || rules.includes('*')) return DETECTORS;
  const want = new Set(rules);
  return DETECTORS.filter((d) => want.has(d.id) || want.has(d.category));
}

/**
 * @param {string} text
 * @param {{ rules?: string[], minConfidence?: number }} [opts]
 */
function scan(text, { rules, minConfidence = 0 } = {}) {
  if (typeof text !== 'string') throw new TypeError('DLP scan: text must be a string');
  const truncated = text.length > MAX_SCAN_CHARS;
  const slice = truncated ? text.slice(0, MAX_SCAN_CHARS) : text;
  const { norm, map, mapEnd, capped } = normalise(slice);
  const raw = [];
  for (const det of activeDetectors(rules)) {
    for (const f of det.find(norm)) {
      const confidence = /** @type {any} */ (f).confidence ?? det.confidence;
      if (confidence < minConfidence) continue;
      raw.push({ rule: det.id, category: det.category, start: map[f.start], end: mapEnd[f.end - 1], confidence, value: norm.slice(f.start, f.end) });
    }
  }
  // overlap resolution: overlapping findings form a CLUSTER; the cluster is replaced as a whole (its span is the union, so no tail of a dropped finding survives a redaction),
  // named by its most confident member (ties: the longer one), and the other rules that fired inside it are kept in `alsoRules`
  raw.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start) || b.confidence - a.confidence);
  const findings = []; let cur = null;
  const flush = () => {
    if (!cur) return;
    const w = cur.members.reduce((x, y) => (y.confidence > x.confidence || (y.confidence === x.confidence && y.end - y.start > x.end - x.start) ? y : x));
    findings.push({ rule: w.rule, category: w.category, start: cur.start, end: cur.end, confidence: w.confidence, value: w.value, alsoRules: [...new Set(cur.members.map((m) => m.rule).filter((r) => r !== w.rule))].sort() });
  };
  for (const f of raw) {
    if (cur && f.start < cur.end) { cur.members.push(f); if (f.end > cur.end) cur.end = f.end; } else { flush(); cur = { start: f.start, end: f.end, members: [f] }; }
  }
  flush();
  const tooMany = findings.length > MAX_FINDINGS;                       // a result that is mostly findings is a dump: not scanned further, handled like text past the cap
  const kept = tooMany ? findings.slice(0, MAX_FINDINGS) : findings;
  return { findings: kept, rules: [...new Set(kept.map((f) => f.rule))].sort(), truncated: truncated || capped || tooMany };
}

// what "the same value" means per rule: an e-mail address is case-insensitive (its local part is not rewritten otherwise); numbers and ids are the same number however they were grouped;
// everything else is compared as typed
function canonicalValue(rule, value) {
  if (rule === 'EMAIL') return value.toLowerCase();
  if (rule === 'IBAN') return value.replace(/[\s.-]/g, '').toUpperCase();
  if (rule === 'CARD' || rule === 'PHONE' || /^(CNP|PESEL|BSN|DE_TAX_ID|US_SSN|ES_DNI_NIE|UK_NINO)$/.test(rule)) return value.replace(/[\s.\-/_\u2010-\u2013]/g, '').toUpperCase();
  return value;
}
function stableToken(rule, value, key) {
  const mac = crypto.createHmac('sha256', key).update(rule).update('\u0000').update(canonicalValue(rule, value)).digest('hex').slice(0, 12);
  return `[[${rule}:${mac}]]`;
}

// MASK keeps a recognisable tail but never more than a quarter of the value, and never lets the length of a secret show
function maskOf(f) {
  const v = f.value;
  if (f.rule === 'EMAIL') {
    const at = v.indexOf('@'); const local = v.slice(0, at);
    return `${local.length >= 4 ? local[0] : ''}${'*'.repeat(Math.max(3, Math.min(local.length - (local.length >= 4 ? 1 : 0), 8)))}${v.slice(at)}`;
  }
  if (f.category === 'FINANCIAL' || f.category === 'NATIONAL_ID' || f.rule === 'PHONE') {
    const digits = v.replace(/[^A-Za-z0-9]/g, ''); const keep = Math.min(4, Math.floor(digits.length / 4));
    return `${'*'.repeat(Math.max(4, digits.length - keep))}${keep ? digits.slice(-keep) : ''}`;
  }
  return '*'.repeat(12);
}

/**
 * @param {string} text
 * @param {{ action?: 'DETECT'|'REDACT'|'MASK'|'BLOCK', rules?: string[], minConfidence?: number, tokenKey?: Buffer|string, onTruncated?: 'BLOCK'|'PASS' }} o
 */
function transform(text, { action = 'DETECT', rules, minConfidence = 0, tokenKey, onTruncated = 'BLOCK' } = {}) {
  if (!ACTIONS.includes(action)) throw new TypeError(`DLP action must be one of ${ACTIONS.join(', ')}`);
  if (action === 'REDACT' && (!tokenKey || tokenKey.length < 16)) throw new TypeError('DLP REDACT needs a tokenKey of at least 16 bytes (stable tokens must not be guessable)');
  const before = sha256Hex(text);
  const { findings, rules: hit, truncated } = scan(text, { rules, minConfidence });
  const unscanned = truncated && onTruncated === 'BLOCK' && action !== 'DETECT';
  const base = { action, findings: findings.map(({ value, ...f }) => f), rules: hit, truncated, inputHashBefore: before };
  if (action === 'BLOCK' && (findings.length > 0 || unscanned)) return { ...base, blocked: true, text: null, inputHashAfter: before };
  if (unscanned) return { ...base, blocked: true, text: null, inputHashAfter: before };
  if (action === 'DETECT' || action === 'BLOCK' || findings.length === 0) return { ...base, blocked: false, text, inputHashAfter: before };
  let out = ''; let pos = 0;
  for (const f of findings) {
    out += text.slice(pos, f.start);
    out += action === 'REDACT' ? stableToken(f.rule, f.value, tokenKey) : maskOf(f);
    pos = f.end;
  }
  out += text.slice(pos);
  return { ...base, blocked: false, text: out, inputHashAfter: sha256Hex(out) };
}

module.exports = { scan, transform, normalise, ACTIONS, MAX_SCAN_CHARS, sha256Hex };
