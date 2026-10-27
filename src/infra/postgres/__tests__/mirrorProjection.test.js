'use strict';

/**
 * mirror projection P / P⁻¹.
 *
 *   MP-01  the §10 example vectors, byte for byte (String.raw literals = the exact projected ASCII)
 *   MP-02  the required character classes, singly and combined: ASCII, accented Latin, Romanian, CJK, emoji, quotes,
 *          backslashes, TAB / LF / CR, U+0000, lone high / low surrogate, empty string — P is pure printable ASCII,
 *          P⁻¹(P(s)) === s exactly
 *   MP-03  seeded property test over random UTF-16 code-unit strings (surrogate-, control- and backslash-heavy)
 *   MP-04  P is injective on distinct inputs (incl. already-escaped-looking text) and never emits a bare `"`
 *   MP-05  decode errors: unknown escape, uppercase hex, truncated \u, trailing backslash, raw control / non-ASCII /
 *          bare quote — MirrorDecodeError, never a guess
 *   MP-06  JSON recursion: nested executionContext / consentProvenance values and keys, arrays, numbers, booleans,
 *          null; key collisions after decoding are refused; "__proto__" round-trips as an own key
 *   MP-07  encodingOf: 0 / 1 / null / absent accepted; anything else refused
 *   MP-08  HASH INVARIANCE: for v7 entries carrying every class above in every per-field position, the canonical JSON
 *          and the hash recomputed from the P⁻¹(P(·)) fields are byte-identical to the originals
 */

const crypto = require('crypto');
const mp = require('../mirrorProjection');
const eb = require('../../../core/audit/entryBuilder');
const { sortedJSON } = require('../../crypto/hashing');

const ASCII_PRINTABLE = /^[\x20-\x7e]*$/;

// F6-N2: entryBuilder.normalizeFields now REFUSES U+0000 / lone surrogates at write time. The projection must still
// round-trip them (legacy / foreign rows), so entries carrying them are hand-sealed here: normalize a masked copy, put the
// real values back, recompute canonical + hash exactly as buildEntry does (CORE_HASH_FIELDS_V7, AUDIT domain).
const UNREP_G = /\u0000|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
const mask = (v) => (typeof v === 'string' ? v.replace(UNREP_G, '?') : Array.isArray(v) ? v.map(mask)
  : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [mask(k), mask(x)])) : v);
function sealV7(fields, prev) {
  const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../crypto/hashing');
  const e = { ...eb.buildEntry(eb.normalizeFields(mask(fields)), prev) };
  for (const k of Object.keys(fields)) if (k in e) e[k] = fields[k];
  const core = {}; for (const f of eb.CORE_HASH_FIELDS_V7) core[f] = e[f];
  e.canonical = sortedJSON(core);
  e.hash = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, e.canonical).toString('hex');
  return e;
}
const CLASSES = {
  ascii: 'PROVIDER_EXECUTION req-42 a+b=c',
  accented: 'éàüñçÉ Ångström naïve',
  romanian: 'Ștefan își ţară Ăîâșț',
  cjk: '漢字かなカナ한국어',
  emoji: '😀👩‍👩‍👧🇷🇴',
  quotes: 'say "hi" and \'bye\'',
  backslashes: 'C:\\temp\\new \\u00e9 \\\\ end\\',
  tabs: 'a\tb\t',
  newlines: 'line1\nline2\n',
  carriageReturns: 'r1\r\nr2\r',
  nul: 'a\u0000b\u0000',
  loneHigh: 'x\ud800y',
  loneLow: '\udc00z',
  empty: '',
  del: 'a\u007fb',
  lineSep: 'p\u2028q\u2029r',
};
const COMBINED = Object.values(CLASSES).join('|') + '\ud83d' + '"\\\u0000';

describe('mirror projection', () => {
  test('MP-01 §10 example vectors, byte for byte', () => {
    const v = [
      ['Ștefan își', String.raw`\u0218tefan \u00ee\u0219i`],
      ['😀', String.raw`\ud83d\ude00`],
      ['e\u0301', String.raw`e\u0301`],
      ['é', String.raw`\u00e9`],
      ['a\u0000b\tc', String.raw`a\u0000b\u0009c`],
      ['\ud800', String.raw`\ud800`],
      [String.raw`\u00e9`, String.raw`\\u00e9`],
      ['say "hi"', String.raw`say \"hi\"`],
      [String.raw`C:\temp`, String.raw`C:\\temp`],
      ['PROVIDER_EXECUTION', 'PROVIDER_EXECUTION'],
    ];
    for (const [input, projected] of v) {
      expect({ input, out: mp.encodeString(input) }).toEqual({ input, out: projected });
      expect(mp.decodeString(projected)).toBe(input);
    }
    expect(JSON.stringify(mp.encodeJson({ subject: 'Ștefan', n: 1, tags: ['😀'] })))
      .toBe(String.raw`{"subject":"\\u0218tefan","n":1,"tags":["\\ud83d\\ude00"]}`);
  });

  test('MP-02 every required class, singly and combined: pure printable ASCII, exact round trip', () => {
    for (const [name, s] of [...Object.entries(CLASSES), ['combined', COMBINED]]) {
      const p = mp.encodeString(s);
      expect({ name, ascii: ASCII_PRINTABLE.test(p), back: mp.decodeString(p) === s }).toEqual({ name, ascii: true, back: true });
    }
    expect(mp.encodeString('')).toBe('');
  });

  test('MP-03 seeded property test: P⁻¹(P(s)) === s for 20,000 random UTF-16 strings', () => {
    let seed = 0x5eed;
    const rnd = () => { seed = (seed * 1103515245 + 12345) >>> 0; return seed; };
    const pools = [() => rnd() % 0x10000, () => 0xd800 + (rnd() % 0x800), () => rnd() % 0x20, () => [0x5c, 0x22, 0x75, 0x30][rnd() % 4], () => 0x20 + (rnd() % 0x5f)];
    for (let n = 0; n < 20000; n++) {
      const len = rnd() % 24;
      let s = '';
      for (let i = 0; i < len; i++) s += String.fromCharCode(pools[rnd() % pools.length]());
      const p = mp.encodeString(s);
      if (!ASCII_PRINTABLE.test(p) || mp.decodeString(p) !== s) throw new Error(`property violated for ${JSON.stringify(s)}`);
    }
  });

  test('MP-04 injective: distinct inputs never share a projection; P never emits a bare quote', () => {
    const inputs = [...Object.values(CLASSES), COMBINED, String.raw`\u0000`, '\u0000', String.raw`\"`, '"', '\\', String.raw`\\`, 'é', String.raw`\u00e9`];
    const seen = new Map();
    for (const s of inputs) {
      const p = mp.encodeString(s);
      expect(p.replace(/\\\\|\\"/g, '')).not.toMatch(/"/);
      if (seen.has(p)) expect(seen.get(p)).toBe(s);
      seen.set(p, s);
    }
    expect(seen.size).toBe(new Set(inputs).size);
  });

  test('MP-05 corrupt projected values raise MirrorDecodeError — never a guess', () => {
    const bad = [String.raw`\x41`, String.raw`\n`, String.raw`\u00E9`, String.raw`\u00g9`, String.raw`ab\u12`, 'end\\', 'raw\u0000nul', 'raw é', 'bare"quote', 'tab\there'];
    for (const t of bad) {
      let err = null;
      try { mp.decodeString(t, 'reason'); } catch (e) { err = e; }
      expect({ t, name: err && err.name, code: err && err.code, where: err && err.where }).toEqual({ t, name: 'MirrorDecodeError', code: 'MIRROR_DECODE_ERROR', where: 'reason' });
    }
  });

  test('MP-06 JSON recursion: nested values and keys, arrays, scalars; collisions refused; __proto__ stays an own key', () => {
    const value = {
      stage: 'PROVIDER_DISPATCH', 'clé Ș': { deep: [CLASSES.nul, CLASSES.loneHigh, { [CLASSES.emoji]: CLASSES.backslashes }], n: 1.5, t: true, z: null },
      consent: { consentId: 'c-1', subject: 'ap1:' + 'a'.repeat(64), scope: [CLASSES.romanian, CLASSES.cjk] }, empty: '', arr: [],
    };
    const enc = mp.encodeJson(value);
    expect(JSON.stringify(enc)).toMatch(/^[\x20-\x7e]*$/);
    expect(mp.decodeJson(JSON.parse(JSON.stringify(enc)))).toEqual(value);   // through JSON text, as JSONB returns it
    expect(() => mp.decodeJson({ a: 1, [String.raw`\u0061`]: 2 })).toThrow(mp.MirrorDecodeError);
    const proto = mp.decodeJson(JSON.parse('{"__proto__":{"x":1}}'));
    expect(Object.prototype.hasOwnProperty.call(proto, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(proto)).toBe(Object.prototype);
    expect(mp.decodeJson(null)).toBeNull();
    expect(mp.encodeJson(42)).toBe(42);
  });

  test('MP-07 encodingOf accepts only 0 / 1 (null / absent = 0)', () => {
    expect([mp.encodingOf(0), mp.encodingOf(1), mp.encodingOf('1'), mp.encodingOf(null), mp.encodingOf(undefined)]).toEqual([0, 1, 1, 0, 0]);
    for (const v of [2, -1, 'x', 1.5]) expect(() => mp.encodingOf(v)).toThrow(mp.MirrorDecodeError);
  });

  test('MP-08 HASH INVARIANCE: canonical and hash recomputed from P⁻¹(P(fields)) are byte-identical', () => {
    const TEXT = ['artifactId', 'decision', 'inputHash', 'signature', 'requestHash', 'policyHash', 'nonce', 'tenantId', 'publicKeyId', 'provider', 'model', 'stage', 'reason', 'responseId', 'entryType', 'outputHash', 'requestId', 'organizationId', 'executingProvider', 'highResTime'];
    const JSONB = ['executionContext', 'consentProvenance', 'policyDecision', 'callerContext', 'semantic', 'tokenUsage'];
    let prev = 'GENESIS';
    for (const [name, s] of [...Object.entries(CLASSES), ['combined', COMBINED]]) {
      const e = sealV7({
        artifactId: 'mp08-' + name + s, inputHash: 'a'.repeat(64), decision: 'BLOCK', signature: 'sig' + s, requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
        verificationResult: false, nonce: 'n' + s, tenantId: 't' + s, organizationId: 'o' + s, requestId: 'r' + s, publicKeyId: 'k' + s, provider: 'p' + s, model: 'm' + s,
        stage: 'S' + s, reason: 'R' + s, responseId: 'resp' + s, executingProvider: 'x' + s,
        executionContext: { stage: s, nested: { [s || 'k']: [s, 1, null] } }, consentProvenance: { consentId: 'c' + s, subject: s }, policyDecision: { policyId: s, path: [s] },
        callerContext: { callerId: 'ap1:' + 'd'.repeat(64), callerName: s }, semantic: { decision: s, score: 0.25 }, tokenUsage: { [s + 'k']: 3 },
      }, prev);
      expect(eb.verifyCanonicalHash(e)).toBe(true);
      prev = e.hash;
      const back = { ...e };
      for (const f of TEXT) if (typeof e[f] === 'string') back[f] = mp.decodeString(mp.encodeString(e[f]));
      for (const f of JSONB) if (e[f] != null) back[f] = mp.decodeJson(JSON.parse(JSON.stringify(mp.encodeJson(e[f]))));
      const core = {}; for (const f of eb.CORE_HASH_FIELDS_V7) core[f] = back[f];
      expect({ name, canonical: sortedJSON(core) === e.canonical, hash: eb.expectedHashFor(back) === e.hash, verify: eb.verifyCanonicalHash(back) }).toEqual({ name, canonical: true, hash: true, verify: true });
    }
    // and P is NOT applied to canonical / hash: the canonical text is already pure JSON (no raw NUL / lone surrogate)
    const sample = sealV7({ artifactId: 'x', decision: 'BLOCK', reason: COMBINED }, 'GENESIS');
    expect(sample.canonical).not.toMatch(/\u0000|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/);   // no NUL, no LONE surrogate (pairs are valid UTF-8)
    expect(crypto.createHash('sha256').update('QODIQA::AUDIT::V1', 'utf8').update(sample.canonical, 'utf8').digest('hex')).toBe(sample.hash);
  });
});
