'use strict';

/**
 * DLP units. Every secret-shaped value is BUILT at run time from parts (a literal in this file would be a repository secret to scanners).
 *
 *   DLP-01  each detector: a valid value is found, a near miss is not (checksums: Luhn, IBAN mod 97, CNP, PESEL, BSN, DNI)
 *   DLP-02  evasion: zero-width / soft hyphen / bidi controls, fullwidth digits, separators
 *   DLP-03  REDACT: stable tokens (same value -> same token, other key -> other token), no value survives, offsets are the original's
 *   DLP-04  MASK and DETECT; BLOCK; minConfidence; rule selection by id and category
 *   DLP-05  the two hashes of the audit entry
 *   DLP-06  bounds: the scan cap, onTruncated
 *   DLP-07  ReDoS fuzz: adversarial inputs for every detector finish in bounded time
 */

const { scan, transform, MAX_SCAN_CHARS, sha256Hex } = require('../engine');
const { luhn, mod97 } = require('../detectors');

const KEY = Buffer.alloc(32, 7);
const ZW = String.fromCharCode(0x200b); const SHY = String.fromCharCode(0x00ad); const RLO = String.fromCharCode(0x202e);

function luhnComplete(prefix, len) { let body = prefix; while (body.length < len - 1) body += String((body.length * 7 + 3) % 10); for (let c = 0; c < 10; c++) if (luhn(body + c)) return body + c; throw new Error('no luhn'); }
function ibanOf(cc, bban) { const rem = mod97(bban + cc + '00'); return `${cc}${String(98 - rem).padStart(2, '0')}${bban}`; }
function cnpOf(s, yy, mm, dd, jj, nnn) { const d = `${s}${yy}${mm}${dd}${jj}${nnn}`; const w = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9]; let sum = 0; for (let i = 0; i < 12; i++) sum += Number(d[i]) * w[i]; const c = sum % 11 === 10 ? 1 : sum % 11; return d + c; }
const rules = (t, o) => scan(t, o).rules;

describe('DLP-01 detectors', () => {
  test('email', () => {
    expect(rules('write to a.b+c@sub.example.co.uk now')).toEqual(['EMAIL']);
    expect(rules('user@localhost and a@b and x@1.23')).toEqual([]);
  });
  test('card (Luhn + issuer + length)', () => {
    const visa = luhnComplete('4', 16); const amex = luhnComplete('37', 15); const mc = luhnComplete('51', 16);
    for (const n of [visa, amex, mc]) expect(rules(`pay with ${n} please`)).toEqual(['CARD']);
    expect(rules(`pay ${visa.slice(0, 4)} ${visa.slice(4, 8)} ${visa.slice(8, 12)} ${visa.slice(12)}`)).toEqual(['CARD']);
    expect(rules(`pay ${visa.slice(0, 4)}-${visa.slice(4, 8)}-${visa.slice(8, 12)}-${visa.slice(12)}`)).toEqual(['CARD']);
    const bad = visa.slice(0, 15) + ((Number(visa[15]) + 1) % 10);
    expect(rules(`order ${bad}`)).toEqual([]);                                  // fails Luhn
    expect(rules('invoice 1234567890123456')).toEqual([]);                      // no issuer
  });
  test('iban (country length + mod 97)', () => {
    const de = ibanOf('DE', '370400440532013000'); const gb = ibanOf('GB', 'NWBK60161331926819'); const ro = ibanOf('RO', 'AAAA1B31007593840000');
    for (const i of [de, gb, ro]) { expect(rules(`iban ${i} ok`)).toEqual(['IBAN']); expect(rules(`iban ${i.replace(/(.{4})/g, '$1 ').trim()} ok`)).toEqual(['IBAN']); }
    expect(rules(`iban ${de.slice(0, -1)}1`)).toEqual([]);                      // wrong check digits (if not coincidentally valid)
    expect(rules('iban XX00 1234 5678')).toEqual([]);
  });
  test('cnp / pesel / bsn / dni / ssn / nino', () => {
    const cnp = cnpOf(1, '80', '01', '01', '22', '114'); expect(rules(`cnp ${cnp}`)).toEqual(['CNP']);
    expect(rules(`cnp ${cnp.slice(0, 12)}${(Number(cnp[12]) + 1) % 10}`)).toEqual([]);
    expect(rules('cnp 1801301221149')).toEqual([]);                             // 30 January is valid, month 13 is not: use an impossible date
    expect(rules('pesel 44051401458')).toEqual(['PESEL']);                      // published sample number
    expect(rules('bsn 111222333')).toEqual(['BSN']);
    expect(rules('dni 12345678Z')).toEqual(['ES_DNI_NIE']);
    expect(rules('dni 12345678A')).toEqual([]);
    expect(rules('ssn 123-45-6789')).toEqual(['US_SSN']);
    expect(rules('ssn 000-45-6789 and 666-12-3456 and 900-12-3456', { rules: ['US_SSN'] })).toEqual([]);     // (they still look like phone numbers to the PHONE detector)
    expect(rules('nino AB 12 34 56 C')).toEqual(['UK_NINO']);
    expect(rules('nino BG 12 34 56 C')).toEqual([]);
  });
  test('phone is shape-only: separators or a plus are needed', () => {
    expect(rules('call +40 721 234 567 today')).toEqual(['PHONE']);
    expect(rules('call (555) 123-4567 today')).toEqual(['PHONE']);
    expect(rules('number 5551234567')).toEqual([]);
    expect(rules('date 2026-10-22')).toEqual([]);
    expect(scan('call +40 721 234 567').findings[0].confidence).toBeGreaterThan(scan('call (555) 123-4567').findings[0].confidence);
  });
  test('credentials: known prefixes, PEM, JWT, assignments', () => {
    const aws = 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP'; const gh = 'gh' + 'p_' + 'a'.repeat(36); const stripe = 'sk_' + 'live_' + 'A1b2C3d4E5f6G7h8I9j0';
    const slack = 'xo' + 'xb-' + '1234567890-abcdefghij'; const goog = 'AI' + 'za' + 'S'.repeat(35); const ant = 'sk-' + 'ant-' + 'api03-' + 'Zz9'.repeat(10);
    const qod = 'sk' + '_' + 'ab'.repeat(32);
    for (const [id, v] of [['KEY_AWS_ACCESS', aws], ['KEY_GITHUB', gh], ['KEY_STRIPE', stripe], ['KEY_SLACK', slack], ['KEY_GOOGLE_API', goog], ['KEY_ANTHROPIC', ant], ['KEY_QODIQA', qod]])
      expect(rules(`token is ${v} end`)).toEqual([id]);
    const pem = ['-----BEGIN ' + 'PRIVATE KEY-----', 'MIIE' + 'vQIBADANBgkqhkiG9w0BAQEFAASC', '-----END ' + 'PRIVATE KEY-----'].join('\n');
    const r = scan(`here:\n${pem}\nthanks`); expect(r.rules).toEqual(['PEM_BLOCK']); expect(r.findings[0].end - r.findings[0].start).toBe(pem.length);
    expect(rules(['-----BEGIN ' + 'CERTIFICATE-----', 'AAAA', '-----END ' + 'CERTIFICATE-----'].join('\n'))).toEqual([]);      // a public certificate is not secret
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    expect(rules(`auth ${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ sub: '1' })}.${'s'.repeat(20)}`)).toEqual(['JWT']);
    expect(rules(`eyJ${'a'.repeat(10)}.eyJ${'b'.repeat(10)}.sig`)).toEqual([]);                                             // not decodable
    expect(rules('config = { password: "Tr0ub4dor&3xyz" }')).toEqual(['CODE_SECRET']);
    expect(rules('config = { password: "changeme" } and secret = "xxxxxxxx"')).toEqual([]);
  });
});

describe('DLP-02 evasion', () => {
  const visa = luhnComplete('4', 16);
  test('zero-width / soft hyphen / bidi controls inside a number do not hide it, and redaction covers the original characters', () => {
    const broken = visa.split('').join(ZW);
    const t = transform(`pay ${broken} now`, { action: 'REDACT', tokenKey: KEY });
    expect(t.rules).toEqual(['CARD']); expect(t.text).toMatch(/^pay \[\[CARD:[0-9a-f]{12}\]\] now$/);
    expect(transform(`pay ${visa.slice(0, 8)}${SHY}${visa.slice(8)}`, { action: 'MASK' }).rules).toEqual(['CARD']);
    expect(rules(`pay ${RLO}${visa}`)).toEqual(['CARD']);
  });
  test('fullwidth digits and compatibility forms', () => {
    const fw = visa.replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + Number(d)));
    expect(rules(`pay ${fw}`)).toEqual(['CARD']);
    expect(rules('mail＠example.com'.replace('mail', 'bob'))).toEqual(['EMAIL']);          // fullwidth @
  });
  test('an e-mail split by a zero-width character is still an e-mail', () => {
    expect(rules(`bob${ZW}@example${ZW}.com`)).toEqual(['EMAIL']);
  });
});

describe('DLP-03 / 04 actions', () => {
  const visa = luhnComplete('4', 16); const mail = 'jane.roe@example.org';
  test('REDACT: stable tokens, per-key, nothing of the value left', () => {
    const a = transform(`${mail} and again ${mail} and ${visa}`, { action: 'REDACT', tokenKey: KEY });
    const tokens = a.text.match(/\[\[EMAIL:[0-9a-f]{12}\]\]/g);
    expect(tokens).toHaveLength(2); expect(tokens[0]).toBe(tokens[1]);
    expect(a.text).not.toContain('jane'); expect(a.text).not.toContain(visa);
    const b = transform(mail, { action: 'REDACT', tokenKey: Buffer.alloc(32, 9) });
    expect(b.text).not.toBe(tokens[0]);
    expect(() => transform(mail, { action: 'REDACT' })).toThrow(/tokenKey/);
    expect(() => transform(mail, { action: 'REDACT', tokenKey: 'short' })).toThrow(/tokenKey/);
  });
  test('the same card with other separators gets the same token (normalised value)', () => {
    const spaced = `${visa.slice(0, 4)} ${visa.slice(4, 8)} ${visa.slice(8, 12)} ${visa.slice(12)}`;
    const t1 = transform(visa, { action: 'REDACT', tokenKey: KEY }).text; const t2 = transform(spaced, { action: 'REDACT', tokenKey: KEY }).text;
    expect(t1).toBe(t2);
  });
  test('MASK keeps a recognisable tail; DETECT changes nothing; BLOCK withholds the text', () => {
    expect(transform(`card ${visa}`, { action: 'MASK' }).text).toBe(`card ${'*'.repeat(12)}${visa.slice(-4)}`);
    expect(transform(mail, { action: 'MASK' }).text).toBe('j' + '*'.repeat(7) + '@example.org');
    const d = transform(`${mail} ${visa}`, { action: 'DETECT' }); expect(d.text).toBe(`${mail} ${visa}`); expect(d.rules).toEqual(['CARD', 'EMAIL']); expect(d.blocked).toBe(false);
    const b = transform(`x ${visa}`, { action: 'BLOCK' }); expect(b.blocked).toBe(true); expect(b.text).toBeNull();
    expect(transform('nothing here', { action: 'BLOCK' })).toMatchObject({ blocked: false, text: 'nothing here', rules: [] });
  });
  test('rule selection by id or category, and minConfidence', () => {
    const t = `${mail} ${visa} call (555) 123-4567`;
    expect(rules(t, { rules: ['EMAIL'] })).toEqual(['EMAIL']);
    expect(rules(t, { rules: ['FINANCIAL'] })).toEqual(['CARD']);
    expect(rules(t, { rules: ['*'] })).toEqual(['CARD', 'EMAIL', 'PHONE']);
    expect(rules(t, { minConfidence: 0.9 })).toEqual(['CARD', 'EMAIL']);
  });
  test('overlapping findings never produce overlapping edits', () => {
    const iban = ibanOf('DE', '370400440532013000');
    const t = transform(`${iban} ${iban.replace(/(.{4})/g, '$1 ').trim()}`, { action: 'REDACT', tokenKey: KEY });
    expect(t.text).toMatch(/^\[\[IBAN:[0-9a-f]{12}\]\] \[\[IBAN:[0-9a-f]{12}\]\]$/);
  });
});

describe('DLP-05 audit hashes', () => {
  test('before and after are the SHA-256 of the two texts; they differ iff the text changed', () => {
    const mail = 'x@example.org'; const t = transform(`hi ${mail}`, { action: 'REDACT', tokenKey: KEY });
    expect(t.inputHashBefore).toBe(sha256Hex(`hi ${mail}`)); expect(t.inputHashAfter).toBe(sha256Hex(t.text));
    expect(t.inputHashBefore).not.toBe(t.inputHashAfter);
    const same = transform('hello', { action: 'REDACT', tokenKey: KEY }); expect(same.inputHashBefore).toBe(same.inputHashAfter);
    expect(t.inputHashBefore).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('DLP-06 bounds', () => {
  test('text past the scan cap is reported; REDACT/BLOCK refuse it by default', () => {
    const big = 'a'.repeat(MAX_SCAN_CHARS) + ' tail@example.org';
    expect(scan(big).truncated).toBe(true);
    expect(transform(big, { action: 'REDACT', tokenKey: KEY })).toMatchObject({ blocked: true, text: null, truncated: true });
    expect(transform(big, { action: 'REDACT', tokenKey: KEY, onTruncated: 'PASS' })).toMatchObject({ blocked: false, truncated: true });
    expect(transform(big, { action: 'DETECT' }).blocked).toBe(false);
  });
});

describe('DLP-07 ReDoS fuzz', () => {
  const N = 200_000;
  const cases = {
    'long local part': 'a'.repeat(N) + '@',
    'many at signs': '@a'.repeat(N / 2),
    'dots': 'a.'.repeat(N / 2) + '@',
    'digit separators': '1 '.repeat(N / 2),
    'dash digits': '1-'.repeat(N / 2),
    'iban groups': 'DE89' + ' ABCD'.repeat(N / 5),
    'plus digits': '+1' + ' 1'.repeat(N / 2),
    'pem begin spam': ('-----BEGIN ' + 'PRIVATE ' + 'KEY-----').repeat(N / 27),
    'jwt prefix': 'eyJ' + 'a'.repeat(N),
    'jwt dots': ('eyJabcde.'.repeat(N / 9)),
    'secret assignment': 'password' + ' '.repeat(N) + '=',
    'secret quotes': 'secret = "' + 'a '.repeat(N / 2),
    'nino groups': 'AB ' + '12 '.repeat(N / 3),
    'ssn spam': '123-45-'.repeat(N / 7),
    'key prefixes': 'ghp_'.repeat(N / 4) + 'AKIA'.repeat(N / 4) + 'sk-'.repeat(N / 3),
    'unicode invisibles': ZW.repeat(N),
    'mixed': 'a@b.c 1 1 AB12 DE89 -----BEGIN '.repeat(N / 30),
  };
  for (const [name, input] of Object.entries(cases)) {
    test(`bounded time: ${name}`, () => {
      const t0 = process.hrtime.bigint();
      scan(input);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      expect(ms).toBeLessThan(4000);
    });
  }
});

describe('DLP-08 repairs after the independent verification', () => {
  const visa = luhnComplete('4', 16); const masterc = luhnComplete('51', 16);
  const grp = (s) => `${s.slice(0, 4)} ${s.slice(4, 8)} ${s.slice(8, 12)} ${s.slice(12)}`;
  const kinds = (t, o) => scan(t, o).findings.map((f) => f.rule);

  test('a card next to another number is still found, in every arrangement', () => {
    for (const t of [`1 ${grp(visa)}`, `${visa} ${masterc}`, `2024-01-15 ${grp(visa)}`, `${grp(visa)} 20240115`, `order 12345678 ${grp(visa)}`, `${grp(visa)} ${grp(masterc)}`])
      expect(kinds(t)).toContain('CARD');
    expect(kinds(`${visa} ${masterc}`).filter((r) => r === 'CARD')).toHaveLength(2);
    expect(transform(`1 ${grp(visa)}`, { action: 'REDACT', tokenKey: KEY }).text).toMatch(/^1 \[\[CARD:[0-9a-f]{12}\]\]$/);
  });
  test('more separators for cards and IBANs; lower-case IBAN; IBAN with dashes', () => {
    for (const sep of ['.', '/', '-', '_', '\n', '\t']) expect(kinds(`pay ${visa.match(/.{4}/g).join(sep)} now`)).toContain('CARD');
    const iban = ibanOf('DE', '370400440532013000');
    expect(kinds(iban.toLowerCase())).toContain('IBAN'); expect(kinds(iban.match(/.{1,4}/g).join('-'))).toContain('IBAN'); expect(kinds(iban.match(/.{1,4}/g).join('.'))).toContain('IBAN');
  });
  test('combining marks, format characters, blank braille cells, object replacement characters and look-alike letters do not hide a value', () => {
    const interleaved = (ch) => visa.split('').join(ch);
    for (const cp of [0x0300, 0x20d0, 0x2800, 0xfffc, 0x0600, 0x1d173]) expect(kinds(interleaved(String.fromCodePoint(cp)))).toContain('CARD');
    const cyr = (s) => s.replace(/a/g, String.fromCharCode(0x0430)).replace(/e/g, String.fromCharCode(0x0435)).replace(/o/g, String.fromCharCode(0x043e));
    expect(kinds(cyr('jane.roe@example.org'))).toContain('EMAIL');
    expect(kinds(('gh' + 'p_' + 'a'.repeat(36)).replace(/p/g, String.fromCharCode(0x0440)))).toContain('KEY_GITHUB');
    expect(kinds('r' + String.fromCharCode(0x0301) + 'esum' + String.fromCharCode(0x0301) + ' of the meeting')).toEqual([]);          // accents on ordinary words stay quiet
  });
  test('overlapping findings are replaced as a cluster: no tail of a dropped finding survives', () => {
    const t = '+4' + ' '.repeat(14) + grp(visa);
    const r = transform(t, { action: 'REDACT', tokenKey: KEY });
    expect(r.text).not.toMatch(/1111/); expect(r.text).toMatch(/^\[\[[A-Z_]+:[0-9a-f]{12}\]\]$/);
  });
  test('stable tokens: e-mail case does not matter, dots in the local part do; numbers are the same however grouped', () => {
    const tok = (t) => transform(t, { action: 'REDACT', tokenKey: KEY }).text;
    expect(tok('Jane.Roe@Example.org')).toBe(tok('jane.roe@example.org'));
    expect(tok('janeroe@example.org')).not.toBe(tok('jane.roe@example.org'));
    expect(tok(visa)).toBe(tok(grp(visa))); expect(tok(visa)).toBe(tok(visa.match(/.{4}/g).join('.')));
  });
  test('MASK shows at most a quarter of a number, hides short e-mail local parts, and never shows the length of a secret', () => {
    expect(transform('call +40 721 234 567', { action: 'MASK' }).text).toBe('call *********67');             // 11 digits: a quarter (2) shown at most
    expect(transform('a@example.org', { action: 'MASK' }).text).toBe('***@example.org');
    const k1 = transform('key ' + 'gh' + 'p_' + 'a'.repeat(36), { action: 'MASK' }).text; const k2 = transform('key ' + 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP', { action: 'MASK' }).text;
    expect(k1.length).toBe(k2.length);
    expect(transform(`card ${visa}`, { action: 'MASK' }).text).toBe(`card ${'*'.repeat(12)}${visa.slice(-4)}`);
  });
  test('resource bounds: NFKC expansion is capped and reported as truncated; a result that is mostly findings is refused, not slowed down', () => {
    const fdfa = String.fromCharCode(0xfdfa).repeat(200_000);
    const t0 = Date.now(); const r = scan(fdfa); expect(Date.now() - t0).toBeLessThan(3000); expect(r.truncated).toBe(true);
    expect(transform(fdfa, { action: 'BLOCK' }).blocked).toBe(true);
    const many = Array.from({ length: 25_000 }, (_, i) => `u${i}@e.io`).join(' ');
    const m = scan(many); expect(m.truncated).toBe(true); expect(m.findings.length).toBeLessThanOrEqual(20_000);
    expect(transform(many, { action: 'REDACT', tokenKey: KEY }).blocked).toBe(true);
  });
});

describe('DLP-09 decoy neighbours and doubled separators', () => {
  const visa = luhnComplete('4', 16);
  const grp4 = (s) => `${s.slice(0, 4)} ${s.slice(4, 8)} ${s.slice(8, 12)} ${s.slice(12)}`;
  test('a neighbour that forms a valid window with the first groups of a card does not hide the card (REDACT and MASK)', () => {
    let hits = 0;
    for (let i = 0; i < 400; i++) {
      const decoy = '4' + String(10_000_000 + i * 7919).slice(0, 8);
      const t = `Order ref ${decoy} ${grp4(visa)} thanks`;
      for (const action of ['REDACT', 'MASK']) {
        const out = transform(t, { action, tokenKey: KEY }).text;
        if (/1111 1111 1111|111 1111 1111 1111/.test(out)) hits++;
      }
    }
    expect(hits).toBe(0);
    const e = transform('Order ref 400000004 ' + grp4(visa) + ' thanks', { action: 'REDACT', tokenKey: KEY }).text;
    expect(e).toMatch(/^Order ref .*\[\[CARD:[0-9a-f]{12}\]\] thanks$/); expect(e).not.toContain(visa.slice(4, 12));
  });
  test('a decoy prefix does not hide an IBAN', () => {
    const iban = ibanOf('DE', '370400440532013000'); const spaced = iban.match(/.{1,4}/g).join(' ');
    const out = transform(`NO66 123 5678 ${spaced}`, { action: 'REDACT', tokenKey: KEY }).text;
    expect(out).not.toMatch(/3704|0532|0130/); expect(out).toMatch(/^\[\[IBAN:/);
  });
  test('up to two separators between groups: doubled spaces, a stripped invisible character between spaces, commas, CRLF', () => {
    const ZWSP = String.fromCharCode(0x200b);
    for (const sep of ['  ', `${' '}${ZWSP}${' '}`, ', ', '\r\n', '; ']) expect(rules(`pay ${visa.match(/.{4}/g).join(sep)} now`)).toContain('CARD');
    expect(rules(`pay ${visa.match(/.{4}/g).join('   ')} now`)).not.toContain('CARD');                      // three separators: not one number any more (documented limit)
  });
});
