'use strict';

/**
 * DLP detectors. Pure functions over a string: no I/O, no globals, no pattern with nested unbounded quantifiers (adversarial inputs are timed in
 * enterprise/dlp/__tests__/dlp.test.js, DLP-07/08; the cost is bounded, not strictly linear).
 *
 * A detector is { id, category, confidence, find(text) -> [{ start, end, confidence? }] }.
 *   - `category` groups ids for policy ("PII", "FINANCIAL", "NATIONAL_ID", "CREDENTIAL", "CRYPTO").
 *   - `confidence` is the detector's base confidence in [0,1]: HIGH when a checksum/structure validates (Luhn, IBAN mod 97, CNP control digit, known key prefix),
 *     lower when only a shape matches (phone numbers, generic "secret = ..." assignments).
 * Offsets are into the string passed to find(): the engine scans a NORMALISED view and maps them back (enterprise/dlp/engine.js).
 */

const DIGIT = /[0-9]/;
const isDigit = (c) => c >= '0' && c <= '9';

// ── checksums ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
function luhn(digits) {
  let sum = 0; let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}

function mod97(s) {
  let rem = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c >= 65 && c <= 90 ? c - 55 : c - 48;
    rem = v > 9 ? (rem * 100 + v) % 97 : (rem * 10 + v) % 97;
  }
  return rem;
}

// IBAN lengths by country (ISO 13616 registry, the countries seen in practice; an unknown country is not accepted - a wrong guess is a false positive)
const IBAN_LEN = Object.freeze({
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28, CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24,
  FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LI: 21,
  LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SC: 31,
  SE: 24, SI: 19, SK: 24, SM: 27, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20,
});

// ── scanning helpers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/**
 * Digit groups chained by ONE separator character, e.g. "4111 1111 1111 1111". Every WINDOW of consecutive groups whose digits total minDigits..maxDigits is a candidate, longest
 * first at each start, so a number sitting next to another number ("1 4111 1111 1111 1111", "4111111111111111 5500000000000004", "2024-01-15 4111 ...") is still found: the
 * detector validates each window on its own (checksum) instead of giving up on the merged run. At most 19 groups are extended per start, so the cost stays linear.
 * Returns [{ start, end, digits }] (overlapping candidates; the caller keeps the valid ones and resolves overlaps).
 */
function digitRuns(text, minDigits, maxDigits, seps) {
  const groups = [];                                            // maximal digit groups of the text, with the separator (if a single one) that follows
  const n = text.length;
  for (let i = 0; i < n;) {
    if (!isDigit(text[i])) { i++; continue; }
    let j = i; while (j < n && isDigit(text[j])) j++;
    // up to TWO separator characters between groups (stripped invisible characters leave a doubled space, people write "4111, 1111" and CRLF)
    let k = 0; while (seps.length > 0 && k < 2 && j + k < n && (seps.includes(text[j + k]) || EXTRA_SEPS.includes(text[j + k]))) k++;
    groups.push({ start: i, end: j, sepLen: k > 0 && j + k < n && isDigit(text[j + k]) ? k : 0 });
    i = j;
  }
  const out = [];
  for (let g = 0; g < groups.length; g++) {
    let digits = ''; let end = g;
    for (let h = g; h < groups.length && digits.length <= maxDigits; h++) {
      if (h > g && !(groups[h - 1].sepLen > 0 && groups[h - 1].end + groups[h - 1].sepLen === groups[h].start)) break;     // not chained by one or two separators
      digits += text.slice(groups[h].start, groups[h].end); end = h;
      if (digits.length >= minDigits && digits.length <= maxDigits) out.push({ start: groups[g].start, end: groups[end].end, digits });
    }
  }
  return out.sort((x, y) => x.start - y.start || (y.end - y.start) - (x.end - x.start));
}

const EXTRA_SEPS = ',;:\r';
const CARD_SEPS = ' -./_\n\t\u2010\u2011\u2012\u2013';           // what people put between groups (NFKC already folds the no-break and thin spaces)
const wordBoundaryBefore = (text, i) => i === 0 || !/[A-Za-z0-9_]/.test(text[i - 1]);
const wordBoundaryAfter = (text, i) => i >= text.length || !/[A-Za-z0-9_]/.test(text[i]);

// ── detectors ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const EMAIL = {
  id: 'EMAIL', category: 'PII', confidence: 0.95,
  find(text) {
    const out = [];
    const re = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const tld = m[0].slice(m[0].lastIndexOf('.') + 1);
      if (tld.length < 2 || /[0-9]/.test(tld)) continue;
      out.push({ start: m.index, end: m.index + m[0].length });
    }
    return out;
  },
};

const PHONE = {
  id: 'PHONE', category: 'PII', confidence: 0.6,
  find(text) {
    const out = [];
    // international ("+" then 8..15 digits) or national with separators/parentheses (9..15 digits). A bare run of digits is NOT a phone number (too many false positives).
    const re = /\+?[0-9][0-9 ().-]{6,22}[0-9]/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const raw = m[0]; const digits = raw.replace(/[^0-9]/g, '');
      if (digits.length < 8 || digits.length > 15) continue;
      const plus = raw[0] === '+';
      const sep = /[ ().-]/.test(raw);
      if (!plus && !sep) continue;
      if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(raw)) continue;                 // an ISO date
      if (!wordBoundaryBefore(text, m.index) && !plus) continue;
      out.push({ start: m.index, end: m.index + raw.length, confidence: plus ? 0.8 : 0.55 });
    }
    return out;
  },
};

const CARD = {
  id: 'CARD', category: 'FINANCIAL', confidence: 0.97,
  find(text) {
    const out = [];
    for (const r of digitRuns(text, 13, 19, CARD_SEPS)) {                  // every valid window is kept: the engine replaces overlapping ones as a cluster, so a decoy
      const d = r.digits;                                                  // neighbour that forms a valid window can never hide the real card (at the price of also redacting the neighbour)
      if (!luhn(d)) continue;
      const issuer = /^4/.test(d) ? (d.length === 13 || d.length === 16 || d.length === 19)
        : /^(5[1-5]|2(2[2-9][1-9]|2[3-9]|[3-6]|7[01]|720))/.test(d) ? d.length === 16
          : /^3[47]/.test(d) ? d.length === 15
            : /^(6011|65|64[4-9])/.test(d) ? (d.length >= 16 && d.length <= 19)
              : /^35(2[89]|[3-8])/.test(d) ? (d.length >= 16 && d.length <= 19)
                : /^3(0[0-5]|[68])/.test(d) ? (d.length >= 14 && d.length <= 16)
                  : /^62/.test(d) ? (d.length >= 16 && d.length <= 19) : false;
      if (issuer) out.push({ start: r.start, end: r.end });
    }
    return out;
  },
};

const IBAN = {
  id: 'IBAN', category: 'FINANCIAL', confidence: 0.97,
  find(text) {
    const out = [];
    const re = /[A-Za-z]{2}[0-9]{2}(?:[ \-.]?[A-Za-z0-9]{1,4}){2,8}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!wordBoundaryBefore(text, m.index)) continue;
      // trailing groups may over-extend into the next word: try the longest, then shorter prefixes ending on a group boundary
      let cand = m[0];
      for (;;) {
        const compact = cand.replace(/[ \-.]/g, '').toUpperCase();
        const want = IBAN_LEN[compact.slice(0, 2)];
        if (want && compact.length === want && mod97(compact.slice(4) + compact.slice(0, 4)) === 1 && wordBoundaryAfter(text, m.index + cand.length)) {
          out.push({ start: m.index, end: m.index + cand.length }); re.lastIndex = m.index + 2; break;      // keep scanning inside: a decoy prefix must not hide a real IBAN
        }
        const cut = Math.max(cand.lastIndexOf(' '), cand.lastIndexOf('-'), cand.lastIndexOf('.'));
        if (cut < 0) { re.lastIndex = m.index + 2; break; }
        cand = cand.slice(0, cut);
      }
    }
    return out;
  },
};

// Romanian personal numeric code: S AA LL ZZ JJ NNN C
const CNP_W = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];
function cnpValid(d) {
  if (!/^[1-9][0-9]{12}$/.test(d)) return false;
  const s = Number(d[0]);
  const yy = Number(d.slice(1, 3)); const mm = Number(d.slice(3, 5)); const dd = Number(d.slice(5, 7)); const jj = Number(d.slice(7, 9));
  if (mm < 1 || mm > 12 || dd < 1 || dd > 31) return false;
  const century = s === 1 || s === 2 ? 1900 : s === 3 || s === 4 ? 1800 : s === 5 || s === 6 ? 2000 : 0;
  if (century) { const dt = new Date(Date.UTC(century + yy, mm - 1, dd)); if (dt.getUTCMonth() !== mm - 1 || dt.getUTCDate() !== dd) return false; }
  if (!((jj >= 1 && jj <= 46) || jj === 51 || jj === 52 || jj === 99)) return false;
  let sum = 0; for (let i = 0; i < 12; i++) sum += (d.charCodeAt(i) - 48) * CNP_W[i];
  const c = sum % 11 === 10 ? 1 : sum % 11;
  return c === d.charCodeAt(12) - 48;
}

const pesel = (d) => /^[0-9]{11}$/.test(d) && (() => { const w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]; let s = 0; for (let i = 0; i < 10; i++) s += w[i] * (d.charCodeAt(i) - 48); return (10 - (s % 10)) % 10 === d.charCodeAt(10) - 48; })()
  && (() => { const m = Number(d.slice(2, 4)) % 20; return m >= 1 && m <= 12; })();
const bsn = (d) => /^[0-9]{9}$/.test(d) && d !== '000000000' && (() => { let s = 0; for (let i = 0; i < 8; i++) s += (9 - i) * (d.charCodeAt(i) - 48); s -= (d.charCodeAt(8) - 48); return s % 11 === 0; })();
const steuerId = (d) => /^[1-9][0-9]{10}$/.test(d) && (() => { let p = 10; for (let i = 0; i < 10; i++) { let s = (d.charCodeAt(i) - 48 + p) % 10; if (s === 0) s = 10; p = (s * 2) % 11; } const c = 11 - p; return (c === 10 ? 0 : c) === d.charCodeAt(10) - 48; })();

function fixedDigits(id, len, validate, confidence) {
  return {
    id, category: 'NATIONAL_ID', confidence,
    find(text) {
      const out = [];
      for (const r of digitRuns(text, len, len, '')) if (r.end - r.start === len && wordBoundaryBefore(text, r.start) && wordBoundaryAfter(text, r.end) && validate(r.digits)) out.push({ start: r.start, end: r.end });
      return out;
    },
  };
}
const CNP = fixedDigits('CNP', 13, cnpValid, 0.9);
const PESEL = fixedDigits('PESEL', 11, pesel, 0.75);       // 11 digits collide with other things: lower confidence
const BSN = fixedDigits('BSN', 9, bsn, 0.5);              // 9 digits: weak on its own
const STEUER_ID = fixedDigits('DE_TAX_ID', 11, steuerId, 0.6);

const US_SSN = {
  id: 'US_SSN', category: 'NATIONAL_ID', confidence: 0.8,
  find(text) {
    const out = [];
    const re = /[0-9]{3}[- ][0-9]{2}[- ][0-9]{4}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!wordBoundaryBefore(text, m.index) || !wordBoundaryAfter(text, m.index + 11)) continue;
      const a = Number(m[0].slice(0, 3)); const g = Number(m[0].slice(4, 6)); const s = Number(m[0].slice(7));
      if (a === 0 || a === 666 || a >= 900 || g === 0 || s === 0) continue;
      out.push({ start: m.index, end: m.index + 11 });
    }
    return out;
  },
};

const ES_DNI = {
  id: 'ES_DNI_NIE', category: 'NATIONAL_ID', confidence: 0.8,
  find(text) {
    const out = [];
    const re = /[XYZ]?[0-9]{7,8}[- ]?[A-Z]/g;
    const L = 'TRWAGMYFPDXBNJZSQVHLCKE';
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!wordBoundaryBefore(text, m.index) || !wordBoundaryAfter(text, m.index + m[0].length)) continue;
      let body = m[0].replace(/[- ]/g, ''); const letter = body[body.length - 1]; body = body.slice(0, -1);
      if (/^[XYZ]/.test(body)) { if (body.length !== 8) continue; body = String('XYZ'.indexOf(body[0])) + body.slice(1); } else if (body.length !== 8) continue;
      if (L[Number(body) % 23] === letter) out.push({ start: m.index, end: m.index + m[0].length });
    }
    return out;
  },
};

const UK_NINO = {
  id: 'UK_NINO', category: 'NATIONAL_ID', confidence: 0.7,
  find(text) {
    const out = [];
    const re = /[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?[0-9]{2} ?[0-9]{2} ?[0-9]{2} ?[A-D]/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (!wordBoundaryBefore(text, m.index) || !wordBoundaryAfter(text, m.index + m[0].length)) continue;
      if (/^(BG|GB|NK|KN|TN|NT|ZZ)/.test(m[0])) continue;
      out.push({ start: m.index, end: m.index + m[0].length });
    }
    return out;
  },
};

// ── credentials ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
function prefixed(id, source, confidence = 0.95) {
  const re = new RegExp(source, 'g');
  return {
    id, category: 'CREDENTIAL', confidence,
    find(text) {
      const out = []; let m; re.lastIndex = 0;
      while ((m = re.exec(text)) !== null) { if (wordBoundaryBefore(text, m.index)) out.push({ start: m.index, end: m.index + m[0].length }); }
      return out;
    },
  };
}
// The token shapes of widely used services. A known PREFIX with the documented length/alphabet is what makes these high-confidence.
const API_KEYS = [
  prefixed('KEY_AWS_ACCESS', '(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}'),
  prefixed('KEY_GITHUB', '(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})'),
  prefixed('KEY_STRIPE', '(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,99}'),
  prefixed('KEY_SLACK', 'xox[abprs]-[A-Za-z0-9-]{10,200}'),
  prefixed('KEY_GOOGLE_API', 'AIza[0-9A-Za-z_-]{35}'),
  prefixed('KEY_ANTHROPIC', 'sk-ant-[A-Za-z0-9_-]{20,200}'),
  prefixed('KEY_OPENAI', 'sk-(?:proj-)?[A-Za-z0-9_-]{32,200}', 0.85),
  prefixed('KEY_NPM', 'npm_[A-Za-z0-9]{36}'),
  prefixed('KEY_SENDGRID', 'SG\\.[A-Za-z0-9_-]{16,32}\\.[A-Za-z0-9_-]{16,64}'),
  prefixed('KEY_QODIQA', '(?:sk|ok)_[0-9a-f]{64}'),
];

const PEM = {
  id: 'PEM_BLOCK', category: 'CRYPTO', confidence: 0.99,
  find(text) {
    const out = [];
    const head = /-----BEGIN [A-Z0-9 ]{3,40}-----/g;
    let m;
    while ((m = head.exec(text)) !== null) {
      const label = m[0].slice(11, -5);
      // private material is the point; a public certificate is not secret, but a block is withheld whole either way when it is a KEY or unlabelled secret
      if (!/(PRIVATE KEY|ENCRYPTED|SECRET|OPENSSH|PGP PRIVATE)/.test(label)) continue;
      const endTag = `-----END ${label}-----`;
      const e = text.indexOf(endTag, head.lastIndex);
      const end = e >= 0 ? e + endTag.length : Math.min(text.length, m.index + 8192);   // unterminated: withhold up to a bounded length
      out.push({ start: m.index, end });
      head.lastIndex = end;
    }
    return out;
  },
};

const JWT = {
  id: 'JWT', category: 'CREDENTIAL', confidence: 0.9,
  find(text) {
    const out = [];
    const re = /eyJ[A-Za-z0-9_-]{4,2000}\.eyJ[A-Za-z0-9_-]{4,4000}\.[A-Za-z0-9_-]{0,2000}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      try {
        const head = JSON.parse(Buffer.from(m[0].split('.')[0], 'base64url').toString('utf8'));
        if (head && typeof head === 'object') out.push({ start: m.index, end: m.index + m[0].length });
      } catch { /* not a JWT */ }
    }
    return out;
  },
};

const CODE_SECRET = {
  id: 'CODE_SECRET', category: 'CREDENTIAL', confidence: 0.6,
  find(text) {
    const out = [];
    const re = /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key)["']?[ \t]{0,8}[:=][ \t]{0,8}["']([^"'\s]{8,200})["']/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
      const val = m[1];
      if (/^(?:x+|\*+|\.+|<.*>|\$\{.*\}|%\(.*\)s|changeme|example|placeholder|your[_-].*)$/i.test(val)) continue;
      const valStart = m.index + m[0].lastIndexOf(val);
      out.push({ start: valStart, end: valStart + val.length, confidence: entropyBits(val) >= 3 ? 0.75 : 0.5 });
    }
    return out;
  },
};

function entropyBits(s) {
  const f = new Map(); for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let h = 0; for (const n of f.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

const DETECTORS = Object.freeze([EMAIL, PHONE, CARD, IBAN, CNP, PESEL, BSN, STEUER_ID, US_SSN, ES_DNI, UK_NINO, ...API_KEYS, PEM, JWT, CODE_SECRET]);

module.exports = { DETECTORS, luhn, mod97, cnpValid, entropyBits, IBAN_LEN, DIGIT };
