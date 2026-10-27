'use strict';

/**
 * Automatic data classification and exfiltration signals. Pure functions over text and over the findings of enterprise/dlp/engine.js#scan.
 *
 *   classify(text, findings, { markings? })  -> { level, confidence, reasons: [{ signal, level, confidence }] }
 *   exfiltration(outputText, outputFindings, { inputFindingValues?, inputText?, allowHosts?, bulkThreshold? }) -> { signals: [{ signal, severity, confidence, detail }] }
 *
 * LEVELS are ordered PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED. A text is classified by two kinds of evidence, both reported with a confidence:
 *   - what is IN it: findings (credentials, cryptographic material, financial and national-id data are RESTRICTED; personal data is CONFIDENTIAL);
 *   - what it SAYS about itself: classification markings in several languages ("strictly confidential", "uz intern", "nur für den internen gebrauch", ...), plus
 *     tenant-supplied marking lists. A marking is evidence, not proof - confidence 0.8, and a text that merely discusses the word "confidential" in a sentence about
 * something else still matches; that is a known false-positive source reported in the corpus.
 * Independent signals combine as a noisy-OR (1 - prod(1 - p)), capped at 0.99; the level is the highest level any signal reaches with confidence >= 0.5.
 *
 * Exfiltration is judged on the ANSWER: sensitive data the user did not supply (the model recalled it or a tool returned it), links or images whose URL carries data to a host
 * that is not allow-listed (the markdown-image exfiltration trick), bulk dumps of personal records, and large encoded blobs.
 */

const LEVELS = Object.freeze(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED']);
const rank = (l) => LEVELS.indexOf(l);

const CATEGORY_LEVEL = Object.freeze({ CREDENTIAL: 'RESTRICTED', CRYPTO: 'RESTRICTED', FINANCIAL: 'RESTRICTED', NATIONAL_ID: 'RESTRICTED', PII: 'CONFIDENTIAL' });

// Markings by level. Lower-case; matched on the NFKC-lowered text with diacritics folded, as whole phrases.
const MARKINGS = Object.freeze({
  RESTRICTED: ['top secret', 'strictly confidential', 'strict confidential', 'secret', 'restricted', 'strict secret', 'strict confidential', 'streng vertraulich', 'geheim',
    'strictement confidentiel', 'secret defense', 'estrictamente confidencial', 'strettamente riservato', 'strict secret', 'strict confidential'],
  CONFIDENTIAL: ['confidential', 'vertraulich', 'confidentiel', 'confidencial', 'riservato', 'confidential', 'do not distribute', 'not for distribution', 'nu se difuzeaza', 'privileged and confidential'],
  INTERNAL: ['internal use only', 'for internal use', 'internal only', 'uz intern', 'nur fur den internen gebrauch', 'usage interne', 'uso interno', 'company internal', 'intern'],
});

const fold = (s) => s.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase();

function markingSignals(text, extra) {
  const hay = ` ${fold(text).replace(/[^a-z0-9]+/g, ' ')} `;
  const out = [];
  const lists = { ...MARKINGS };
  if (extra) for (const [lvl, words] of Object.entries(extra)) if (LEVELS.includes(lvl)) lists[lvl] = [...(lists[lvl] || []), ...words.map((w) => fold(String(w)).replace(/[^a-z0-9]+/g, ' ').trim()).filter(Boolean)];
  for (const lvl of ['RESTRICTED', 'CONFIDENTIAL', 'INTERNAL']) {
    for (const w of new Set(lists[lvl])) if (hay.includes(` ${w} `)) { out.push({ signal: `MARKING:${w}`, level: lvl, confidence: lvl === 'INTERNAL' ? 0.6 : 0.8 }); break; }
  }
  return out;
}

/**
 * @param {string} text
 * @param {any[]} [findings]
 * @param {{ markings?: any }} [opts]
 */
function classify(text, findings = [], { markings } = {}) {
  const reasons = [];
  const byRule = new Map();
  for (const f of findings) {
    const lvl = CATEGORY_LEVEL[f.category];
    if (!lvl) continue;
    const prev = byRule.get(f.rule);
    if (!prev || f.confidence > prev.confidence) byRule.set(f.rule, { signal: `FINDING:${f.rule}`, level: lvl, confidence: f.confidence });
  }
  reasons.push(...byRule.values(), ...markingSignals(text, markings));
  let level = 'PUBLIC';
  for (const r of reasons) if (r.confidence >= 0.5 && rank(r.level) > rank(level)) level = r.level;
  const atLevel = reasons.filter((r) => r.level === level && r.confidence >= 0.5);
  const confidence = level === 'PUBLIC' ? (reasons.length === 0 ? 0.9 : 0.6)
    : Math.min(0.99, 1 - atLevel.reduce((p, r) => p * (1 - r.confidence), 1));
  return { level, confidence: Math.round(confidence * 1000) / 1000, reasons };
}

// ── exfiltration ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const URL_RE = /(!?)\[[^\]\n]{0,200}\]\((https?:\/\/[^\s)]{1,2000})\)|<img[^>]{0,300}?src=["'](https?:\/\/[^"']{1,2000})["']|(https?:\/\/[^\s<>"')]{1,2000})/gi;
const norm = (v) => String(v).replace(/[\s.-]/g, '').toLowerCase();

function hostOf(u) { try { return new URL(u).hostname.toLowerCase().replace(/\.$/, ''); } catch { return null; } }
const hostAllowed = (h, allow) => allow.some((a) => { const x = a.toLowerCase(); return h === x || (x.startsWith('*.') && h.endsWith(x.slice(1))); });

function exfiltration(outputText, outputFindings = [], { inputFindingValues = [], inputText = '', allowHosts = [], bulkThreshold = 10 } = {}) {
  const signals = [];
  const known = new Set(inputFindingValues.map(norm));
  const inputNorm = norm(inputText);

  // 1. sensitive data in the answer that the user did not supply
  const fresh = outputFindings.filter((f) => CATEGORY_LEVEL[f.category] && f.value !== undefined && !known.has(norm(f.value)) && !(inputNorm && inputNorm.includes(norm(f.value))));
  const strong = fresh.filter((f) => CATEGORY_LEVEL[f.category] === 'RESTRICTED' || f.confidence >= 0.9);
  if (strong.length > 0) signals.push({ signal: 'NEW_SENSITIVE_IN_OUTPUT', severity: 'HIGH', confidence: Math.min(0.95, strong.reduce((m, f) => (f.confidence > m ? f.confidence : m), 0)), detail: { rules: [...new Set(strong.map((f) => f.rule))].sort(), count: strong.length } });

  // 2. links / images whose URL carries data to a host that is not allow-listed
  let m; URL_RE.lastIndex = 0; let urls = 0;
  while ((m = URL_RE.exec(outputText)) !== null && urls < 200) {
    urls++;
    const url = m[2] || m[3] || m[4]; const host = hostOf(url);
    if (!host || hostAllowed(host, allowHosts)) continue;
    let carries = false; let why = null;
    const q = url.indexOf('?') >= 0 ? url.slice(url.indexOf('?') + 1) : '';
    const tail = decodeURIComponentSafe(q + ' ' + url.slice(url.indexOf(host) + host.length).split('?')[0]);
    if (outputFindings.some((f) => f.value !== undefined && tail.replace(/[\s.-]/g, '').toLowerCase().includes(norm(f.value)))) { carries = true; why = 'sensitive value in the URL'; }
    else if (/[A-Za-z0-9+/_-]{40,}={0,2}|[0-9a-f]{32,}/.test(q)) { carries = true; why = 'long encoded parameter'; }
    if (carries) signals.push({ signal: 'URL_EXFIL', severity: m[1] === '!' || /^<img/i.test(m[0]) ? 'HIGH' : 'MEDIUM', confidence: why === 'sensitive value in the URL' ? 0.9 : 0.6, detail: { host, why, image: m[1] === '!' || /^<img/i.test(m[0]) } });
  }

  // 3. bulk records
  const pii = outputFindings.filter((f) => CATEGORY_LEVEL[f.category] && f.confidence >= 0.5);
  if (pii.length >= bulkThreshold) signals.push({ signal: 'BULK_RECORDS', severity: 'MEDIUM', confidence: 0.7, detail: { count: pii.length } });

  // 4. large encoded blobs
  const blob = /(?:[A-Za-z0-9+/]{256,}={0,2})|(?:[0-9a-fA-F]{512,})/.exec(outputText);
  if (blob) signals.push({ signal: 'ENCODED_BLOB', severity: 'MEDIUM', confidence: 0.5, detail: { length: blob[0].length } });
  return { signals };
}

function decodeURIComponentSafe(s) { try { return decodeURIComponent(s); } catch { return s; } }

module.exports = { LEVELS, rank, classify, exfiltration, CATEGORY_LEVEL };
