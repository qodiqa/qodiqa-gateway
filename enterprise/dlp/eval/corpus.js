'use strict';

/**
 * Synthetic multilingual corpus for the DLP detectors. NO real data: every value is generated from a seeded PRNG with valid checksums where the detector checks them, and
 * every key-shaped value is assembled at run time from parts, so no secret-shaped literal exists in the repository and the corpus is regenerated, not stored.
 *
 *   generate({ seed, perLanguage }) -> { docs: [{ id, lang, slice, text, labels: [{ rule, start, end }] }], uncovered: [...] }
 *
 * Slices: "clean" (entity in running text), "separators" (grouping / spacing as people write them, including dots, slashes, dashes in IBANs, lower-case IBANs), "adjacent" (a card or IBAN next
 * to other numbers), "evasion" (zero-width characters, fullwidth digits, combining marks, blank braille cells, Cyrillic look-alike letters), "negative" (no entity, with
 * hard negatives: look-alike numbers that fail their checksum, dates, versions, order ids), "mixed" (several entities in one text). `uncovered` lists national-id shapes of countries
 * no detector covers (reported as known gaps, never counted as a pass).
 */

const { luhn, mod97, IBAN_LEN } = require('../detectors');

function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

const LANGS = ['en', 'ro', 'de', 'fr', 'es', 'it', 'pl', 'nl'];
const NAMES = { en: ['james.smith', 'mary.jones', 'oliver.brown'], ro: ['ion.popescu', 'maria.ionescu', 'andrei.radu'], de: ['hans.mueller', 'anna.schmidt', 'lukas.weber'], fr: ['jean.dupont', 'marie.martin', 'louis.bernard'],
  es: ['carlos.garcia', 'lucia.fernandez', 'pablo.lopez'], it: ['marco.rossi', 'giulia.bianchi', 'luca.ferrari'], pl: ['jan.kowalski', 'anna.nowak', 'piotr.wisniewski'], nl: ['jan.devries', 'sanne.bakker', 'pieter.jansen'] };
const DOMAINS = ['example.com', 'example.org', 'example.net', 'mail.example.co.uk', 'firma.example.ro', 'beispiel.example.de'];
const CCTLD = { en: '+44', ro: '+40', de: '+49', fr: '+33', es: '+34', it: '+39', pl: '+48', nl: '+31' };

// filler and templates per language: {0}.. are entity slots; filler sentences carry no entity
const T = {
  en: { one: ['Please contact me at {0} about the invoice.', 'My details: {0}. Thanks for your help.', 'The customer wrote: "{0}" and asked for a reply.', 'Forward this to {0} before Friday.'],
    filler: ['The meeting moved to Thursday afternoon.', 'Quarterly results were better than expected.', 'Please review the attached draft.', 'The release is planned for next week.'] },
  ro: { one: ['Vă rog să mă contactați la {0} pentru factură.', 'Datele mele: {0}. Mulțumesc pentru ajutor.', 'Clientul a scris: „{0}” și a cerut un răspuns.', 'Trimiteți aceasta la {0} până vineri.'],
    filler: ['Ședința a fost mutată joi după-amiază.', 'Rezultatele trimestriale au fost mai bune decât se aștepta.', 'Vă rog să verificați proiectul atașat.', 'Lansarea este planificată pentru săptămâna viitoare.'] },
  de: { one: ['Bitte kontaktieren Sie mich unter {0} wegen der Rechnung.', 'Meine Angaben: {0}. Danke für Ihre Hilfe.', 'Der Kunde schrieb: „{0}“ und bat um Antwort.', 'Leiten Sie das vor Freitag an {0} weiter.'],
    filler: ['Das Treffen wurde auf Donnerstagnachmittag verschoben.', 'Die Quartalszahlen waren besser als erwartet.', 'Bitte prüfen Sie den beigefügten Entwurf.', 'Die Veröffentlichung ist für nächste Woche geplant.'] },
  fr: { one: ['Veuillez me contacter à {0} au sujet de la facture.', 'Mes coordonnées : {0}. Merci pour votre aide.', 'Le client a écrit : « {0} » et demande une réponse.', 'Transmettez ceci à {0} avant vendredi.'],
    filler: ['La réunion a été déplacée à jeudi après-midi.', 'Les résultats trimestriels étaient meilleurs que prévu.', 'Merci de relire le projet joint.', 'La publication est prévue pour la semaine prochaine.'] },
  es: { one: ['Por favor contácteme en {0} sobre la factura.', 'Mis datos: {0}. Gracias por su ayuda.', 'El cliente escribió: «{0}» y pidió respuesta.', 'Reenvíe esto a {0} antes del viernes.'],
    filler: ['La reunión se movió al jueves por la tarde.', 'Los resultados trimestrales fueron mejores de lo esperado.', 'Revise el borrador adjunto, por favor.', 'El lanzamiento está previsto para la próxima semana.'] },
  it: { one: ['Vi prego di contattarmi a {0} per la fattura.', 'I miei dati: {0}. Grazie per l’aiuto.', 'Il cliente ha scritto: «{0}» e chiede una risposta.', 'Inoltrate questo a {0} entro venerdì.'],
    filler: ['La riunione è stata spostata a giovedì pomeriggio.', 'I risultati trimestrali sono stati migliori del previsto.', 'Si prega di rivedere la bozza allegata.', 'Il rilascio è previsto per la prossima settimana.'] },
  pl: { one: ['Proszę o kontakt pod {0} w sprawie faktury.', 'Moje dane: {0}. Dziękuję za pomoc.', 'Klient napisał: „{0}” i poprosił o odpowiedź.', 'Przekaż to na {0} przed piątkiem.'],
    filler: ['Spotkanie przeniesiono na czwartek po południu.', 'Wyniki kwartalne były lepsze od oczekiwań.', 'Proszę przejrzeć załączony projekt.', 'Wydanie zaplanowano na przyszły tydzień.'] },
  nl: { one: ['Neem contact met mij op via {0} over de factuur.', 'Mijn gegevens: {0}. Bedankt voor de hulp.', 'De klant schreef: „{0}” en vroeg om antwoord.', 'Stuur dit voor vrijdag door naar {0}.'],
    filler: ['De vergadering is verplaatst naar donderdagmiddag.', 'De kwartaalcijfers waren beter dan verwacht.', 'Bekijk het bijgevoegde concept.', 'De release is gepland voor volgende week.'] },
};

// ── value generators (valid by construction) ─────────────────────────────────────────────────────────────────────────────────────────────────
const pick = (r, a) => a[Math.floor(r() * a.length)];
const digits = (r, n) => { let s = ''; for (let i = 0; i < n; i++) s += Math.floor(r() * 10); return s; };
const alnum = (r, n, set = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') => { let s = ''; for (let i = 0; i < n; i++) s += set[Math.floor(r() * set.length)]; return s; };
const pad = (n, w) => String(n).padStart(w, '0');

function email(r, lang) { return `${pick(r, NAMES[lang])}${Math.floor(r() * 90) + 10}@${pick(r, DOMAINS)}`; }
function phone(r, lang, style) {
  const a = digits(r, 3); const b = digits(r, 3); const c = digits(r, 3);
  return style === 'dash' ? `(0${a}) ${b}-${c}${digits(r, 1)}` : `${CCTLD[lang]} ${a} ${b} ${c}`;
}
function card(r) {
  const prefix = pick(r, ['4', '51', '52', '53', '55', '37', '6011']);
  const len = prefix === '37' ? 15 : 16; let body = prefix; while (body.length < len - 1) body += Math.floor(r() * 10);
  for (let c = 0; c < 10; c++) if (luhn(body + c)) return body + c;
  throw new Error('no luhn');
}
function iban(r, cc) {
  const len = IBAN_LEN[cc]; const bban = []; for (let i = 0; i < len - 4; i++) bban.push(cc === 'GB' && i < 4 ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(r() * 26)] : String(Math.floor(r() * 10)));
  const b = bban.join(''); const check = 98 - mod97(b + cc + '00');
  return `${cc}${pad(check, 2)}${b}`;
}
const groups = (s, n, sep) => s.replace(new RegExp(`(.{${n}})`, 'g'), `$1${sep}`).trim();

function cnp(r) {
  const s = pick(r, [1, 2, 5, 6]); const yy = pad(Math.floor(r() * 99), 2); const mm = pad(1 + Math.floor(r() * 12), 2); const dd = pad(1 + Math.floor(r() * 28), 2); const jj = pad(1 + Math.floor(r() * 46), 2); const nnn = pad(1 + Math.floor(r() * 998), 3);
  const d = `${s}${yy}${mm}${dd}${jj}${nnn}`; const w = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9]; let sum = 0; for (let i = 0; i < 12; i++) sum += Number(d[i]) * w[i];
  return d + (sum % 11 === 10 ? 1 : sum % 11);
}
function pesel(r) {
  const yy = pad(Math.floor(r() * 99), 2); const mm = pad(1 + Math.floor(r() * 12) + pick(r, [0, 20]), 2); const dd = pad(1 + Math.floor(r() * 28), 2); const ser = digits(r, 4);
  const d = `${yy}${mm}${dd}${ser}`; const w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]; let s = 0; for (let i = 0; i < 10; i++) s += w[i] * Number(d[i]);
  return d + ((10 - (s % 10)) % 10);
}
function bsn(r) { for (;;) { const b = digits(r, 8); for (let c = 0; c < 10; c++) { const d = b + c; let s = 0; for (let i = 0; i < 8; i++) s += (9 - i) * Number(d[i]); s -= Number(d[8]); if (s % 11 === 0 && d !== '000000000') return d; } } }
function steuerId(r) { for (;;) { const b = `${1 + Math.floor(r() * 9)}${digits(r, 9)}`; for (let c = 0; c < 10; c++) { const d = b + c; let p = 10; for (let i = 0; i < 10; i++) { let s = (Number(d[i]) + p) % 10; if (s === 0) s = 10; p = (s * 2) % 11; } const k = 11 - p; if ((k === 10 ? 0 : k) === c) return d; } } }
function dni(r) { const n = pad(Math.floor(r() * 99999999), 8); return n + 'TRWAGMYFPDXBNJZSQVHLCKE'[Number(n) % 23]; }
function ssn(r) { const a = pick(r, [123, 234, 345, 456, 567, 678, 789, 101, 202]); return `${a}-${pad(10 + Math.floor(r() * 89), 2)}-${pad(1 + Math.floor(r() * 9998), 4)}`; }
function nino(r) { return `${pick(r, [...'ACEHJLMPRSTW'])}${pick(r, [...'ACEGHJKLMNPRSTWXYZ'])} ${digits(r, 2)} ${digits(r, 2)} ${digits(r, 2)} ${pick(r, [...'ABCD'])}`.replace(/^(BG|GB|NK|KN|TN|NT|ZZ)/, 'AB'); }

// secret-shaped values: ASSEMBLED here, never written in full anywhere
function keyValue(r, kind) {
  switch (kind) {
    case 'KEY_AWS_ACCESS': return 'AK' + 'IA' + alnum(r, 16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
    case 'KEY_GITHUB': return 'gh' + 'p_' + alnum(r, 36);
    case 'KEY_STRIPE': return 'sk_' + 'live_' + alnum(r, 24);
    case 'KEY_SLACK': return 'xo' + 'xb-' + digits(r, 10) + '-' + alnum(r, 12, 'abcdefghijklmnopqrstuvwxyz');
    case 'KEY_GOOGLE_API': return 'AI' + 'za' + alnum(r, 35, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-');
    case 'KEY_ANTHROPIC': return 'sk-' + 'ant-' + alnum(r, 40, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-');
    case 'KEY_QODIQA': return 'sk' + '_' + alnum(r, 64, '0123456789abcdef');
    default: throw new Error(kind);
  }
}
function jwt(r) { const b = (o) => Buffer.from(JSON.stringify(o)).toString('base64url'); return `${b({ alg: 'HS256', typ: 'JWT' })}.${b({ sub: digits(r, 6), iat: 1700000000 })}.${alnum(r, 43, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')}`; }
function pem(r) { return ['-----BEGIN ' + 'PRIVATE ' + 'KEY-----', alnum(r, 64, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), alnum(r, 64, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), '-----END ' + 'PRIVATE ' + 'KEY-----'].join('\n'); }
function codeSecret(r) { return `password = "${alnum(r, 14)}"`; }

const ZW = String.fromCharCode(0x200b);
const toFullwidth = (s) => s.replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + Number(d)));
const interleave = (s) => s.split('').join(ZW);
const COMBINING = String.fromCharCode(0x0300); const BRAILLE_BLANK = String.fromCharCode(0x2800);
// a number placed before a card so that "neighbour + first groups of the card" is itself a Luhn-valid window (the decoy that made the first repair leak 12 digits)
function decoyBefore(r, cardText) {
  const first = cardText.replace(/\D/g, '').slice(0, 4);
  for (let t = 0; t < 5000; t++) {
    const d = '4' + digits(r, 8);
    const w = d + first;                                                       // 13 digits: a Visa-length window made of the decoy and the card's first group
    if (luhn(w)) return d;
  }
  return digits(r, 9);
}
const CYR_A = String.fromCharCode(0x0430); const CYR_E = String.fromCharCode(0x0435); const CYR_O = String.fromCharCode(0x043e); const CYR_P = String.fromCharCode(0x0440);

// ── negatives: shapes that look like entities and are not ────────────────────────────────────────────────────────────────────────────────
function hardNegative(r) {
  const k = Math.floor(r() * 12);
  switch (k) {
    case 0: { const c = card(r); const L = c.length - 1; return c.slice(0, L) + ((Number(c[L]) + 1 + Math.floor(r() * 8)) % 10); }    // fails Luhn (the last digit is changed)
    case 1: return `ORD-${digits(r, 4)}-${digits(r, 6)}`;
    case 2: return `2026-${pad(1 + Math.floor(r() * 12), 2)}-${pad(1 + Math.floor(r() * 28), 2)}`;
    case 3: return `v${Math.floor(r() * 9)}.${Math.floor(r() * 30)}.${Math.floor(r() * 99)}`;
    case 4: return digits(r, 13).replace(/^(.)/, '9');                                                          // 13 digits, leading 9, almost never a CNP
    case 5: return `${Math.floor(r() * 9000) + 100}.${pad(Math.floor(r() * 99), 2)} EUR`;
    case 6: return `ID${digits(r, 10)}`;
    case 7: { const i = iban(r, 'DE'); return i.slice(0, -1) + ((Number(i[i.length - 1]) + 1) % 10); }          // wrong check digits
    case 8: return `https://docs.example.com/guide?page=${Math.floor(r() * 9)}`;
    case 9: return `${digits(r, 3)}-${digits(r, 2)}-${digits(r, 4)}`.replace(/^./, '9');                          // SSN-shaped but area 9xx is never issued
    case 10: return 'the password policy requires twelve characters';
    default: return `${Math.floor(r() * 99999)}`;
  }
}

function generate({ seed = 20261022, perLanguage = 40 } = {}) {
  const r = rng(seed); const docs = []; const uncovered = []; let n = 0;
  const add = (lang, slice, build) => {
    const parts = []; const labels = []; let text = '';
    const emit = (s, rule) => { if (rule) labels.push({ rule, start: text.length, end: text.length + s.length }); text += s; };
    build(emit, parts);
    docs.push({ id: `d${++n}`, lang, slice, text, labels });
  };
  const tpl = (lang) => T[lang];
  const wrap = (lang, emit, value, rule) => { const t = pick(r, tpl(lang).one); const [pre, post] = t.split('{0}'); emit(pre); emit(value, rule); emit(post); };

  for (const lang of LANGS) {
    const nat = lang === 'ro' ? ['CNP', cnp] : lang === 'pl' ? ['PESEL', pesel] : lang === 'nl' ? ['BSN', bsn] : lang === 'de' ? ['DE_TAX_ID', steuerId] : lang === 'es' ? ['ES_DNI_NIE', dni] : lang === 'en' ? ['US_SSN', ssn] : null;
    const ibanCc = { en: 'GB', ro: 'RO', de: 'DE', fr: 'FR', es: 'ES', it: 'IT', pl: 'PL', nl: 'NL' }[lang];
    for (let i = 0; i < perLanguage; i++) {
      add(lang, 'clean', (emit) => wrap(lang, emit, email(r, lang), 'EMAIL'));
      add(lang, 'clean', (emit) => wrap(lang, emit, phone(r, lang, i % 2 ? 'dash' : 'intl'), 'PHONE'));
      add(lang, 'clean', (emit) => wrap(lang, emit, card(r), 'CARD'));
      add(lang, 'clean', (emit) => wrap(lang, emit, iban(r, ibanCc), 'IBAN'));
      if (nat) add(lang, 'clean', (emit) => wrap(lang, emit, nat[1](r), nat[0]));
      if (lang === 'en') add(lang, 'clean', (emit) => wrap(lang, emit, nino(r), 'UK_NINO'));
      add(lang, 'separators', (emit) => wrap(lang, emit, groups(card(r), 4, ' '), 'CARD'));
      add(lang, 'separators', (emit) => wrap(lang, emit, groups(iban(r, ibanCc), 4, ' '), 'IBAN'));
      add(lang, 'evasion', (emit) => wrap(lang, emit, interleave(card(r)), 'CARD'));
      add(lang, 'evasion', (emit) => wrap(lang, emit, toFullwidth(card(r)), 'CARD'));
      add(lang, 'evasion', (emit) => wrap(lang, emit, interleave(email(r, lang)), 'EMAIL'));
      add(lang, 'evasion', (emit) => wrap(lang, emit, card(r).split('').join(COMBINING), 'CARD'));
      add(lang, 'evasion', (emit) => wrap(lang, emit, card(r).split('').join(BRAILLE_BLANK), 'CARD'));
      add(lang, 'evasion', (emit) => wrap(lang, emit, email(r, lang).replace(/a/g, CYR_A).replace(/e/g, CYR_E).replace(/o/g, CYR_O), 'EMAIL'));
      add(lang, 'evasion', (emit) => wrap(lang, emit, keyValue(r, 'KEY_GITHUB').replace(/p/g, CYR_P), 'KEY_GITHUB'));
      add(lang, 'separators', (emit) => wrap(lang, emit, groups(card(r), 4, pick(r, ['.', '/', '-', ' '])), 'CARD'));
      add(lang, 'separators', (emit) => wrap(lang, emit, groups(iban(r, ibanCc), 4, pick(r, ['-', '.'])), 'IBAN'));
      add(lang, 'separators', (emit) => wrap(lang, emit, groups(iban(r, ibanCc), 4, ' ').toLowerCase(), 'IBAN'));
      add(lang, 'adjacent', (emit) => { emit(pick(r, tpl(lang).filler) + ' ' + digits(r, 1 + Math.floor(r() * 8)) + ' '); emit(groups(card(r), 4, ' '), 'CARD'); emit(' ' + pick(r, ['', digits(r, 8)]) + ' ' + pick(r, tpl(lang).filler)); });
      add(lang, 'adjacent', (emit) => { const c = groups(card(r), 4, ' '); emit(pick(r, tpl(lang).filler) + ' ' + decoyBefore(r, c) + ' '); emit(c, 'CARD'); emit(' ' + pick(r, tpl(lang).filler)); });
      add(lang, 'adjacent', (emit) => { const c = groups(iban(r, ibanCc), 4, ' '); emit('NO66 123 5678 '); emit(c, 'IBAN'); });
      add(lang, 'separators', (emit) => wrap(lang, emit, card(r).match(/.{1,4}/g).join(pick(r, [', ', '  ', '\r\n', '; '])), 'CARD'));
      add(lang, 'separators', (emit) => wrap(lang, emit, groups(card(r), 4, ' ').split(' ').join(' ' + ZW + ' '), 'CARD'));
      add(lang, 'adjacent', (emit) => { emit('2026-' + pad(1 + Math.floor(r() * 12), 2) + '-' + pad(1 + Math.floor(r() * 28), 2) + ' '); emit(card(r), 'CARD'); emit(' '); emit(card(r), 'CARD'); });
      add(lang, 'adjacent', (emit) => { emit('order ' + digits(r, 8) + ' '); emit(iban(r, ibanCc), 'IBAN'); emit(' ' + digits(r, 6)); });
      const kk = pick(r, ['KEY_AWS_ACCESS', 'KEY_GITHUB', 'KEY_STRIPE', 'KEY_SLACK', 'KEY_GOOGLE_API', 'KEY_ANTHROPIC', 'KEY_QODIQA']);
      add(lang, 'clean', (emit) => wrap(lang, emit, keyValue(r, kk), kk));
      if (i % 4 === 0) add(lang, 'clean', (emit) => wrap(lang, emit, jwt(r), 'JWT'));
      if (i % 4 === 1) add(lang, 'clean', (emit) => { emit(pick(r, tpl(lang).filler) + '\n'); emit(pem(r), 'PEM_BLOCK'); emit('\n' + pick(r, tpl(lang).filler)); });
      if (i % 4 === 2) add(lang, 'clean', (emit) => { const v = codeSecret(r); const q = v.indexOf('"') + 1; emit(pick(r, tpl(lang).filler) + ' config: ' + v.slice(0, q)); emit(v.slice(q, -1), 'CODE_SECRET'); emit('"'); });
      add(lang, 'mixed', (emit) => { emit(pick(r, tpl(lang).filler) + ' '); emit(email(r, lang), 'EMAIL'); emit(' / '); emit(card(r), 'CARD'); emit(' / '); emit(iban(r, ibanCc), 'IBAN'); emit('. ' + pick(r, tpl(lang).filler)); });
      for (let k = 0; k < 3; k++) add(lang, 'negative', (emit) => { emit(pick(r, tpl(lang).filler) + ' '); emit(hardNegative(r)); emit(' ' + pick(r, tpl(lang).filler)); });
      add(lang, 'negative', (emit) => emit(pick(r, tpl(lang).filler) + ' ' + pick(r, tpl(lang).filler)));
      if (lang === 'fr') uncovered.push({ lang, kind: 'FR_NIR', sample: `${pick(r, [1, 2])}${digits(r, 12)}` });
      if (lang === 'it') uncovered.push({ lang, kind: 'IT_CODICE_FISCALE', sample: `${alnum(r, 6, 'ABCDEFGHILMNPRSTUVZ')}${digits(r, 2)}${pick(r, [...'ABCDEHLMPRST'])}${digits(r, 2)}${pick(r, [...'ABCDEFGHILMNPRSTUVZ'])}${digits(r, 3)}${pick(r, [...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'])}` });
    }
  }
  return { docs, uncovered, seed, perLanguage };
}

module.exports = { generate, LANGS, rng };
