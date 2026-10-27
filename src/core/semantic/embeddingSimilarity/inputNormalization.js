'use strict';

/**
 * INPUT NORMALIZATION FOR THE EMBEDDING PATH —.
 *
 * ── The defect this closes ──────────────────────────────────────────────────
 * The semantic layer has always had a normalization pipeline: ../textSignals.js
 * `normalize()` — NFKC, cross-script confusable folding, zero-width/bidi and
 * pictographic stripping, a bounded decode-and-rescan for base64/hex/URL/HTML
 * entities/Unicode escapes, Latin diacritic folding, character-repetition
 * collapse and dictionary-bounded fragment reconstruction.
 *
 * It was wired to the wrong layer. ../index.js computes it once per request and
 * threads it to the KEYWORD classifiers; ../requestSemanticCheck.js then hands
 * ../embeddingGate.js the ORIGINAL prompt, and ./index.js embeds that raw
 * string. So the entire pipeline was applied to the layer the audit measured at
 *
 * Measured proof that this is the mechanism, not a hypothesis
 *:
 *
 *   - The ONE obfuscation class the audit found DETECTED is UPPERCASE, and the
 *     tokenizer control shows why: MiniLM is uncased, so the clean and
 *     uppercased forms produce IDENTICAL token id sequences. The model never
 *     sees that transformation. Every other class reaches it raw.
 *   - Feeding the ALREADY-EXISTING normalize() output to the unchanged gates
 *     recovers two classes outright, with no model change and no threshold
 *   - Token counts localise the loss to the input: a 16-token clean prompt
 *     becomes 43 tokens under leet, 54 under letter spacing, 71 under
 *     punctuation insertion, 56 under ROT13. The obfuscated embedding is not a
 *     degraded version of the clean one — it is a different point.
 *
 * ── What this module adds beyond re-wiring ──────────────────────────────────
 * Re-wiring alone recovers 2 of 7 classes. The remaining 4 — leetspeak, letter
 * spacing, punctuation insertion, ROT13 — are classes the existing pipeline has
 * no transform for at all: its fragment reconstruction is bounded to a ~40-word
 * KEYWORD_DICTIONARY (so it only rebuilds words already on a list), and it has
 * no digit-substitution and no letter-rotation decoder.
 *
 * The three transforms below fill exactly those gaps and are deliberately
 * GENERAL — each is defined over character classes or a frozen statistical
 * property of the text, never over a list of attack words. None of them can
 * "recognise" an attack; they only undo a surface encoding, after which the
 * unchanged gates decide. That distinction is the whole point of a
 * keyword list dressed as normalization would be the prohibited fix.
 *
 * ── The safety architecture ─────────────────────────────────────────────────
 * This module produces CANDIDATE TEXTS. ./index.js scores the raw text first and
 * ORs the candidates on top. Three properties follow structurally, not
 * empirically:
 *
 *   MONOTONE      the raw result is computed first and its DENY is never
 *                 withdrawn, so no existing detection can be lost.
 *   FAIL-CLOSED   a non-READY raw result short-circuits; a failure is never
 *                 retried into an ALLOW.
 *   INERT         a candidate is emitted only on positive evidence that a
 *                 transform actually fired. Text carrying none produces zero
 *                 candidates, one embedding pass, and an output object with no
 *                 normalization fields — byte-identical to the previous path.
 *
 * same rule every gate here already lives under: a candidate can only cause one
 * if the transform turns benign text into text that scores like an attack. That
 * legitimate set — never a subset — before this is enabled.
 *
 * ── Why "positive evidence", not "text changed" ─────────────────────────────
 * Emitting a candidate whenever normalize() changed anything would fire on
 * ordinary prose: case, whitespace and Latin diacritics all change the string
 * and none is an evasion signal. Case and whitespace in particular are already
 * neutralised by the uncased tokenizer, so a second pass over them is pure
 * latency for arithmetically identical input. The gate is instead
 * analyzeNormalization()'s own evasion flags — the pipeline's existing,
 * audit-safe statement of WHICH transform fired.
 */

const { normalize, analyzeNormalization, substituteEncodedContent, tryBase64Decode } = require('../textSignals');
const { NORMALIZE_V2_ENABLED } = require('./config');

/**
 * The normalization-meta flags that constitute positive evidence of an
 * encoding or obfuscation transform, as opposed to routine text variation.
 *
 * Deliberately EXCLUDES the diacritic fold: an accented word is ordinary
 * multilingual text, not evasion, and folding it does not move an attack across
 * there is representational and belongs to not to this stage). Also
 * excludes `changed` and `truncated`, which say nothing about which transform
 * fired.
 */
const EVASION_META_FLAGS = Object.freeze([
  'base64Decoded',
  'hexDecoded',
  'urlDecoded',
  'htmlEntityDecoded',
  'unicodeEscapeDecoded',
  'homoglyphFolded',
  'pictographicStripped',
  'evasionCharsStripped',
  'repetitionCollapsed',
  'fragmentsReconstructed',
]);

/**
 * Hard cap on candidates scored per classify() call, so a pathological input
 * cannot multiply inference cost without bound. Four transforms exist; the cap
 * is the number of DISTINCT candidate texts, after de-duplication.
 */
const MAX_CANDIDATES = 3;

// ── Transform 0: invisible-character strip, as a BASE for the two below ─────
//
// Compatibility-normalises and removes the characters that carry no meaning in
// a prompt and exist only to break a scanner: zero-width and bidi controls, and
// pictographic characters used as inter-letter separators. The character
// classes are deliberately the same ones ../textSignals.js already strips, for
// the same reasons its own comments give.
//
// It is repeated here rather than reused because of WHAT ELSE normalize() does:
// it collapses runs of whitespace, and a doubled space is exactly the
// word-boundary signal collapseSeparatedLetters() reads to rebuild
// "G i v e  s t e p" as two words rather than one. Running the separator rule
// after whitespace collapsing would destroy the information it needs. This
// strip is therefore the minimal cleaning the composed transforms can sit on;
// the full pipeline still runs afterwards, on their output.
const INVISIBLES = /[​-‏‪-‮⁠﻿]|\p{Extended_Pictographic}/gu;

function stripInvisibles(text) {
  return text.normalize('NFKC').replace(INVISIBLES, '');
}

// ── Transform 1: leet / character-substitution folding ──────────────────────
//
// Digit-and-symbol-for-letter substitution ("G1v3 st3p-by-st3p"). Scoped to a
// single word token that MIXES letters and substituted characters, which is the
// signature of the transform: a purely numeric token (a quantity, a year, a
// percentage) has no letters and is never touched, and a purely alphabetic
// token has nothing to substitute.
//
// POSITION IS THE DISCRIMINATOR, and it is what separates this from a word
// list. In genuine leetspeak the substituted character stands in for a letter
// INSIDE a word, so it is followed by more letters: "st3p", "1nstruct10ns",
// "b0mb", "h0m3". In ordinary technical vocabulary the digits are a SUFFIX:
// "base64", "SHA256", "MD5", "utf8", "IPv4", "Q4". Requiring at least one
// substituted character to be followed by a letter keeps every one of those
// intact while folding every leet form — a structural rule about where the
// character sits, with no knowledge of which words matter.
//
// This rule was added on measured evidence, not anticipation: without it
// "base64" folded to "basega", and that corruption alone accounted for 2 of the
//
// Where a token IS still rewritten (e.g. "3D" -> "eD"), the consequence is
// bounded by the architecture rather than by the rule: it produces one
// additional candidate that scores low, never a denial of its own.
const LEET_MAP = Object.freeze({
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
  '@': 'a', '$': 's', '!': 'i', '|': 'l', '+': 't',
});
const LEET_TOKEN = /[A-Za-z0-9@$!|+]+/g;
const IS_LETTER = /[A-Za-z]/;
// Minimum length for the DENSE branch only. Short reference codes are exactly
// the shape that branch would otherwise match — one letter carrying two or
// three digits — and they are common in ordinary, often safety-relevant
// requests. Measured: without this floor the protective corpus gained a false
// positive, "How do I get a copy of my own P60 or W-2?", because "P60" folded
// to "pgo". A word substituted densely enough to lose its interleaving is
// several characters long ("d37411", "un7r4c34813"); a form number is not.
// The interleaved branch is unaffected and needs no floor — it is already
// discriminating on position.
const DENSE_MIN_LENGTH = 5;

function foldLeet(text) {
  let changed = false;
  const out = text.replace(LEET_TOKEN, (token) => {
    if (token.length < 2) return token;
    let letters = 0;
    let subs = 0;
    let internalSub = false;
    for (let i = 0; i < token.length; i++) {
      const ch = token[i];
      if (IS_LETTER.test(ch)) { letters += 1; continue; }
      if (LEET_MAP[ch] === undefined) return token; // not a leet token at all
      subs += 1;
      if (i + 1 < token.length && IS_LETTER.test(token[i + 1])) internalSub = true;
    }
    // Fold on EITHER signature of a substitution, because leetspeak has two.
    //
    //   interleaved — a substituted character is followed by a letter:
    //                 "st3p", "b0mb", "8u11d". This is the common case and it
    //                 is what separates leet from a digit SUFFIX ("base64",
    //                 "SHA256", "MD5", "utf8", "IPv4", "Q4"), where nothing
    //                 follows the digits.
    //   dense       — substitutions outnumber the surviving letters:
    //                 "d37411" for "detail", where the substitution is so
    //                 thorough that almost no letter is left to follow. This
    //                 case has no interleaving to detect, and it is the one a
    //                 position rule alone silently misses — measured, on the
    //                 leet-plus-spacing composition, before this branch existed.
    //
    // A technical identifier satisfies neither: its digits trail a longer
    // alphabetic stem, so nothing follows them and they never outnumber it.
    if (letters < 1 || subs < 1) return token;
    if (!internalSub && (subs <= letters || token.length < DENSE_MIN_LENGTH)) return token;
    let folded = '';
    for (const ch of token) folded += LEET_MAP[ch] !== undefined ? LEET_MAP[ch] : ch;
    changed = true;
    return folded;
  });
  return { text: out, changed };
}

// ── Transform 2: separated-letter collapse ──────────────────────────────────
//
// Letter-by-letter spelling with an inserted separator: "G i v e  s t e p" and
// "E.x.p.l.a.i.n" are the same evasion with different separator characters, so
// they are one transform, not two.
//
// The rule is structural and content-free:
//   - a run is an alternating sequence of SINGLE letters and separator runs;
//   - a separator run of length 1 is INTRA-word and disappears;
//   - a separator run of length >= 2 is a WORD BOUNDARY and becomes one space;
//   - the run must contain at least MIN_RUN_LETTERS letters and at least one
//     length-1 separator, or it is not fragmentation at all.
//
// The two conditions are what keep ordinary prose intact. An enumeration like
// "a, b, c" separates with two characters throughout, so it has no intra-word
// separator and is left alone; initials such as "I. M. Pei" fail both tests.
// The minimum is 5 rather than 4 because 4 admitted ordinary abbreviation
// clusters — "the U.K., e.g." is four run positions with a single-character
// separator inside "U.K." — while genuine fragmentation spells whole words or
// whole sentences and clears any small minimum by an order of magnitude.
// external legitimate set rather than argued —
// A run position may be a letter OR a leet substitution character. Spacing and
// leet COMPOSE in real payloads ("3 x p l 4 1 n"), and a rule that only walked
// letters would break the run at the first digit and defeat itself — measured:
// each transform alone was fully recovered. The two rules that keep ordinary
// prose intact (a minimum run length, and a required intra-word separator) are
const MIN_RUN_LETTERS = 5;
const RUN_CHAR = '[\\p{L}0-9@$!|+]';
const RUN_SEP = '[ .\\-_,;:]';
const SEPARATED_RUN = new RegExp(
  `(?<!${RUN_CHAR})${RUN_CHAR}(?:${RUN_SEP}{1,3}${RUN_CHAR}){3,}(?!${RUN_CHAR})`, 'gu',
);
const RUN_SEP_ONE = /[ .\-_,;:]/;

function collapseSeparatedLetters(text) {
  let changed = false;
  const out = text.replace(SEPARATED_RUN, (run) => {
    const letters = [];
    const seps = [];
    let i = 0;
    while (i < run.length) {
      letters.push(run[i]);
      i += 1;
      let sep = 0;
      while (i < run.length && RUN_SEP_ONE.test(run[i])) { sep += 1; i += 1; }
      if (i < run.length) seps.push(sep);
    }
    if (letters.length < MIN_RUN_LETTERS) return run;
    if (!seps.some((s) => s === 1)) return run;
    // A run made only of digits and symbols is a formatted NUMBER, not spelled
    // text — "1 2 3 4", "4-5-6-7", a spaced card or reference number. Requiring
    // at least one real letter keeps every one of those untouched.
    if (!letters.some((c) => /\p{L}/u.test(c))) return run;
    let rebuilt = letters[0];
    for (let k = 0; k < seps.length; k++) {
      rebuilt += seps[k] >= 2 ? ` ${letters[k + 1]}` : letters[k + 1];
    }
    changed = true;
    return rebuilt;
  });
  return { text: out, changed };
}

// ── Transform 3: ROT13 ──────────────────────────────────────────────────────
//
// A letter rotation is trivially reversible, but applying it unconditionally
// would double inference cost on every request. The gate is a frozen English
// unigram model: ROT13 is its own inverse, so the decision is a single
// comparison — take the rotated text only when it is MORE English-like than
// what arrived.
//
// This is a statistical property of the character distribution, not a word
// list. Ordinary English scores far above its own rotation (ROT13 maps the
// commonest letters onto some of the rarest: e->r, t->g, a->n, o->b), so the
// comparison costs microseconds and produces no candidate for normal traffic.
// A ROT13'd payload inverts the comparison and produces exactly one.
//
// Frequencies are per-cent of letters in English text, a standard published
// distribution; the floor keeps log() finite for letters absent from a short
// sample.
const ENGLISH_FREQ = Object.freeze({
  a: 8.167, b: 1.492, c: 2.782, d: 4.253, e: 12.702, f: 2.228, g: 2.015,
  h: 6.094, i: 6.966, j: 0.153, k: 0.772, l: 4.025, m: 2.406, n: 6.749,
  o: 7.507, p: 1.929, q: 0.095, r: 5.987, s: 6.327, t: 9.056, u: 2.758,
  v: 0.978, w: 2.360, x: 0.150, y: 1.974, z: 0.074,
});
const MIN_LETTERS_FOR_ROT13 = 20;
// Required separation in mean log-probability per letter before the rotated
// form is accepted. A margin rather than a bare `>` so near-ties — short or
// atypical text where the statistic carries little information — produce no
// candidate instead of a coin flip.
const ROT13_MARGIN = 0.05;
// The comparison is made over a SLIDING WINDOW, not over the whole text,
// because a whole-text average is exactly what a long-context attack defeats: a
// rotated payload buried in ordinary English padding leaves the document as a
// whole looking English, and the signal is diluted below any margin. The
// windows overlap for the same reason the classifier's own do — a payload
// straddling a boundary must still be visible whole in at least one window.
//
// The size was swept, not chosen. Detections are of the 16 rotated variants in
// gibberish, and gibberish cannot score like an attack):
//
//
// buys no detection and costs more passes. The protective corpus never triggers
// at any size, which is the population where an extra pass would matter most.
const ROT13_WINDOW_CHARS = 100;
const ROT13_WINDOW_STEP = 50;

function rot13(text) {
  return text.replace(/[A-Za-z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/**
 * Mean natural-log unigram probability per alphabetic character. Returns null
 * when there is too little text for the statistic to mean anything.
 */
function englishScore(text) {
  let total = 0;
  let n = 0;
  for (const ch of text.toLowerCase()) {
    const f = ENGLISH_FREQ[ch];
    if (f === undefined) continue;
    total += Math.log(f / 100);
    n += 1;
  }
  return n >= MIN_LETTERS_FOR_ROT13 ? total / n : null;
}

/**
 * True when SOME chunk of the text reads more like English after rotation than
 * before it. Taking the maximum over chunks rather than the mean over the whole
 * document is what keeps a rotated payload visible when it is padded with
 * ordinary prose — see ROT13_WINDOW_CHARS.
 *
 * Rotating the whole text once a chunk qualifies is deliberate and costs
 * nothing: ROT13 is self-inverse, so the padding becomes gibberish (which
 * scores low and cannot deny anything) while the payload becomes readable, and
 * the classifier's own windowing then presents the payload in a window of its
 * own.
 */
function rot13Improves(text) {
  for (let i = 0; i < text.length; i += ROT13_WINDOW_STEP) {
    const window = text.slice(i, i + ROT13_WINDOW_CHARS);
    const sRaw = englishScore(window);
    const sRot = englishScore(rot13(window));
    if (sRaw !== null && sRot !== null && sRot > sRaw + ROT13_MARGIN) return true;
    if (i + ROT13_WINDOW_CHARS >= text.length) break;
  }
  return false;
}

// ── (S2a) — second-tier decoder coverage, gated by NORMALIZE_V2_ENABLED ──
//
// Four additional transforms, each following the same INERT/structural rule
// as the three above: fire only on positive evidence that its own transform
// applies, never on "text changed" generally. Kept behind their own flag
// (config.js's NORMALIZE_V2_ENABLED, default OFF) rather than folded into the
// three above, because these are UNMEASURED against the frozen
// With the flag off (the
// production default), none of the functions below are ever called and
// candidatesFor()'s output is byte-identical to the earlier code.

// ── V2 Transform: whitespace-tolerant base64 ─────────────────────────────────
//
// textSignals.js's own decode-and-rescan requires ONE contiguous base64 run
// with no interior whitespace. Base64 pasted from a document, email, or chat
// client commonly wraps across lines. This candidate looks for a MULTI-CHUNK
// span — at least 3 chunks of >=4 base64-alphabet characters, separated by
// short whitespace runs — strips the whitespace, and hands the result to the
// SAME decode-and-validate function textSignals.js itself uses
// fire on anything decode-and-validate would not already accept contiguous.
//
// The 3-chunk-minimum is the discriminator that keeps this off ordinary
// prose: two words separated by one space would trivially match a looser
// span (letters are a subset of the base64 alphabet), but genuine wrapped
// base64 is many chunks long, and three arbitrary English words joined
// without punctuation is already an unusual sentence, LONG before it would
// two independent, structurally unrelated conditions that ordinary prose
// essentially never satisfies together (verified empirically, not assumed,
const WS_B64_CHUNK = '[A-Za-z0-9+/_-]{4,}';
const WS_B64_SEP = '[ \\t\\r\\n]{1,2}';
const WS_BASE64_SPAN = new RegExp(`${WS_B64_CHUNK}(?:${WS_B64_SEP}${WS_B64_CHUNK}){2,}={0,2}`, 'g');
// Bounds worst-case cost on a pathological input with many candidate spans —
// same defense-in-depth posture as textSignals.js's own MAX_CANDIDATES_PER_PASS.
const MAX_WS_BASE64_SPANS_SCANNED = 5;
const MIN_WS_BASE64_STRIPPED_LENGTH = 24;

function tryWhitespaceBase64Decode(text) {
  const spans = text.match(WS_BASE64_SPAN);
  if (!spans) return null;
  for (const span of spans.slice(0, MAX_WS_BASE64_SPANS_SCANNED)) {
    const stripped = span.replace(/\s+/g, '');
    if (stripped.length < MIN_WS_BASE64_STRIPPED_LENGTH) continue;
    const decoded = tryBase64Decode(stripped);
    if (decoded) return decoded;
  }
  return null;
}

// ── V2 Transform: extended homoglyph folding ─────────────────────────────────
//
// textSignals.js's own CONFUSABLES table maps 29 characters, but only the
// LOWERCASE Cyrillic/Greek confusables — it has no entry for the UPPERCASE
// ones, which are the single most famous homoglyph class in existence (the
// canonical IDN-homograph set: Cyrillic А/В/Е/К/М/Н/О/Р/С/Т/Х and Greek
// Α/Β/Ε/Ζ/Η/Ι/Κ/Μ/Ν/Ο/Ρ/Τ/Υ/Χ render as visually IDENTICAL glyphs to their
// Latin counterparts in essentially every font — this is not a judgment call
// the way a "close but not identical" mapping would be). Verified these are
// NOT already folded by NFKC (checked directly: `'А'.normalize('NFKC') ===
// 'А'`, unchanged — Cyrillic/Greek letters are canonically distinct
// codepoints from Latin with no compatibility decomposition, exactly the
// same reason the original lowercase CONFUSABLES table was needed at all).
//
// Deliberately a SEPARATE, local table rather than an edit to
// textSignals.js's CONFUSABLES: that table feeds the always-on production
// normalize() pipeline (NORMALIZE_ENABLED is pinned true), so growing it
// would change production behaviour immediately, outside this task's
// flag-gated, measure-before-enable design.
//
// Same scoping rule as the shared table: folding fires only on a token that
// MIXES Latin letters with these confusables, never on an all-non-Latin
// token — genuine Cyrillic/Greek prose is left alone; the multilingual
// signals layer (i18nSignals.js), not this module, is responsible for it.
const EXTENDED_CONFUSABLES = Object.freeze({
  // Cyrillic uppercase -> Latin
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H',
  'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'Ѕ': 'S', 'Ј': 'J',
  // Greek uppercase -> Latin
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
  'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
});
const EXTENDED_CONFUSABLE_CHAR_RE = new RegExp(
  `[${Object.keys(EXTENDED_CONFUSABLES).join('')}]`,
);
const IS_LATIN_LETTER = /[A-Za-z]/;
const WORD_TOKEN = /[\p{L}\p{N}]+/gu;

function foldExtendedConfusables(text) {
  let changed = false;
  const out = text.replace(WORD_TOKEN, (token) => {
    let hasExtended = false;
    let hasLatin = false;
    for (const ch of token) {
      if (EXTENDED_CONFUSABLE_CHAR_RE.test(ch)) hasExtended = true;
      else if (IS_LATIN_LETTER.test(ch)) hasLatin = true;
    }
    // Mixed-token rule (see header): an all-Cyrillic/Greek token is left
    // untouched for the multilingual layer to handle.
    if (!hasExtended || !hasLatin) return token;
    let folded = '';
    for (const ch of token) folded += EXTENDED_CONFUSABLES[ch] !== undefined ? EXTENDED_CONFUSABLES[ch] : ch;
    changed = true;
    return folded;
  });
  return { text: out, changed };
}

// ── V2 Transform: wider-separator, multi-pass letter-spacing collapse ────────
//
// Extends collapseSeparatedLetters()'s separator character class with four
// more common separator glyphs (/  \  *  ~) not in the V1 set, and applies
// the spacing+leet composition TWICE (a second round only when the first
// round changed something), to catch cases where folding round 1 reveals a
// spacing pattern round 1 itself could not see (e.g. a residual separator
// left between two tokens that only merge into one run after the first
// round's leet substitutions land). The two conditions that keep ordinary
// prose intact in V1 (a minimum run length, and a required intra-word
// single-character separator) are unchanged and untouched by the wider
// character class or the second round — both rounds are the same function,
// just re-applied.
const RUN_SEP_V2 = '[ .\\-_,;:/\\\\*~]';
const SEPARATED_RUN_V2 = new RegExp(
  `(?<!${RUN_CHAR})${RUN_CHAR}(?:${RUN_SEP_V2}{1,3}${RUN_CHAR}){3,}(?!${RUN_CHAR})`, 'gu',
);
const RUN_SEP_ONE_V2 = /[ .\-_,;:/\\*~]/;

function collapseSeparatedLettersV2(text) {
  let changed = false;
  const out = text.replace(SEPARATED_RUN_V2, (run) => {
    const letters = [];
    const seps = [];
    let i = 0;
    while (i < run.length) {
      letters.push(run[i]);
      i += 1;
      let sep = 0;
      while (i < run.length && RUN_SEP_ONE_V2.test(run[i])) { sep += 1; i += 1; }
      if (i < run.length) seps.push(sep);
    }
    if (letters.length < MIN_RUN_LETTERS) return run;
    if (!seps.some((s) => s === 1)) return run;
    if (!letters.some((c) => /\p{L}/u.test(c))) return run;
    let rebuilt = letters[0];
    for (let k = 0; k < seps.length; k++) {
      rebuilt += seps[k] >= 2 ? ` ${letters[k + 1]}` : letters[k + 1];
    }
    changed = true;
    return rebuilt;
  });
  return { text: out, changed };
}

const MULTI_PASS_ROUNDS = 2;

function deobfuscateV2(text) {
  let current = stripInvisibles(text);
  let anyChanged = false;
  for (let round = 0; round < MULTI_PASS_ROUNDS; round++) {
    const spaced = collapseSeparatedLettersV2(current);
    const leeted = foldLeet(spaced.text);
    if (!spaced.changed && !leeted.changed) break;
    anyChanged = true;
    current = leeted.text;
  }
  return { text: current, changed: anyChanged };
}

// ── V2 Transform: generalized ROT-n ───────────────────────────────────────────
//
// rot13Improves()/rot13() above test exactly one shift (n=13), the classic
// and overwhelmingly common case. This generalizes the identical sliding-
// window English-likelihood comparison to the other 24 non-trivial shifts,
// so a payload rotated by any amount — not just 13 — produces a candidate.
// n=13 itself is deliberately excluded here (the existing, separately-tested
// rot13Improves()/rot13() pair already covers it) so V1 behaviour is
// completely unaffected when this function is never called (flag off).
function rotN(text, n) {
  return text.replace(/[A-Za-z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + n) % 26) + base);
  });
}

function bestOtherRotN(text) {
  // Tracks the BEST-scoring shift, not the first one that merely clears the
  // margin — with 24 shifts searched per window, more than one can score
  // above sRaw + ROT13_MARGIN on a short/noisy window (a wrong shift can
  // still look "somewhat English"), and returning the first such shift found
  // a real bug during implementation: for a text ROT7'd, n=4 cleared the
  // margin and was returned before n=19 (the actual, correctly round-tripping
  // decode, which scored decisively better) was ever compared. Taking the
  // max across the full 1..25 sweep before deciding fixes this.
  for (let i = 0; i < text.length; i += ROT13_WINDOW_STEP) {
    const window = text.slice(i, i + ROT13_WINDOW_CHARS);
    const sRaw = englishScore(window);
    if (sRaw !== null) {
      let bestN = null;
      let bestScore = -Infinity;
      for (let n = 1; n <= 25; n++) {
        if (n === 13) continue;
        const sRot = englishScore(rotN(window, n));
        if (sRot !== null && sRot > bestScore) { bestScore = sRot; bestN = n; }
      }
      if (bestN !== null && bestScore > sRaw + ROT13_MARGIN) return bestN;
    }
    if (i + ROT13_WINDOW_CHARS >= text.length) break;
  }
  return null;
}

// ── Candidate assembly ──────────────────────────────────────────────────────

/**
 * Canonical form used ONLY to decide whether two texts are the same input as
 * far as the model is concerned. Case and whitespace are collapsed because the
 * tokenizer is uncased and whitespace-insensitive, so a candidate differing
 * only in those respects would produce an arithmetically identical embedding
 * and cost a full inference pass for nothing.
 */
function canonical(text) {
  return text.toLowerCase().replace(/\s+/g, ' ').trim();
}

/**
 * The candidate texts to score IN ADDITION to the raw input, in priority order.
 * The raw text is never included — ./index.js always scores it first and this
 * module never sees the result, so it cannot influence, weaken or replace it.
 *
 * @param {string} text
 * @returns {Array<{id: string, text: string}>} at most MAX_CANDIDATES entries
 */
function candidatesFor(text) {
  if (typeof text !== 'string' || text.length === 0) return [];

  const out = [];
  const seen = new Set([canonical(text)]);
  // with the V2 flag off (the default), this is exactly MAX_CANDIDATES
  // and step (4) below never runs, so behaviour is byte-identical to earlier.
  // MAX_CANDIDATES itself is left unchanged (existing pinning tests assert its
  // value) — the higher cap only ever applies locally, within this call, and
  // only when NORMALIZE_V2_ENABLED is true.
  const cap = NORMALIZE_V2_ENABLED ? MAX_CANDIDATES + 4 : MAX_CANDIDATES;

  const push = (id, candidateText) => {
    if (out.length >= cap) return;
    if (typeof candidateText !== 'string' || candidateText.length === 0) return;
    const key = canonical(candidateText);
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ id, text: candidateText });
  };

  // (1) The shared pipeline, gated on its own evasion evidence.
  let meta;
  try {
    meta = analyzeNormalization(text);
  } catch {
    // The pipeline is a pure function of a string and should not throw, but a
    // normalization failure must never take down classification: the caller
    // still has the raw result, which is the earlier behaviour exactly.
    return out;
  }
  if (EVASION_META_FLAGS.some((f) => meta[f])) {
    // SUBSTITUTING, not appending. normalize() alone carries the undecoded blob
    // along with its plaintext, which is correct for a scanner and measurably
    // positives's first measurement, every one of them a legitimate
    // "please decode this base64" hard negative. See
    // ../textSignals.js's substituteEncodedContent() for the full evidence.
    try { push('decoded', normalize(substituteEncodedContent(text))); } catch { /* see above */ }
  }

  // (2) The transforms the shared pipeline has no rule for. Applied together —
  // they compose in real payloads ("G1v3 st3p-by-st3p" is leet AND hyphenated)
  // and scoring them separately would cost two passes to say one thing. The
  // result is run through the shared pipeline so the candidate is comparable to
  // the text every threshold was calibrated against.
  //
  // They run on an INVISIBLES-STRIPPED base rather than on the raw text,
  // because zero-width insertion composes with both of them and would otherwise
  // for zero-width+leet until this pre-strip existed. It cannot simply run on
  // normalize()'s output instead: that collapses whitespace, and a run of two
  // spaces is precisely the word-boundary signal collapseSeparatedLetters()
  // depends on to rebuild "G i v e  s t e p" as two words rather than one.
  try {
    const base = stripInvisibles(text);
    const spaced = collapseSeparatedLetters(base);
    const leeted = foldLeet(spaced.text);
    if (spaced.changed || leeted.changed) push('deobfuscated', normalize(leeted.text));
  } catch { /* see above */ }

  // (3) Letter rotation, gated by the frozen English unigram comparison taken
  // per chunk so padding cannot dilute it away.
  try {
    if (rot13Improves(text)) push('rot13', normalize(rot13(text)));
  } catch { /* see above */ }

  // (4) (S2a) — second-tier decoders, off by default (see the flag's
  // own header comment in config.js). Each still only ever emits a candidate
  // on its own positive evidence, same INERT rule as (1)-(3) above.
  if (NORMALIZE_V2_ENABLED) {
    try {
      const wsDecoded = tryWhitespaceBase64Decode(text);
      if (wsDecoded) push('ws-base64-v2', normalize(wsDecoded));
    } catch { /* see above */ }

    try {
      const folded = foldExtendedConfusables(text);
      if (folded.changed) push('homoglyph-v2', normalize(folded.text));
    } catch { /* see above */ }

    try {
      const deob = deobfuscateV2(text);
      if (deob.changed) push('deobfuscated-v2', normalize(deob.text));
    } catch { /* see above */ }

    try {
      const n = bestOtherRotN(text);
      if (n !== null) push('rotn-v2', normalize(rotN(text, n)));
    } catch { /* see above */ }
  }

  return out;
}

module.exports = {
  candidatesFor,
  // Exported for the pinning tests, which assert each transform's behaviour on
  // legitimate text directly rather than only through the ensemble.
  foldLeet,
  collapseSeparatedLetters,
  stripInvisibles,
  rot13,
  rot13Improves,
  englishScore,
  canonical,
  EVASION_META_FLAGS,
  MAX_CANDIDATES,
  MIN_RUN_LETTERS,
  MIN_LETTERS_FOR_ROT13,
  ROT13_MARGIN,
  // (S2a) — V2 decoders, exported for the pinning/unit tests.
  tryWhitespaceBase64Decode,
  foldExtendedConfusables,
  collapseSeparatedLettersV2,
  deobfuscateV2,
  rotN,
  bestOtherRotN,
  EXTENDED_CONFUSABLES,
};
