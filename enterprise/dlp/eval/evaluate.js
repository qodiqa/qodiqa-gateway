'use strict';

/**
 * Precision / recall of the DLP detectors on the synthetic corpus. EVERY proportion is reported with its 95% Wilson score interval - there is no bare figure anywhere in the
 * output, and a rule with too few examples (n < 30) says so instead of pretending.
 *
 *   evaluate({ seed, perLanguage, minConfidence }) -> report
 *   node enterprise/dlp/eval/evaluate.js [--seed N] [--per-language N] [--write <dir>]
 *
 * Matching: a finding is a true positive for a label when it has the SAME rule and its span overlaps the label's; a label with no such finding is a false negative; a finding
 * that matches no label of its rule is a false positive for the finding's rule (so a phone number found inside a card number counts against PHONE). Documents of the "negative"
 * slice are also scored as documents: the share with at least one finding is the false-positive document rate.
 *
 * What this measures, and does not: synthetic text written by us, templates in eight languages, values generated to be valid. It shows the detectors work on well-formed data and
 * how they hold up against separators, invisible characters and look-alike numbers. It does NOT estimate performance on real traffic, which has formats, typos and contexts this
 * corpus does not.
 */

const fs = require('fs');
const path = require('path');
const { scan } = require('../engine');
const { classify } = require('../classify');
const { generate, LANGS } = require('./corpus');

function wilson(k, n, z = 1.959964) {
  if (n === 0) return { p: null, lo: null, hi: null, n };
  const p = k / n; const d = 1 + (z * z) / n; const c = p + (z * z) / (2 * n); const m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return { p, lo: Math.max(0, (c - m) / d), hi: Math.min(1, (c + m) / d), n };
}
const fmt = (w) => (w.p === null ? 'n/a (no examples)' : `${(w.p * 100).toFixed(2)}% [${(w.lo * 100).toFixed(2)}, ${(w.hi * 100).toFixed(2)}] (n=${w.n})`);
const overlaps = (a, b) => a.start < b.end && b.start < a.end;

function evaluate({ seed = 20261022, perLanguage = 40, minConfidence = 0, operatingPoints = true } = {}) {
  const corpus = generate({ seed, perLanguage });
  const per = new Map(); const bySlice = new Map(); const byLang = new Map();
  const bump = (m, k, f) => { if (!m.has(k)) m.set(k, { tp: 0, fp: 0, fn: 0 }); m.get(k)[f]++; };
  let negDocs = 0; let negDocsWithFinding = 0; const falsePositives = {};
  for (const d of corpus.docs) {
    const { findings } = scan(d.text, { rules: ['*'], minConfidence });
    const used = new Set();
    for (const l of d.labels) {
      const hit = findings.findIndex((f, i) => (f.rule === l.rule || f.alsoRules.includes(l.rule)) && overlaps(f, l) && !used.has(i));
      if (hit >= 0) { used.add(hit); bump(per, l.rule, 'tp'); bump(bySlice, d.slice, 'tp'); bump(byLang, d.lang, 'tp'); } else { bump(per, l.rule, 'fn'); bump(bySlice, d.slice, 'fn'); bump(byLang, d.lang, 'fn'); }
    }
    findings.forEach((f, i) => {
      if (used.has(i)) return;
      // a finding of a rule that has a label there but another label of the same rule already used it is still not a new error
      if (d.labels.some((l) => (l.rule === f.rule || f.alsoRules.includes(l.rule)) && overlaps(f, l))) return;
      bump(per, f.rule, 'fp'); bump(bySlice, d.slice, 'fp'); bump(byLang, d.lang, 'fp');
      (falsePositives[f.rule] = falsePositives[f.rule] || []).push({ slice: d.slice, lang: d.lang });
    });
    if (d.slice === 'negative') { negDocs++; if (findings.length) negDocsWithFinding++; }
  }
  // rule-agnostic view: was the labelled span found by ANY rule? (11-digit national ids collide - a German tax id can also be a valid PESEL - and redaction protects the value either way)
  let anyHit = 0; let anyTotal = 0;
  for (const d of corpus.docs) {
    const { findings } = scan(d.text, { rules: ['*'], minConfidence });
    for (const l of d.labels) { anyTotal++; if (findings.some((f) => overlaps(f, l))) anyHit++; }
  }
  const row = (c) => ({ tp: c.tp, fp: c.fp, fn: c.fn, precision: wilson(c.tp, c.tp + c.fp), recall: wilson(c.tp, c.tp + c.fn) });
  const rules = Object.fromEntries([...per.entries()].sort().map(([k, c]) => [k, row(c)]));
  const total = [...per.values()].reduce((a, c) => ({ tp: a.tp + c.tp, fp: a.fp + c.fp, fn: a.fn + c.fn }), { tp: 0, fp: 0, fn: 0 });
  const slices = Object.fromEntries([...bySlice.entries()].sort().map(([k, c]) => [k, row(c)]));
  const langs = Object.fromEntries([...byLang.entries()].sort().map(([k, c]) => [k, row(c)]));

  // classification markings: neutral text that merely contains words near the markings must not be labelled, and marked text must be
  const marked = ['This document is strictly confidential.', 'Dokument streng vertraulich.', 'Document strict confidențial.', 'For internal use only.', 'Uz intern.', 'Do not distribute outside the company.'];
  const neutral = ['The secretary booked the room.', 'He internalised the feedback quickly.', 'We discussed the confidence interval of the estimate.', 'A restricted-use licence was mentioned in passing in the contract review.', 'The company canteen opens at noon.', 'Intern students start on Monday.'];
  const markedHit = marked.filter((t) => classify(t, []).level !== 'PUBLIC').length; const neutralHit = neutral.filter((t) => classify(t, []).level !== 'PUBLIC').length;

  const points = operatingPoints ? [0.6, 0.8].map((mc) => { const r = evaluate({ seed, perLanguage, minConfidence: mc, operatingPoints: false }); return { minConfidence: mc, precision: r.micro.precision, recall: r.micro.recall, ruleAgnosticRecall: r.ruleAgnosticRecall, falsePositiveDocumentRate: r.negativeDocuments.falsePositiveDocumentRate, phone: r.rules.PHONE || null }; }) : undefined;
  return {
    minConfidence, operatingPoints: points, seed, perLanguage, languages: LANGS, documents: corpus.docs.length, labels: corpus.docs.reduce((n, d) => n + d.labels.length, 0),
    micro: row(total), ruleAgnosticRecall: wilson(anyHit, anyTotal), rules, slices, languagesDetail: langs,
    negativeDocuments: { documents: negDocs, withAnyFinding: negDocsWithFinding, falsePositiveDocumentRate: wilson(negDocsWithFinding, negDocs) },
    markings: { markedTexts: wilson(markedHit, marked.length), neutralTextsFlagged: wilson(neutralHit, neutral.length), note: 'small hand-written sets: read the intervals, they are wide on purpose' },
    uncovered: { note: 'national-id shapes of countries no detector covers; these are known gaps, not passes', kinds: [...new Set(corpus.uncovered.map((u) => u.kind))], count: corpus.uncovered.length },
    falsePositiveExamples: Object.fromEntries(Object.entries(falsePositives).map(([k, v]) => [k, { count: v.length, slices: [...new Set(v.map((x) => x.slice))] }])),
  };
}

function toMarkdown(rep) {
  const L = [];
  L.push('# DLP detectors on the synthetic multilingual corpus', '');
  L.push(`Seed ${rep.seed}, ${rep.perLanguage} cycles per language over ${rep.languages.join(', ')}: ${rep.documents} documents, ${rep.labels} labelled entities. Synthetic text, valid-by-construction values, no real data.`);
  L.push('Every proportion is shown with its 95% Wilson score interval `[low, high]` and the number of examples it rests on. **These figures describe this corpus, not real traffic.**', '');
  L.push(`## Overall at minConfidence ${rep.minConfidence} (micro-average over all rules)`, '', `* precision (rule-exact) ${fmt(rep.micro.precision)}`, `* recall (rule-exact) ${fmt(rep.micro.recall)}`, `* recall, any rule (was the labelled span found at all?) ${fmt(rep.ruleAgnosticRecall)}`, '');
  if (rep.operatingPoints) {
    L.push('### Operating points (the policy setting `minConfidence`)', '', '| minConfidence | precision | recall (rule-exact) | recall (any rule) | false-positive document rate | PHONE precision |', '|---|---|---|---|---|---|');
    L.push(`| ${rep.minConfidence} | ${fmt(rep.micro.precision)} | ${fmt(rep.micro.recall)} | ${fmt(rep.ruleAgnosticRecall)} | ${fmt(rep.negativeDocuments.falsePositiveDocumentRate)} | ${fmt(rep.rules.PHONE.precision)} |`);
    for (const p of rep.operatingPoints) L.push(`| ${p.minConfidence} | ${fmt(p.precision)} | ${fmt(p.recall)} | ${fmt(p.ruleAgnosticRecall)} | ${fmt(p.falsePositiveDocumentRate)} | ${p.phone ? fmt(p.phone.precision) : 'rule not found'} |`);
    L.push('');
  }
  L.push('## By rule', '', '| Rule | TP | FP | FN | Precision | Recall |', '|---|---|---|---|---|---|');
  for (const [k, r] of Object.entries(rep.rules)) L.push(`| ${k} | ${r.tp} | ${r.fp} | ${r.fn} | ${fmt(r.precision)}${r.precision.n < 30 && r.precision.n > 0 ? ' (few examples)' : ''} | ${fmt(r.recall)}${r.recall.n < 30 && r.recall.n > 0 ? ' (few examples)' : ''} |`);
  L.push('', '## By slice', '', '| Slice | TP | FP | FN | Precision | Recall |', '|---|---|---|---|---|---|');
  for (const [k, r] of Object.entries(rep.slices)) L.push(`| ${k} | ${r.tp} | ${r.fp} | ${r.fn} | ${fmt(r.precision)} | ${fmt(r.recall)} |`);
  L.push('', '## By language', '', '| Language | TP | FP | FN | Precision | Recall |', '|---|---|---|---|---|---|');
  for (const [k, r] of Object.entries(rep.languagesDetail)) L.push(`| ${k} | ${r.tp} | ${r.fp} | ${r.fn} | ${fmt(r.precision)} | ${fmt(r.recall)} |`);
  const nd = rep.negativeDocuments;
  L.push('', '## Negative documents (look-alike numbers, dates, versions, order ids, plain text)', '', `${nd.withAnyFinding} of ${nd.documents} contained a finding: false-positive document rate ${fmt(nd.falsePositiveDocumentRate)}.`);
  if (Object.keys(rep.falsePositiveExamples).length) { L.push('', 'False positives by rule (count, slices where they occurred):', ''); for (const [k, v] of Object.entries(rep.falsePositiveExamples)) L.push(`* ${k}: ${v.count} (${v.slices.join(', ')})`); }
  L.push('', '## Classification markings (small hand-written sets)', '', `* marked texts detected ${fmt(rep.markings.markedTexts)}`, `* neutral texts wrongly flagged ${fmt(rep.markings.neutralTextsFlagged)}`, `* ${rep.markings.note}`);
  L.push('', '## Known gaps', '', `${rep.uncovered.note}: ${rep.uncovered.kinds.join(', ')} (${rep.uncovered.count} generated samples, recall 0 by design: no detector exists).`);
  return L.join('\n') + '\n';
}

if (require.main === module) {
  const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
  const rep = evaluate({ seed: Number(arg('--seed', 20261022)), perLanguage: Number(arg('--per-language', 40)) });
  const md = toMarkdown(rep);
  const out = arg('--write', null);
  if (out) { fs.mkdirSync(out, { recursive: true }); fs.writeFileSync(path.join(out, 'dlp-eval.json'), JSON.stringify(rep, null, 2)); fs.writeFileSync(path.join(out, 'dlp-eval.md'), md); }
  console.log(md);
}

module.exports = { evaluate, toMarkdown, wilson };
