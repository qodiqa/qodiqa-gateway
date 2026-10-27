'use strict';

/**
 * A regular-expression engine that cannot be made to backtrack. Operator-supplied patterns in content rules are compiled to a Thompson NFA and run by simulating ALL states
 * in lock-step over the input: the cost is O(input x states) whatever the pattern - there is no backtracking, so `(a+)+$` and `(a|aa)*b` cost the same as `abc`. The engine reports only
 * WHETHER the pattern matches somewhere in the text (and where the first match ends); it has no captures.
 *
 * Supported: literals and escapes (\. \\ \t \n \r \d \D \w \W \s \S), `.` (any character but a line break), classes `[a-z0-9_]` / `[^...]` (ranges, the escapes above), groups `(...)`
 * and `(?:...)`, alternation `|`, quantifiers `* + ? {m} {m,} {m,n}` (counts <= 100, a trailing `?` for lazy is accepted and means the same), anchors `^` and `$` (start and end of the text).
 * REFUSED when compiling: lookahead/lookbehind, back-references, named groups, `\b`, flags inside the pattern, nesting deeper than 16, patterns longer than 512 characters, or more than
 * 500 NFA states after counted repetitions are expanded. `caseInsensitive` folds both sides with toLowerCase on single code points.
 *
 *   compile(pattern, { caseInsensitive }) -> { test(text) -> boolean, states }     throws RegexError
 *   MAX_INPUT = 262144   longer text is not scanned by test(): it throws, so a caller treats it as "not scanned completely"
 */

const MAX_PATTERN = 512; const MAX_STATES = 500; const MAX_DEPTH = 16; const MAX_COUNT = 100; const MAX_INPUT = 262_144;

class RegexError extends Error { constructor(m) { super(m); this.name = 'RegexError'; } }

const isDigit = (c) => c >= 48 && c <= 57;
const isWord = (c) => isDigit(c) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || (c > 127 && /[\p{L}\p{N}]/u.test(String.fromCodePoint(c)));
const isSpace = (c) => c === 32 || (c >= 9 && c <= 13) || c === 0xa0 || c === 0x2028 || c === 0x2029 || c === 0xfeff;
const isLineBreak = (c) => c === 10 || c === 13 || c === 0x2028 || c === 0x2029;
const fold = (c) => { const s = String.fromCodePoint(c).toLowerCase(); return s.length === String.fromCodePoint(c).length ? s.codePointAt(0) : c; };

// ── parser: pattern -> AST ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
function parse(pattern) {
  if (typeof pattern !== 'string' || pattern.length === 0) throw new RegexError('the pattern is empty');
  if (pattern.length > MAX_PATTERN) throw new RegexError(`the pattern is longer than ${MAX_PATTERN} characters`);
  const cps = [...pattern]; let i = 0;
  const peek = () => cps[i]; const eat = () => cps[i++];
  const escapeSet = (ch) => ({ d: isDigit, w: isWord, s: isSpace, D: (c) => !isDigit(c), W: (c) => !isWord(c), S: (c) => !isSpace(c) })[ch];
  const escapeChar = (ch) => ({ t: 9, n: 10, r: 13 })[ch];

  function parseClass() {
    let negate = false; const items = [];
    if (peek() === '^') { negate = true; eat(); }
    let first = true;
    while (i < cps.length && (peek() !== ']' || first)) {
      first = false; let c = eat(); let set = null;
      if (c === '\\') {
        const e = eat(); if (e === undefined) throw new RegexError('a trailing backslash');
        if (escapeSet(e)) set = escapeSet(e); else if (escapeChar(e) !== undefined) c = String.fromCharCode(escapeChar(e)); else if (/[0-9bBkpPuxc]/.test(e)) throw new RegexError(`unsupported escape \\${e}`); else c = e;
      }
      if (set) { items.push(set); continue; }
      const lo = c.codePointAt(0);
      if (peek() === '-' && cps[i + 1] !== undefined && cps[i + 1] !== ']') {
        eat(); let h = eat();
        if (h === '\\') { const e = eat(); if (escapeSet(e) || /[0-9bBkpPuxc]/.test(e)) throw new RegexError('a class range cannot end in an escape class'); h = escapeChar(e) !== undefined ? String.fromCharCode(escapeChar(e)) : e; }
        const hi = h.codePointAt(0); if (hi < lo) throw new RegexError('a class range is reversed');
        items.push([lo, hi]);
      } else items.push([lo, lo]);
    }
    if (peek() !== ']') throw new RegexError('an unterminated class'); eat();
    return { t: 'set', negate, items };
  }

  function parseAtom(depth) {
    const c = eat();
    if (c === '(') {
      if (depth >= MAX_DEPTH) throw new RegexError(`groups nested deeper than ${MAX_DEPTH}`);
      if (peek() === '?') { eat(); if (eat() !== ':') throw new RegexError('only (?:...) groups are supported (no lookaround, no named groups)'); }
      const inner = parseAlt(depth + 1); if (eat() !== ')') throw new RegexError('an unterminated group'); return inner;
    }
    if (c === ')' ) throw new RegexError('an unmatched )');
    if (c === '[') return parseClass();
    if (c === '.') return { t: 'any' };
    if (c === '^') return { t: 'bol' };
    if (c === '$') return { t: 'eol' };
    if (c === '*' || c === '+' || c === '?') throw new RegexError(`nothing to repeat before ${c}`);
    if (c === '{' ) throw new RegexError('a { that does not follow an atom');
    if (c === '\\') {
      const e = eat(); if (e === undefined) throw new RegexError('a trailing backslash');
      if (escapeSet(e)) return { t: 'set', negate: false, items: [escapeSet(e)] };
      if (escapeChar(e) !== undefined) return { t: 'char', c: escapeChar(e) };
      if (/[0-9bBkpPuxc]/.test(e)) throw new RegexError(`unsupported escape \\${e} (no back-references, word boundaries, unicode or hex escapes)`);
      return { t: 'char', c: e.codePointAt(0) };
    }
    return { t: 'char', c: c.codePointAt(0) };
  }

  function parseRepeat(depth) {
    let atom = parseAtom(depth);
    for (;;) {
      const q = peek(); let min; let max;
      if (q === '*') { eat(); min = 0; max = Infinity; } else if (q === '+') { eat(); min = 1; max = Infinity; } else if (q === '?') { eat(); min = 0; max = 1; } else if (q === '{') {
        const m = /^\{(\d{1,3})(,(\d{0,3}))?\}/.exec(cps.slice(i).join('')); if (!m) throw new RegexError('a malformed {m,n} quantifier');
        min = Number(m[1]); max = m[2] === undefined ? min : (m[3] === '' ? Infinity : Number(m[3]));
        if (min > MAX_COUNT || (max !== Infinity && max > MAX_COUNT) || max < min) throw new RegexError(`counts are at most ${MAX_COUNT} and {m,n} needs m <= n`);
        i += m[0].length;
      } else break;
      if (peek() === '?') eat();                                   // lazy suffix: the same for a yes/no answer
      if (peek() === '+') throw new RegexError('possessive quantifiers are not supported');
      atom = { t: 'rep', min, max, a: atom };
    }
    return atom;
  }

  function parseConcat(depth) { const parts = []; while (i < cps.length && peek() !== '|' && peek() !== ')') parts.push(parseRepeat(depth)); return { t: 'cat', parts }; }
  function parseAlt(depth) { const alts = [parseConcat(depth)]; while (peek() === '|') { eat(); alts.push(parseConcat(depth)); } return alts.length === 1 ? alts[0] : { t: 'alt', alts }; }

  const ast = parseAlt(0);
  if (i < cps.length) throw new RegexError('an unmatched )');
  return ast;
}

// ── compiler: AST -> NFA ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
function compile(pattern, { caseInsensitive = false } = {}) {
  const ast = parse(pattern);
  const states = [];                                                // { k: 'char'|'any'|'set'|'split'|'bol'|'eol'|'match', ... , out, out2 }
  const add = (s) => { if (states.length >= MAX_STATES) throw new RegexError(`the pattern needs more than ${MAX_STATES} states`); states.push(s); return states.length - 1; };
  const matcherOf = (n) => {
    if (n.t === 'char') { const c = caseInsensitive ? fold(n.c) : n.c; return caseInsensitive ? (x) => fold(x) === c : (x) => x === c; }
    if (n.t === 'any') return (x) => !isLineBreak(x);
    const test = (x) => n.items.some((it) => (typeof it === 'function' ? it(x) : x >= it[0] && x <= it[1]) || (caseInsensitive && !(typeof it === 'function') && (() => { const f = fold(x); return f >= fold(it[0]) && f <= fold(it[1]) || (f >= it[0] && f <= it[1]); })()));
    return n.negate ? (x) => !test(x) : test;
  };
  // build returns { start, outs[] } with `outs` the dangling exits to patch
  function build(n) {
    switch (n.t) {
      case 'char': case 'any': case 'set': { const s = add({ k: 'char', f: matcherOf(n), out: -1 }); return { start: s, outs: [[s, 'out']] }; }
      case 'bol': { const s = add({ k: 'bol', out: -1 }); return { start: s, outs: [[s, 'out']] }; }
      case 'eol': { const s = add({ k: 'eol', out: -1 }); return { start: s, outs: [[s, 'out']] }; }
      case 'cat': {
        if (n.parts.length === 0) { const s = add({ k: 'split', out: -1, out2: -1, eps: true }); return { start: s, outs: [[s, 'out'], [s, 'out2']] }; }
        let first = null; let prev = null;
        for (const p of n.parts) { const f = build(p); if (!first) first = f; else patch(prev.outs, f.start); prev = f; }
        return { start: first.start, outs: prev.outs };
      }
      case 'alt': {
        const fs = n.alts.map(build);
        let start = fs[fs.length - 1].start; let outs = fs[fs.length - 1].outs.slice();
        for (let k = fs.length - 2; k >= 0; k--) { const s = add({ k: 'split', out: fs[k].start, out2: start }); start = s; outs = outs.concat(fs[k].outs); }
        return { start, outs };
      }
      case 'rep': {
        const { min, max, a } = n; const parts = [];
        const copies = (c) => { for (let k = 0; k < c; k++) parts.push(build(a)); };
        copies(min);
        if (max === Infinity) { const body = build(a); const s = add({ k: 'split', out: body.start, out2: -1 }); patch(body.outs, s); parts.push({ start: s, outs: [[s, 'out2']] }); }
        else for (let k = 0; k < max - min; k++) { const body = build(a); const s = add({ k: 'split', out: body.start, out2: -1 }); parts.push({ start: s, outs: [[s, 'out2']].concat(body.outs) }); }
        if (parts.length === 0) { const s = add({ k: 'split', out: -1, out2: -1 }); return { start: s, outs: [[s, 'out'], [s, 'out2']] }; }
        // chain: each optional copy may exit early, handled because every optional part's outs include its skip exit and the body exits flow into the next part
        let outs = []; let start = parts[0].start;
        for (let k = 0; k < parts.length - 1; k++) { patch(parts[k].outs, parts[k + 1].start); }
        outs = parts[parts.length - 1].outs;
        return { start, outs };
      }
      default: throw new RegexError('internal: unknown node');
    }
  }
  function patch(outs, target) { for (const [idx, key] of outs) states[idx][key] = target; }
  const frag = build(ast);
  const match = add({ k: 'match' });
  patch(frag.outs, match);

  const startState = frag.start;

  function test(text) {
    if (typeof text !== 'string') throw new TypeError('text must be a string');
    if (text.length > MAX_INPUT) throw new RegexError(`the text is longer than ${MAX_INPUT} characters`);
    const cps = []; for (const ch of text) cps.push(ch.codePointAt(0));
    const n = cps.length;
    const mark = new Int32Array(states.length); let stamp = 0;
    let pending = [];
    // adds `s` and everything reachable from it by empty moves to `active`; returns true when the match state is reached
    const close = (s, pos, active) => {
      const stack = [s];
      while (stack.length) {
        const x = stack.pop();
        if (x < 0 || mark[x] === stamp) continue;
        mark[x] = stamp;
        const st = states[x];
        if (st.k === 'match') return true;
        if (st.k === 'split') { stack.push(st.out2, st.out); continue; }
        if (st.k === 'bol') { if (pos === 0) stack.push(st.out); continue; }
        if (st.k === 'eol') { if (pos === n) stack.push(st.out); continue; }
        active.push(x);
      }
      return false;
    };
    for (let pos = 0; pos <= n; pos++) {
      stamp++;
      const active = [];
      for (const t of pending) if (close(t, pos, active)) return true;
      if (close(startState, pos, active)) return true;               // a new attempt may begin anywhere (unanchored search)
      if (pos === n) break;
      pending = [];
      const c = cps[pos];
      for (const x of active) if (states[x].f(c)) pending.push(states[x].out);
    }
    return false;
  }
  return { test, states: states.length };
}

module.exports = { compile, RegexError, MAX_INPUT, MAX_PATTERN, MAX_STATES };
