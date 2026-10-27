'use strict';

const vm = require('vm');

/**
 * Finds the index of the `)` that closes the `(` at `openIdx`, by simple
 * depth counting. This is a text-window extractor, not a full parser — it
 * assumes (true for every call site it's used against in this repo) that
 * the object literal between the parens contains no nested function bodies
 * or string literals with unbalanced parentheses, both of which would
 * defeat naive depth counting.
 */
function findMatchingParen(source, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < source.length; i++) {
    const ch = source[i];
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Finds every `<expr>.sign.sign(<object literal>)` call in `source` whose
 * argument object contains a quoted '/ai/chat' path, extracts the raw
 * object-literal source text, and evaluates it with `vm` against `context`
 * (stubbing any free variables the literal references) to materialize the
 * *actual* JS object the example would send over the wire — not a
 * hand-copied duplicate of it.
 *
 * Throws (rather than returning an empty/partial result) if a matched call
 * can't be parsed or evaluated — a silent skip here would defeat the whole
 * point of deriving expectations from the real source file.
 */
function extractAiChatSignRequests(source, context = {}) {
  const results = [];
  const callRegex = /\.sign\.sign\s*\(/g;
  let m;
  while ((m = callRegex.exec(source)) !== null) {
    const openIdx = m.index + m[0].length - 1;
    const closeIdx = findMatchingParen(source, openIdx);
    if (closeIdx === -1) {
      throw new Error(`Unbalanced parentheses extracting a .sign.sign() call at offset ${m.index}`);
    }
    const argsSrc = source.slice(openIdx + 1, closeIdx);
    if (!/['"`]\/ai\/chat['"`]/.test(argsSrc)) continue;

    const sandbox = { ...context };
    vm.createContext(sandbox);
    let value;
    try {
      value = vm.runInContext(`(${argsSrc})`, sandbox, { timeout: 1000 });
    } catch (err) {
      throw new Error(
        `Failed to evaluate extracted .sign.sign() argument at offset ${m.index}: ${err.message}\n---\n${argsSrc}\n---`,
      );
    }
    results.push(value);
  }
  return results;
}

/** Extracts the content of every ```<lang>\n...``` fenced block in `markdown`. */
function extractFencedBlocks(markdown, lang) {
  const re = new RegExp('```' + lang + '\\n([\\s\\S]*?)```', 'g');
  const blocks = [];
  let m;
  while ((m = re.exec(markdown)) !== null) blocks.push(m[1]);
  return blocks;
}

module.exports = { extractAiChatSignRequests, extractFencedBlocks };
