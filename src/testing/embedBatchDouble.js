'use strict';

// (step 3) — embeddingBackend's documented contract gained embedBatch(texts): every window of one text in ONE
// call, resolving to one 384-dim vector per text, in order. A test double of the backend must honour the contract
// it stands in for (the/B-3 precedent), so this adds embedBatch to any double as the SEQUENTIAL composition of
// that double's own embed(): per-window call counts, argument order and "the first failing window fails the text"
// are exactly what the suites were written against.
module.exports = function withEmbedBatch(backend) {
  return {
    ...backend,
    embedBatch: async (texts) => {
      const out = [];
      for (const t of texts) out.push(await backend.embed(t)); // eslint-disable-line no-await-in-loop
      return out;
    },
  };
};
