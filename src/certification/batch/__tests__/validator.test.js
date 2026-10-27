'use strict';

const { validateCreateBatch } = require('../validator');

function validBody(overrides = {}) {
  return {
    frameworkId: 'SOC2',
    items: [
      { subjectId: 'subject-1', artifacts: [], evidencePackages: [] },
    ],
    ...overrides,
  };
}

// ── Valid requests ─────────────────────────────────────────────────────────────

describe('validateCreateBatch — valid', () => {
  it('accepts minimal valid body', () => {
    expect(validateCreateBatch(validBody())).toBeNull();
  });

  it('accepts multiple items', () => {
    const body = validBody({
      items: [
        { subjectId: 's1' },
        { subjectId: 's2' },
        { subjectId: 's3' },
      ],
    });
    expect(validateCreateBatch(body)).toBeNull();
  });

  it('accepts items with controls object', () => {
    expect(validateCreateBatch(validBody({ items: [{ subjectId: 's1', controls: { policyCompliance: true } }] }))).toBeNull();
  });

  it('accepts items without optional fields', () => {
    expect(validateCreateBatch({ frameworkId: 'ISO27001', items: [{ subjectId: 's1' }] })).toBeNull();
  });
});

// ── Missing/invalid top-level fields ─────────────────────────────────────────

describe('validateCreateBatch — invalid top-level', () => {
  it('rejects null body', () => {
    expect(validateCreateBatch(null)).toBeTruthy();
  });

  it('rejects missing frameworkId', () => {
    expect(validateCreateBatch({ items: [{ subjectId: 's1' }] })).toBeTruthy();
  });

  it('rejects empty frameworkId', () => {
    expect(validateCreateBatch(validBody({ frameworkId: '' }))).toBeTruthy();
  });

  it('rejects missing items', () => {
    expect(validateCreateBatch({ frameworkId: 'SOC2' })).toBeTruthy();
  });

  it('rejects empty items array', () => {
    expect(validateCreateBatch(validBody({ items: [] }))).toBeTruthy();
  });

  it('rejects items exceeding 100', () => {
    const items = Array.from({ length: 101 }, (_, i) => ({ subjectId: `s${i}` }));
    expect(validateCreateBatch(validBody({ items }))).toBeTruthy();
  });
});

// ── Invalid item fields ───────────────────────────────────────────────────────

describe('validateCreateBatch — invalid items', () => {
  it('rejects item without subjectId', () => {
    expect(validateCreateBatch(validBody({ items: [{}] }))).toBeTruthy();
  });

  it('rejects item with empty subjectId', () => {
    expect(validateCreateBatch(validBody({ items: [{ subjectId: '' }] }))).toBeTruthy();
  });

  it('rejects item with non-array artifacts', () => {
    expect(validateCreateBatch(validBody({ items: [{ subjectId: 's1', artifacts: 'bad' }] }))).toBeTruthy();
  });

  it('rejects item with artifacts exceeding 50', () => {
    const artifacts = Array.from({ length: 51 }, () => ({}));
    expect(validateCreateBatch(validBody({ items: [{ subjectId: 's1', artifacts }] }))).toBeTruthy();
  });

  it('rejects item with non-array evidencePackages', () => {
    expect(validateCreateBatch(validBody({ items: [{ subjectId: 's1', evidencePackages: 'bad' }] }))).toBeTruthy();
  });

  it('rejects item with evidencePackages exceeding 50', () => {
    const evidencePackages = Array.from({ length: 51 }, () => ({}));
    expect(validateCreateBatch(validBody({ items: [{ subjectId: 's1', evidencePackages }] }))).toBeTruthy();
  });

  it('rejects item with array controls', () => {
    expect(validateCreateBatch(validBody({ items: [{ subjectId: 's1', controls: [] }] }))).toBeTruthy();
  });

  it('rejects non-object item', () => {
    expect(validateCreateBatch(validBody({ items: ['notanobject'] }))).toBeTruthy();
  });
});
