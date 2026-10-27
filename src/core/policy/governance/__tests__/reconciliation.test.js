'use strict';

/**
 * Governance Publish Reconciliation Tests —
 *
 * GR-01  Skips (returns SKIPPED) when PG is disabled — no query issued
 * GR-02  Clean state: no divergence, emits only GOVERNANCE_RECONCILIATION_COMPLETE
 * GR-03  MISSING_FILE: published policy_id absent from policies.json
 * GR-04  MISSING_PUBLICATION: PUBLISHED change request with no policy_publications row
 * GR-05  VERSION_MISMATCH: file currentVersion != latest publication's resulting version
 * GR-06  HASH_MISMATCH: file snapshot hash != policy_provenance_versions.policy_hash
 * GR-07  PUBLICATION_STATE_INCONSISTENT: orphaned publication (change request not PUBLISHED)
 * GR-08  PUBLICATION_STATE_INCONSISTENT: duplicate publications for one change request
 * GR-09  PUBLICATION_STATE_INCONSISTENT: missing provenance row for a published version
 * GR-10  Never issues a mutating statement (no INSERT/UPDATE/DELETE in any query call)
 * GR-11  A query failure emits GOVERNANCE_RECONCILIATION_FAILED, never throws
 */

const { reconcile, DIVERGENCE_TYPE } = require('../reconciliation');

function makePool({ enabled = true, routes = {} } = {}) {
  const calls = [];
  return {
    isEnabled: () => enabled,
    query: jest.fn(async (sql, params, label) => {
      calls.push({ sql, params, label });
      if (label in routes) return routes[label];
      // Default: empty result set for any unrouted label.
      return { rows: [] };
    }),
    __calls: calls,
  };
}

const CLEAN_ROUTES = {
  governance_reconcile_latest_published:        { rows: [] },
  governance_reconcile_orphaned_publications:    { rows: [] },
  governance_reconcile_duplicate_publications:   { rows: [] },
  governance_reconcile_publication_count:        { rows: [{ total: '0' }] },
};

const fakeProvenance = {
  computePolicyHash: jest.fn(() => 'file-hash-abc'),
};

const fakePolicyStore = {
  getPolicy: jest.fn(),
};

beforeEach(() => {
  fakeProvenance.computePolicyHash.mockReset().mockReturnValue('file-hash-abc');
  fakePolicyStore.getPolicy.mockReset();
});

describe('GR-01: PG disabled', () => {
  test('returns SKIPPED and never queries', async () => {
    const _pool = makePool({ enabled: false });
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(result.outcome).toBe('SKIPPED');
    expect(_pool.query).not.toHaveBeenCalled();
  });
});

describe('GR-02: clean state', () => {
  test('emits only GOVERNANCE_RECONCILIATION_COMPLETE with outcome CLEAN', async () => {
    const _pool = makePool({ routes: CLEAN_ROUTES });
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(result.outcome).toBe('CLEAN');
    expect(result.mismatches).toBe(0);
    const divergenceCalls = _emit.mock.calls.filter(c => c[1] === 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED');
    expect(divergenceCalls).toHaveLength(0);
    expect(_emit).toHaveBeenCalledWith('INFO', 'GOVERNANCE_RECONCILIATION_COMPLETE', expect.objectContaining({ outcome: 'CLEAN' }));
  });
});

describe('GR-03: MISSING_FILE', () => {
  test('published policy_id absent from policies.json', async () => {
    const _pool = makePool({
      routes: {
        ...CLEAN_ROUTES,
        governance_reconcile_latest_published: {
          rows: [{ change_request_id: 'cr-1', policy_id: 'pol-ghost', publication_id: 'pub-1', pub_resulting_version: 2, pub_policy_hash: 'x', published_at: new Date() }],
        },
      },
    });
    fakePolicyStore.getPolicy.mockReturnValue(null);
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(result.mismatches).toBe(1);
    expect(_emit).toHaveBeenCalledWith('WARN', 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED',
      expect.objectContaining({ divergenceType: DIVERGENCE_TYPE.MISSING_FILE, policyId: 'pol-ghost' }));
  });
});

describe('GR-04: MISSING_PUBLICATION', () => {
  test('PUBLISHED change request with no matching policy_publications row', async () => {
    const _pool = makePool({
      routes: {
        ...CLEAN_ROUTES,
        governance_reconcile_latest_published: {
          rows: [{ change_request_id: 'cr-2', policy_id: 'pol-a', publication_id: null, pub_resulting_version: null, pub_policy_hash: null, published_at: null }],
        },
      },
    });
    fakePolicyStore.getPolicy.mockReturnValue({ id: 'pol-a', currentVersion: 2, versions: [] });
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(result.mismatches).toBe(1);
    expect(_emit).toHaveBeenCalledWith('WARN', 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED',
      expect.objectContaining({ divergenceType: DIVERGENCE_TYPE.MISSING_PUBLICATION, policyId: 'pol-a' }));
  });
});

describe('GR-05: VERSION_MISMATCH', () => {
  test('file currentVersion differs from latest publication resulting_policy_version', async () => {
    const _pool = makePool({
      routes: {
        ...CLEAN_ROUTES,
        governance_reconcile_latest_published: {
          rows: [{ change_request_id: 'cr-3', policy_id: 'pol-b', publication_id: 'pub-3', pub_resulting_version: 4, pub_policy_hash: 'h4', published_at: new Date() }],
        },
        governance_reconcile_provenance_lookup: { rows: [{ policy_hash: 'file-hash-abc' }] },
      },
    });
    fakePolicyStore.getPolicy.mockReturnValue({
      id: 'pol-b', currentVersion: 3, versions: [{ v: 3, snapshot: { id: 'pol-b' } }],
    });
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(_emit).toHaveBeenCalledWith('WARN', 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED',
      expect.objectContaining({ divergenceType: DIVERGENCE_TYPE.VERSION_MISMATCH, policyId: 'pol-b' }));
    expect(result.mismatches).toBeGreaterThanOrEqual(1);
  });
});

describe('GR-06: HASH_MISMATCH', () => {
  test('recomputed file snapshot hash differs from policy_provenance_versions.policy_hash', async () => {
    const _pool = makePool({
      routes: {
        ...CLEAN_ROUTES,
        governance_reconcile_latest_published: {
          rows: [{ change_request_id: 'cr-4', policy_id: 'pol-c', publication_id: 'pub-4', pub_resulting_version: 2, pub_policy_hash: 'payload-hash', published_at: new Date() }],
        },
        governance_reconcile_provenance_lookup: { rows: [{ policy_hash: 'expected-content-hash' }] },
      },
    });
    fakePolicyStore.getPolicy.mockReturnValue({
      id: 'pol-c', currentVersion: 2, versions: [{ v: 2, snapshot: { id: 'pol-c', config: { tampered: true } } }],
    });
    fakeProvenance.computePolicyHash.mockReturnValue('different-actual-hash');
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(_emit).toHaveBeenCalledWith('WARN', 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED',
      expect.objectContaining({
        divergenceType: DIVERGENCE_TYPE.HASH_MISMATCH,
        policyId:       'pol-c',
        expectedHash:   'expected-content-hash',
        actualHash:     'different-actual-hash',
      }));
    expect(result.mismatches).toBe(1);
  });
});

describe('GR-07 … GR-09: PUBLICATION_STATE_INCONSISTENT', () => {
  test('GR-07 orphaned publication (change request not PUBLISHED)', async () => {
    const _pool = makePool({
      routes: {
        ...CLEAN_ROUTES,
        governance_reconcile_orphaned_publications: {
          rows: [{ publication_id: 'pub-5', change_request_id: 'cr-5', policy_id: 'pol-d', cr_status: 'REJECTED' }],
        },
      },
    });
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(result.mismatches).toBe(1);
    expect(_emit).toHaveBeenCalledWith('WARN', 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED',
      expect.objectContaining({ divergenceType: DIVERGENCE_TYPE.PUBLICATION_STATE_INCONSISTENT, policyId: 'pol-d' }));
  });

  test('GR-08 duplicate publications for one change request', async () => {
    const _pool = makePool({
      routes: {
        ...CLEAN_ROUTES,
        governance_reconcile_duplicate_publications: {
          rows: [{ change_request_id: 'cr-6', publication_count: '2' }],
        },
      },
    });
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(result.mismatches).toBe(1);
    expect(_emit).toHaveBeenCalledWith('WARN', 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED',
      expect.objectContaining({ divergenceType: DIVERGENCE_TYPE.PUBLICATION_STATE_INCONSISTENT }));
  });

  test('GR-09 missing provenance row for a published version', async () => {
    const _pool = makePool({
      routes: {
        ...CLEAN_ROUTES,
        governance_reconcile_latest_published: {
          rows: [{ change_request_id: 'cr-7', policy_id: 'pol-e', publication_id: 'pub-7', pub_resulting_version: 1, pub_policy_hash: 'h', published_at: new Date() }],
        },
        governance_reconcile_provenance_lookup: { rows: [] },
      },
    });
    fakePolicyStore.getPolicy.mockReturnValue({ id: 'pol-e', currentVersion: 1, versions: [{ v: 1, snapshot: {} }] });
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(result.mismatches).toBe(1);
    expect(_emit).toHaveBeenCalledWith('WARN', 'GOVERNANCE_RECONCILIATION_DIVERGENCE_DETECTED',
      expect.objectContaining({ divergenceType: DIVERGENCE_TYPE.PUBLICATION_STATE_INCONSISTENT, policyId: 'pol-e' }));
  });
});

describe('GR-10: read-only', () => {
  test('never issues a mutating statement', async () => {
    const _pool = makePool({
      routes: {
        ...CLEAN_ROUTES,
        governance_reconcile_latest_published: {
          rows: [{ change_request_id: 'cr-8', policy_id: 'pol-f', publication_id: 'pub-8', pub_resulting_version: 1, pub_policy_hash: 'h', published_at: new Date() }],
        },
        governance_reconcile_provenance_lookup: { rows: [{ policy_hash: 'file-hash-abc' }] },
      },
    });
    fakePolicyStore.getPolicy.mockReturnValue({ id: 'pol-f', currentVersion: 1, versions: [{ v: 1, snapshot: {} }] });

    await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit: jest.fn() });

    for (const call of _pool.__calls) {
      expect(call.sql).toMatch(/^\s*SELECT/i);
    }
  });
});

describe('GR-11: query failure', () => {
  test('emits GOVERNANCE_RECONCILIATION_FAILED and returns FAILED, never throws', async () => {
    const _pool = {
      isEnabled: () => true,
      query: jest.fn().mockRejectedValue(new Error('connection reset')),
    };
    const _emit = jest.fn();

    const result = await reconcile({ _pool, _policyStore: fakePolicyStore, _provenance: fakeProvenance, _emit });

    expect(result.outcome).toBe('FAILED');
    expect(_emit).toHaveBeenCalledWith('ERROR', 'GOVERNANCE_RECONCILIATION_FAILED', expect.objectContaining({ error: 'connection reset' }));
  });
});
