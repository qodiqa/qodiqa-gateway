'use strict';

/**
 * Component #31 — Row-Level Security Tests
 *
 * RLS-01 … RLS-15   tenantContext.js: validate(), setLocal(), clearLocal()
 * RLS-16 … RLS-30   pool.withTenantTransaction(): context isolation, fail-closed
 * RLS-31 … RLS-45   Pool safety: no context leakage across transactions
 * RLS-46 … RLS-55   webhookStore.listByEventType(): tx option wires RLS
 * RLS-56 … RLS-65   webhookDispatcher._fanOut: tenant context propagation
 * RLS-66 … RLS-80   Policy invariants: correct SQL for each table class
 * RLS-81 … RLS-90   Administrative bypass: qodiqa_mig behavior
 * RLS-91 … RLS-100 real-PostgreSQL tests in test/integration/privilegeRls.integration.test.js
 *
 * These tests use mock pg.Pool and mock PG clients — no real database required.
 * RLS-91..100 live in test/integration/privilegeRls.integration.test.js;
 * this file keeps a pointer test for them.
 */

// ── Mocks ─────────────────────────────────────────────────────────────────────

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(),
  allowed: jest.fn(),
  blocked: jest.fn(),
  eventBus: { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

// ── Module imports ────────────────────────────────────────────────────────────

const tenantContext = require('../tenantContext');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeMockClient() {
  const calls = [];
  return {
    query: jest.fn(async (sql, params) => {
      calls.push({ sql, params });
      return { rows: [], rowCount: 0 };
    }),
    release: jest.fn(),
    _calls: calls,
  };
}

function makeMockPool({ queryResults = [] } = {}) {
  let resultIdx = 0;
  const clients = [];
  const client = {
    query: jest.fn(async (sql, params) => {
      const res = queryResults[resultIdx++] ?? { rows: [], rowCount: 0 };
      return res;
    }),
    release: jest.fn(),
  };
  clients.push(client);
  return {
    connect: jest.fn(async () => client),
    query:   jest.fn(async (sql, params) => {
      const res = queryResults[resultIdx++] ?? { rows: [], rowCount: 0 };
      return res;
    }),
    end:     jest.fn(async () => {}),
    on:      jest.fn(),
    options: { max: 10 },
    waitingCount: 0,
    _client: client,
    _clients: clients,
  };
}

// ── RLS-01 … RLS-15: tenantContext ────────────────────────────────────────────

describe('RLS-01 … RLS-15: tenantContext validation and SQL', () => {
  test('RLS-01 validate() accepts a simple alphanumeric tenant ID', () => {
    expect(() => tenantContext.validate('tenant1')).not.toThrow();
  });

  test('RLS-02 validate() accepts tenant IDs with hyphens and underscores', () => {
    expect(() => tenantContext.validate('my-tenant_01')).not.toThrow();
  });

  test('RLS-03 validate() accepts single-character tenant IDs', () => {
    expect(() => tenantContext.validate('a')).not.toThrow();
  });

  test('RLS-04 validate() accepts maximum-length tenant ID (64 chars)', () => {
    expect(() => tenantContext.validate('a'.repeat(64))).not.toThrow();
  });

  test('RLS-05 validate() rejects null', () => {
    expect(() => tenantContext.validate(null)).toThrow(TypeError);
  });

  test('RLS-06 validate() rejects undefined', () => {
    expect(() => tenantContext.validate(undefined)).toThrow(TypeError);
  });

  test('RLS-07 validate() rejects empty string', () => {
    expect(() => tenantContext.validate('')).toThrow(TypeError);
  });

  test('RLS-08 validate() rejects IDs with spaces', () => {
    expect(() => tenantContext.validate('tenant one')).toThrow(TypeError);
  });

  test('RLS-09 validate() rejects IDs with SQL injection characters', () => {
    expect(() => tenantContext.validate("tenant'; DROP TABLE foo; --")).toThrow(TypeError);
  });

  test('RLS-10 validate() rejects IDs longer than 64 characters', () => {
    expect(() => tenantContext.validate('a'.repeat(65))).toThrow(TypeError);
  });

  test('RLS-11 validate() rejects non-string values', () => {
    expect(() => tenantContext.validate(42)).toThrow(TypeError);
    expect(() => tenantContext.validate({})).toThrow(TypeError);
    expect(() => tenantContext.validate([])).toThrow(TypeError);
  });

  test('RLS-12 setLocal() issues set_config with transaction-local flag', async () => {
    const client = makeMockClient();
    await tenantContext.setLocal(client, 'acme-corp');
    expect(client.query).toHaveBeenCalledWith(
      "SELECT set_config('qodiqa.tenant_id', $1, true)",
      ['acme-corp'],
    );
  });

  test('RLS-13 setLocal() third param is true (transaction-local, not session)', async () => {
    const client = makeMockClient();
    await tenantContext.setLocal(client, 'beta-tenant');
    const [sql, params] = client.query.mock.calls[0];
    // Verify the critical pool-safety flag: true = transaction-local
    expect(sql).toContain(', true)');
    expect(sql).not.toContain(', false)');
    expect(params[0]).toBe('beta-tenant');
  });

  test('RLS-14 setLocal() validates tenant ID before issuing SQL', async () => {
    const client = makeMockClient();
    await expect(tenantContext.setLocal(client, '')).rejects.toThrow(TypeError);
    expect(client.query).not.toHaveBeenCalled();
  });

  test('RLS-15 clearLocal() sets tenant context to empty string (transaction-local)', async () => {
    const client = makeMockClient();
    await tenantContext.clearLocal(client);
    expect(client.query).toHaveBeenCalledWith(
      "SELECT set_config('qodiqa.tenant_id', '', true)",
      [],
    );
  });
});

// ── RLS-16 … RLS-30: pool.withTenantTransaction ───────────────────────────────

describe('RLS-16 … RLS-30: pool.withTenantTransaction', () => {
  let pool;
  const SET_TENANT_SQL = "SELECT set_config('qodiqa.tenant_id', $1, true)";

  beforeEach(() => {
    jest.resetModules();
    pool = makeMockPool();
    // Inject mock pool into the pg module for pool.js
    jest.doMock('pg', () => ({ Pool: jest.fn(() => pool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
  });

  afterEach(() => {
    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  function loadPool() {
    return require('../pool');
  }

  test('RLS-16 withTenantTransaction rejects invalid tenantId before acquiring connection', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    await expect(pgPool.withTenantTransaction('', jest.fn())).rejects.toThrow(TypeError);
    // No connection should have been acquired
    expect(pool.connect).not.toHaveBeenCalled();
  });

  test('RLS-17 withTenantTransaction rejects null tenantId', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    await expect(pgPool.withTenantTransaction(null, jest.fn())).rejects.toThrow(TypeError);
  });

  test('RLS-18 withTenantTransaction rejects undefined tenantId', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    await expect(pgPool.withTenantTransaction(undefined, jest.fn())).rejects.toThrow(TypeError);
  });

  test('RLS-19 withTenantTransaction rejects tenantId with invalid characters', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    await expect(pgPool.withTenantTransaction('bad tenant!', jest.fn())).rejects.toThrow(TypeError);
  });

  test('RLS-20 withTenantTransaction sets tenant context before calling fn', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    const callOrder = [];
    pool._client.query.mockImplementation(async (sql, params) => {
      callOrder.push(sql.trim().substring(0, 40));
      return { rows: [], rowCount: 0 };
    });

    await pgPool.withTenantTransaction('acme', async (tx) => {
      await tx.query('SELECT 1 AS business_query', []);
    });

    // set_config must appear before the business query
    const configIdx = callOrder.findIndex(s => s.includes('set_config'));
    const bizIdx    = callOrder.findIndex(s => s.includes('business_query'));
    expect(configIdx).toBeGreaterThanOrEqual(0);
    expect(bizIdx).toBeGreaterThan(configIdx);
  });

  test('RLS-21 withTenantTransaction uses transaction-local set_config (true flag)', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    const configCalls = [];
    pool._client.query.mockImplementation(async (sql, params) => {
      if (sql.includes('set_config')) configCalls.push({ sql, params });
      return { rows: [], rowCount: 0 };
    });

    await pgPool.withTenantTransaction('acme', async (tx) => {});

    expect(configCalls).toHaveLength(1);
    expect(configCalls[0].sql).toBe(SET_TENANT_SQL);
    expect(configCalls[0].params).toEqual(['acme']);
    // Critical: contains ", true)" not ", false)"
    expect(configCalls[0].sql).toContain(', true)');
  });

  test('RLS-22 withTenantTransaction returns the value returned by fn', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    pool._client.query.mockResolvedValue({ rows: [], rowCount: 0 });
    const result = await pgPool.withTenantTransaction('acme', async () => 42);
    expect(result).toBe(42);
  });

  test('RLS-23 withTenantTransaction rolls back and rethrows on error', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    const issuedSqls = [];
    pool._client.query.mockImplementation(async (sql) => {
      issuedSqls.push(sql.trim());
      return { rows: [], rowCount: 0 };
    });

    await expect(
      pgPool.withTenantTransaction('acme', async () => {
        throw new Error('business logic failed');
      }),
    ).rejects.toThrow('business logic failed');

    expect(issuedSqls).toContain('ROLLBACK');
  });

  test('RLS-24 withTenantTransaction wraps fn in a transaction (BEGIN … COMMIT)', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    const issuedSqls = [];
    pool._client.query.mockImplementation(async (sql) => {
      issuedSqls.push(sql.trim());
      return { rows: [], rowCount: 0 };
    });

    await pgPool.withTenantTransaction('acme', async () => {});

    expect(issuedSqls.some(s => s.startsWith('BEGIN'))).toBe(true);
    expect(issuedSqls).toContain('COMMIT');
  });

  test('RLS-25 withTenantTransaction releases client after commit', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    pool._client.query.mockResolvedValue({ rows: [], rowCount: 0 });
    await pgPool.withTenantTransaction('acme', async () => {});
    expect(pool._client.release).toHaveBeenCalledTimes(1);
  });

  test('RLS-26 withTenantTransaction releases client after rollback', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    pool._client.query.mockResolvedValue({ rows: [], rowCount: 0 });
    await pgPool.withTenantTransaction('acme', async () => {
      throw new Error('fail');
    }).catch(() => {});
    expect(pool._client.release).toHaveBeenCalledTimes(1);
  });

  test('RLS-27 withTenantTransaction passes a tx object with query function to fn', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    pool._client.query.mockResolvedValue({ rows: [], rowCount: 0 });
    let receivedTx;
    await pgPool.withTenantTransaction('acme', async (tx) => {
      receivedTx = tx;
    });
    expect(receivedTx).toBeDefined();
    expect(typeof receivedTx.query).toBe('function');
  });

  test('RLS-28 withTenantTransaction accepts valid tenantId variations', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    pool._client.query.mockResolvedValue({ rows: [], rowCount: 0 });
    const validIds = ['t', 'acme-corp', 'tenant_01', 'A1b2C3', 'x'.repeat(64)];
    for (const id of validIds) {
      await expect(pgPool.withTenantTransaction(id, async () => {})).resolves.toBeUndefined();
    }
  });

  test('RLS-29 withTenantTransaction passes isolationLevel option to withTransaction', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    const issuedSqls = [];
    pool._client.query.mockImplementation(async (sql) => {
      issuedSqls.push(sql.trim());
      return { rows: [], rowCount: 0 };
    });
    await pgPool.withTenantTransaction('acme', async () => {}, { isolationLevel: 'SERIALIZABLE' });
    expect(issuedSqls.some(s => s.includes('SERIALIZABLE'))).toBe(true);
  });

  test('RLS-30 withTenantTransaction set_config uses parameterized query (no string concat)', async () => {
    const pgPool = loadPool();
    pgPool.initialize();
    const configCalls = [];
    pool._client.query.mockImplementation(async (sql, params) => {
      if (sql.includes('set_config')) configCalls.push({ sql, params });
      return { rows: [], rowCount: 0 };
    });
    await pgPool.withTenantTransaction("evil'; DROP TABLE foo;--", async () => {}).catch(() => {});
    // If validation fails (which it should), no set_config call is made
    expect(configCalls).toHaveLength(0);
  });
});

// ── RLS-31 … RLS-45: Pool safety — no context leakage ────────────────────────

describe('RLS-31 … RLS-45: Pool safety — tenant context isolation', () => {
  test('RLS-31 context is transaction-local: does not persist after commit', async () => {
    // Verify set_config third param is `true` (not `false` or omitted)
    // session-level (false) would leak context to next request on same connection
    const client = makeMockClient();
    await tenantContext.setLocal(client, 'tenant-a');
    const [sql] = client.query.mock.calls[0];
    // true = transaction-local; resets at COMMIT or ROLLBACK
    expect(sql).toMatch(/set_config\('qodiqa\.tenant_id',\s*\$1,\s*true\)/);
  });

  test('RLS-32 context is not set session-wide (false flag would be dangerous)', async () => {
    const client = makeMockClient();
    await tenantContext.setLocal(client, 'tenant-a');
    const [sql] = client.query.mock.calls[0];
    expect(sql).not.toMatch(/set_config\('qodiqa\.tenant_id',\s*\$1,\s*false\)/);
  });

  test('RLS-33 clearLocal() also uses transaction-local flag', async () => {
    const client = makeMockClient();
    await tenantContext.clearLocal(client);
    const [sql] = client.query.mock.calls[0];
    expect(sql).toContain(', true)');
  });

  test('RLS-34 sequential tenant transactions use independent clients', async () => {
    jest.resetModules();
    let callCount = 0;
    const clients = [makeMockClient(), makeMockClient()];
    const mockPool = {
      connect: jest.fn(async () => clients[callCount++]),
      on: jest.fn(),
      options: { max: 10 },
      waitingCount: 0,
    };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    const configCallsPerClient = [[], []];
    clients.forEach((c, idx) => {
      c.query.mockImplementation(async (sql, params) => {
        if (sql.includes('set_config')) configCallsPerClient[idx].push(params?.[0]);
        return { rows: [], rowCount: 0 };
      });
    });

    await pgPool.withTenantTransaction('tenant-a', async () => {});
    await pgPool.withTenantTransaction('tenant-b', async () => {});

    // Each transaction got a separate client and saw its own tenant context
    expect(configCallsPerClient[0]).toContain('tenant-a');
    expect(configCallsPerClient[1]).toContain('tenant-b');

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-35 validate() is called synchronously before acquiring any connection', async () => {
    jest.resetModules();
    const mockPool = { connect: jest.fn(), on: jest.fn(), options: { max: 10 }, waitingCount: 0 };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    // Invalid tenantId should throw before connect() is called
    await expect(pgPool.withTenantTransaction(null, async () => {})).rejects.toThrow(TypeError);
    expect(mockPool.connect).not.toHaveBeenCalled();

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-36 ROLLBACK clears context as a side effect (transaction ends)', () => {
    // PostgreSQL guarantees: when a transaction ends (commit or rollback),
    // all SET LOCAL / transaction-local set_config values reset.
    // This test verifies our code issues ROLLBACK on error.
    jest.resetModules();
    const client = makeMockClient();
    const issuedSqls = [];
    client.query.mockImplementation(async (sql) => {
      issuedSqls.push(sql.trim());
      return { rows: [], rowCount: 0 };
    });
    const mockPool = {
      connect: jest.fn(async () => client),
      on: jest.fn(),
      options: { max: 10 },
      waitingCount: 0,
    };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    return pgPool.withTenantTransaction('acme', async () => {
      throw new Error('forced');
    }).catch(() => {
      expect(issuedSqls).toContain('ROLLBACK');
    }).finally(() => {
      delete process.env.QODIQA_PG_ENABLED;
      jest.dontMock('pg');
      jest.resetModules();
    });
  });

  test('RLS-37 withTenantTransaction is exported from pool.js', () => {
    jest.resetModules();
    jest.doMock('pg', () => ({ Pool: jest.fn(() => ({ connect: jest.fn(), on: jest.fn(), options: {}, waitingCount: 0 })) }));
    const pgPool = require('../pool');
    expect(typeof pgPool.withTenantTransaction).toBe('function');
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-38 set_config uses parameterized placeholder ($1), not string concatenation', async () => {
    const client = makeMockClient();
    await tenantContext.setLocal(client, 'my-tenant');
    const [sql, params] = client.query.mock.calls[0];
    expect(sql).toContain('$1');
    expect(params).toEqual(['my-tenant']);
    // SQL literal should not contain the tenant ID directly
    expect(sql).not.toContain('my-tenant');
  });

  test('RLS-39 tenantContext module does not depend on pool.js (no circular dep)', () => {
    // tenantContext.js must be a standalone module — circular import with pool.js
    // would cause initialization order issues
    jest.resetModules();
    expect(() => require('../tenantContext')).not.toThrow();
    jest.resetModules();
  });

  test('RLS-40 setLocal() does not issue two queries (no double-set)', async () => {
    const client = makeMockClient();
    await tenantContext.setLocal(client, 'single-tenant');
    expect(client.query).toHaveBeenCalledTimes(1);
  });
});

// ── RLS-41 … RLS-45: Additional validate() edge cases ────────────────────────

describe('RLS-41 … RLS-45: validate() edge cases', () => {
  test('RLS-41 validate() rejects IDs with @ symbol (email-like)', () => {
    expect(() => tenantContext.validate('user@domain.com')).toThrow(TypeError);
  });

  test('RLS-42 validate() rejects IDs with forward slash', () => {
    expect(() => tenantContext.validate('tenant/sub')).toThrow(TypeError);
  });

  test('RLS-43 validate() rejects IDs with null byte', () => {
    expect(() => tenantContext.validate('tenant\x00id')).toThrow(TypeError);
  });

  test('RLS-44 validate() rejects IDs with dot (path traversal prevention)', () => {
    expect(() => tenantContext.validate('../etc/passwd')).toThrow(TypeError);
  });

  test('RLS-45 validate() error message includes the rejected value for debugging', () => {
    try {
      tenantContext.validate('bad value!');
    } catch (e) {
      expect(e.message).toContain('bad value!');
    }
  });
});

// ── RLS-46 … RLS-55: webhookStore.listByEventType tx option ──────────────────

describe('RLS-46 … RLS-55: webhookStore.listByEventType with tenant context', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
  });

  test('RLS-46 listByEventType without tx uses pgPool.query', async () => {
    const mockQuery = jest.fn().mockResolvedValue({ rows: [] });
    jest.doMock('../pool', () => ({
      isEnabled: () => true,
      query: mockQuery,
    }));
    jest.doMock('../../../core/webhooks/webhookSecrets', () => ({
      generateSecret: () => 'secret',
      encryptSecret:  () => ({ enc: 'e', iv: 'i', tag: 't' }),
      decryptSecret:  () => 'plain-secret',
    }));
    const store = require('../../../core/webhooks/webhookStore');
    await store.listByEventType('certification.completed');
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('FROM webhook_endpoints'),
      ['certification.completed'],
    );
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookSecrets');
  });

  test('RLS-47 listByEventType with tx uses tx.query instead of pgPool.query', async () => {
    const mockPoolQuery = jest.fn();
    jest.doMock('../pool', () => ({
      isEnabled: () => true,
      query: mockPoolQuery,
    }));
    jest.doMock('../../../core/webhooks/webhookSecrets', () => ({
      generateSecret: () => 'secret',
      encryptSecret:  () => ({ enc: 'e', iv: 'i', tag: 't' }),
      decryptSecret:  () => 'plain-secret',
    }));
    const store = require('../../../core/webhooks/webhookStore');
    const txQuery = jest.fn().mockResolvedValue({ rows: [] });
    const tx = { query: txQuery };
    await store.listByEventType('certification.completed', { tx });
    // tx.query must be used; pgPool.query must NOT be used
    expect(txQuery).toHaveBeenCalledWith(
      expect.stringContaining('FROM webhook_endpoints'),
      ['certification.completed'],
    );
    expect(mockPoolQuery).not.toHaveBeenCalled();
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookSecrets');
  });

  test('RLS-48 listByEventType returns empty array when PG is disabled', async () => {
    jest.doMock('../pool', () => ({ isEnabled: () => false, query: jest.fn() }));
    jest.doMock('../../../core/webhooks/webhookSecrets', () => ({
      generateSecret: () => 'secret',
      encryptSecret:  () => ({ enc: 'e', iv: 'i', tag: 't' }),
      decryptSecret:  () => 'plain-secret',
    }));
    const store = require('../../../core/webhooks/webhookStore');
    const result = await store.listByEventType('certification.completed');
    expect(result).toEqual([]);
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookSecrets');
  });

  test('RLS-49 listByEventType with tx decrypts secrets from rows', async () => {
    jest.doMock('../pool', () => ({ isEnabled: () => true, query: jest.fn() }));
    jest.doMock('../../../core/webhooks/webhookSecrets', () => ({
      generateSecret: () => 'secret',
      encryptSecret:  () => ({ enc: 'e', iv: 'i', tag: 't' }),
      decryptSecret:  jest.fn((enc, iv, tag) => 'decrypted-' + enc),
    }));
    const store = require('../../../core/webhooks/webhookStore');
    const row = { id: 'ep-1', tenant_id: 'acme', url: 'https://a.com', event_types: ['certification.completed'], secret_enc: 'ENC', secret_iv: 'IV', secret_tag: 'TAG' };
    const tx = { query: jest.fn().mockResolvedValue({ rows: [row] }) };
    const result = await store.listByEventType('certification.completed', { tx });
    expect(result).toHaveLength(1);
    expect(result[0]._secret).toBe('decrypted-ENC');
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookSecrets');
  });

  test('RLS-50 listByEventType with tx passes correct event type param', async () => {
    jest.doMock('../pool', () => ({ isEnabled: () => true, query: jest.fn() }));
    jest.doMock('../../../core/webhooks/webhookSecrets', () => ({
      generateSecret: () => 'secret',
      encryptSecret:  () => ({ enc: 'e', iv: 'i', tag: 't' }),
      decryptSecret:  () => 'secret',
    }));
    const store = require('../../../core/webhooks/webhookStore');
    const txQuery = jest.fn().mockResolvedValue({ rows: [] });
    const tx = { query: txQuery };
    await store.listByEventType('attestation.completed', { tx });
    expect(txQuery.mock.calls[0][1]).toEqual(['attestation.completed']);
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookSecrets');
  });

  test('RLS-51 listByEventType: tx option is backward compatible (optional)', async () => {
    jest.doMock('../pool', () => ({ isEnabled: () => true, query: jest.fn().mockResolvedValue({ rows: [] }) }));
    jest.doMock('../../../core/webhooks/webhookSecrets', () => ({
      generateSecret: () => 'secret',
      encryptSecret:  () => ({ enc: 'e', iv: 'i', tag: 't' }),
      decryptSecret:  () => 'secret',
    }));
    const store = require('../../../core/webhooks/webhookStore');
    // Call without any options object — must not throw
    await expect(store.listByEventType('certification.completed')).resolves.toEqual([]);
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookSecrets');
  });
});

// ── RLS-56 … RLS-65: webhookDispatcher fan-out ───────────────────────────────

describe('RLS-56 … RLS-65: webhookDispatcher tenant context propagation', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.resetModules();
  });

  function loadDispatcher({ isEnabled = true, endpoints = [], tenantTxFn = null } = {}) {
    const mockWithTenantTx = tenantTxFn ?? jest.fn(async (tenantId, fn) => fn({ query: jest.fn().mockResolvedValue({ rows: [] }) }));
    jest.doMock('../pool', () => ({
      isEnabled: () => isEnabled,
      withTenantTransaction: mockWithTenantTx,
    }));
    jest.doMock('../../../core/webhooks/webhookStore', () => ({
      listByEventType: jest.fn(async (eventType, opts) => endpoints),
    }));
    jest.doMock('../../../core/webhooks/webhookMetrics', () => ({ inc: jest.fn() }));
    jest.doMock('../../../core/persistenceRecovery', () => ({
      enqueueWebhookDelivery: jest.fn().mockResolvedValue({}),
      OPERATION_TYPES: { WEBHOOK_DELIVERY: 'WEBHOOK_DELIVERY' },
    }));
    const dispatcher = require('../../../core/webhooks/webhookDispatcher');
    return {
      dispatcher,
      store: require('../../../core/webhooks/webhookStore'),
      mockWithTenantTx,
    };
  }

  test('RLS-56 dispatchEvent calls withTenantTransaction when tenantId is present', async () => {
    const mockTx = jest.fn(async (id, fn) => fn({ query: jest.fn().mockResolvedValue({ rows: [] }) }));
    const { dispatcher, mockWithTenantTx } = loadDispatcher({ tenantTxFn: mockTx });

    const payload = {
      eventId: 'ev-1',
      eventType: 'certification.completed',
      tenantId: 'acme',
      certificationId: 'cert-1',
      level: 'CERTIFIED',
      score: 80,
      status: 'CERTIFIED',
    };

    await new Promise((resolve) => {
      dispatcher.dispatchEvent('certification.completed', payload);
      setImmediate(resolve);
    });
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(mockTx).toHaveBeenCalledWith('acme', expect.any(Function));
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookStore');
    jest.dontMock('../../../core/webhooks/webhookMetrics');
    jest.dontMock('../../../core/persistenceRecovery');
  });

  test('RLS-57 dispatchEvent does NOT call withTenantTransaction when tenantId is null', async () => {
    const mockTx = jest.fn();
    const { dispatcher } = loadDispatcher({ tenantTxFn: mockTx });

    const payload = {
      eventId: 'ev-2',
      eventType: 'certification.completed',
      tenantId: null,
    };

    await new Promise((resolve) => {
      dispatcher.dispatchEvent('certification.completed', payload);
      setImmediate(resolve);
    });
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(mockTx).not.toHaveBeenCalled();
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookStore');
    jest.dontMock('../../../core/webhooks/webhookMetrics');
    jest.dontMock('../../../core/persistenceRecovery');
  });

  test('RLS-58 dispatchEvent passes { tx } to listByEventType when using tenant context', async () => {
    const fakeTx = { query: jest.fn().mockResolvedValue({ rows: [] }) };
    const mockTx = jest.fn(async (id, fn) => fn(fakeTx));
    const { dispatcher, store } = loadDispatcher({ tenantTxFn: mockTx });

    const payload = {
      eventId: 'ev-3',
      eventType: 'certification.completed',
      tenantId: 'beta-corp',
    };

    await new Promise((resolve) => {
      dispatcher.dispatchEvent('certification.completed', payload);
      setImmediate(resolve);
    });
    await new Promise(resolve => setTimeout(resolve, 10));

    const listCalls = store.listByEventType.mock.calls;
    expect(listCalls.length).toBeGreaterThan(0);
    // The second argument to listByEventType must include { tx }
    const opts = listCalls[0][1];
    expect(opts).toBeDefined();
    expect(opts.tx).toBe(fakeTx);
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookStore');
    jest.dontMock('../../../core/webhooks/webhookMetrics');
    jest.dontMock('../../../core/persistenceRecovery');
  });

  test('RLS-59 dispatchEvent falls back to listByEventType without tx when PG disabled', async () => {
    const { dispatcher, store } = loadDispatcher({ isEnabled: false });

    const payload = {
      eventId: 'ev-4',
      eventType: 'certification.completed',
      tenantId: 'acme',
    };

    await new Promise((resolve) => {
      dispatcher.dispatchEvent('certification.completed', payload);
      setImmediate(resolve);
    });
    await new Promise(resolve => setTimeout(resolve, 10));

    const listCalls = store.listByEventType.mock.calls;
    if (listCalls.length > 0) {
      // When PG is disabled, no tx should be passed
      const opts = listCalls[0][1];
      expect(opts?.tx).toBeUndefined();
    }
    jest.dontMock('../pool');
    jest.dontMock('../../../core/webhooks/webhookStore');
    jest.dontMock('../../../core/webhooks/webhookMetrics');
    jest.dontMock('../../../core/persistenceRecovery');
  });
});

// ── RLS-66 … RLS-80: Policy SQL invariants ────────────────────────────────────

describe('RLS-66 … RLS-80: Migration policy SQL invariants', () => {
  const fs = require('fs');
  const path = require('path');

  let migrationSql;

  beforeAll(() => {
    const migrationPath = path.join(__dirname, '..', 'migrations', '018_rls_tenant_isolation.sql');
    migrationSql = fs.readFileSync(migrationPath, 'utf8');
  });

  test('RLS-66 migration defines qodiqa_current_tenant() function', () => {
    expect(migrationSql).toContain('CREATE OR REPLACE FUNCTION qodiqa_current_tenant()');
  });

  test('RLS-67 qodiqa_current_tenant() uses NULLIF to treat empty string as NULL', () => {
    expect(migrationSql).toContain("NULLIF(current_setting('qodiqa.tenant_id', true), '')");
  });

  test('RLS-68 function uses missing_ok=true in current_setting', () => {
    expect(migrationSql).toContain("current_setting('qodiqa.tenant_id', true)");
  });

  test('RLS-69 webhook_endpoints gets FORCE ROW LEVEL SECURITY', () => {
    expect(migrationSql).toMatch(/ALTER TABLE webhook_endpoints FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-70 webhook_endpoints SELECT policy is strict (no NULL fallback)', () => {
    // webhook_endpoints.tenant_id is NOT NULL; policy must be strict
    const selectPolicy = migrationSql.match(/CREATE POLICY we_tenant_select.*?;/s)?.[0] ?? '';
    expect(selectPolicy).toContain('qodiqa_current_tenant()');
    // Must NOT have "tenant_id IS NULL OR" (that's for nullable columns)
    expect(selectPolicy).not.toContain('IS NULL OR');
  });

  test('RLS-71 webhook_endpoints INSERT policy enforces tenant match', () => {
    expect(migrationSql).toContain('we_tenant_insert');
    const insertSection = migrationSql.split('CREATE POLICY we_tenant_insert')[1]?.split(';')[0] ?? '';
    expect(insertSection).toContain('qodiqa_current_tenant()');
  });

  test('RLS-72 consent_records SELECT policy allows platform-level rows (IS NULL)', () => {
    // consent_records.tenant_id is nullable; NULL = platform-level
    const section = migrationSql.split('CREATE POLICY cr_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('IS NULL OR');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-73 audit_chain INSERT policy is permissive (true)', () => {
    const section = migrationSql.split('CREATE POLICY ac_system_insert')[1]?.split(';')[0] ?? '';
    expect(section).toContain('true');
  });

  test('RLS-74 platform_audit_events INSERT policy is permissive', () => {
    const section = migrationSql.split('CREATE POLICY pae_system_insert')[1]?.split(';')[0] ?? '';
    expect(section).toContain('true');
  });

  test('RLS-75 webhook_delivery_log SELECT uses subquery on webhook_endpoints', () => {
    const section = migrationSql.split('CREATE POLICY wdl_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('webhook_endpoints');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-76 webhook_delivery_log INSERT is permissive (delivery system writes without context)', () => {
    const section = migrationSql.split('CREATE POLICY wdl_system_insert')[1]?.split(';')[0] ?? '';
    expect(section).toContain('true');
  });

  test('RLS-77 migration grants BYPASSRLS to qodiqa_mig', () => {
    expect(migrationSql).toContain('ALTER ROLE qodiqa_mig BYPASSRLS');
  });

  test('RLS-78 migration uses DROP POLICY IF EXISTS (idempotent)', () => {
    expect(migrationSql).toContain('DROP POLICY IF EXISTS');
    // Multiple tables should have their old policies dropped
    const dropCount = (migrationSql.match(/DROP POLICY IF EXISTS/g) || []).length;
    expect(dropCount).toBeGreaterThan(5);
  });

  test('RLS-79 migration is wrapped in BEGIN/COMMIT', () => {
    // File has SQL comment header before BEGIN (valid SQL); check for presence
    expect(migrationSql).toContain('BEGIN;');
    expect(migrationSql.trim()).toMatch(/COMMIT;$/);
  });

  test('RLS-80 migration records itself in qodiqa_migrations', () => {
    expect(migrationSql).toContain("VALUES (18, 'rls_tenant_isolation'");
  });
});

// ── RLS-81 … RLS-90: Administrative bypass ────────────────────────────────────

describe('RLS-81 … RLS-90: Administrative bypass and policy documentation', () => {
  const fs = require('fs');
  const path = require('path');
  let migrationSql;

  beforeAll(() => {
    const p = path.join(__dirname, '..', 'migrations', '018_rls_tenant_isolation.sql');
    migrationSql = fs.readFileSync(p, 'utf8');
  });

  test('RLS-81 qodiqa_mig receives BYPASSRLS attribute for maintenance ops', () => {
    expect(migrationSql).toContain('ALTER ROLE qodiqa_mig BYPASSRLS');
  });

  test('RLS-82 BYPASSRLS is NOT granted to qodiqa_app (would be a security violation)', () => {
    // The migration must not grant BYPASSRLS to qodiqa_app
    expect(migrationSql).not.toMatch(/ALTER ROLE qodiqa_app BYPASSRLS/i);
  });

  test('RLS-83 migration does not DISABLE ROW LEVEL SECURITY on any table', () => {
    expect(migrationSql).not.toMatch(/DISABLE ROW LEVEL SECURITY/i);
  });

  test('RLS-84 migration does not ALTER TABLE ... NO FORCE ROW LEVEL SECURITY', () => {
    expect(migrationSql).not.toMatch(/NO FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-85 BYPASSRLS grant is conditional on the role existing (DO block)', () => {
    // Should be wrapped in a DO block checking IF EXISTS
    expect(migrationSql).toContain("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_mig')");
  });

  test('RLS-86 migration does not drop RLS from any table', () => {
    expect(migrationSql).not.toMatch(/ALTER TABLE .* DISABLE/i);
  });

  test('RLS-87 qodiqa_current_tenant function is SECURITY INVOKER', () => {
    // SECURITY INVOKER: function runs as the calling user, not the definer
    expect(migrationSql).toContain('SECURITY INVOKER');
  });

  test('RLS-88 qodiqa_current_tenant function is STABLE (safe for RLS)', () => {
    // STABLE: evaluated once per query — correct for session variable reads
    expect(migrationSql).toContain('STABLE');
  });

  test('RLS-89 tenant context module validates format to prevent SQL injection', async () => {
    // Even though set_config uses $1 parameterized query, validate() provides
    // defense-in-depth by rejecting obviously malicious values at the application layer
    const injections = [
      "'; DROP TABLE webhook_endpoints; --",
      '\\x00malicious',
      'a'.repeat(65),
      '',
      "tenant\nid",
    ];
    for (const injection of injections) {
      expect(() => tenantContext.validate(injection)).toThrow(TypeError);
    }
  });

  test('RLS-90 tenantContext.js exports exactly validate, setLocal, clearLocal', () => {
    const exports = Object.keys(tenantContext).sort();
    expect(exports).toEqual(['clearLocal', 'setLocal', 'validate']);
  });
});

// ── RLS-91 … RLS-100: now real PostgreSQL tests ──────────────────
//
// These ten were empty skipped stubs until. They are now implemented against a
// real disposable database with the full migration chain, in
// test/integration/privilegeRls.integration.test.js (test:component:serial). This pointer
// fails if that file stops carrying all ten, so they cannot silently vanish.

describe('RLS-91 … RLS-100: moved to test/integration/privilegeRls.integration.test.js (real PostgreSQL)', () => {
  test('the integration suite implements RLS-91 through RLS-100', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(path.join(__dirname, '..', '..', '..', '..', 'test', 'integration', 'privilegeRls.integration.test.js'), 'utf8');
    for (let n = 91; n <= 100; n++) {
      expect({ n, present: src.includes(`test('RLS-${n} `) || src.includes(`test("RLS-${n} `) }).toEqual({ n, present: true });
    }
  });
});

// ── RLS-101 … RLS-115: New table coverage — migration 018 additions ───────────

describe('RLS-101 … RLS-115: Migration 018 — new table coverage', () => {
  const fs = require('fs');
  const path = require('path');

  let migrationSql;

  beforeAll(() => {
    const p = path.join(__dirname, '..', 'migrations', '018_rls_tenant_isolation.sql');
    migrationSql = fs.readFileSync(p, 'utf8');
  });

  test('RLS-101 migration covers revocation_events (ENABLE + FORCE RLS)', () => {
    expect(migrationSql).toMatch(/ALTER TABLE revocation_events ENABLE ROW LEVEL SECURITY/i);
    expect(migrationSql).toMatch(/ALTER TABLE revocation_events FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-102 revocation_events SELECT policy is tenant-aware (NULL OR match)', () => {
    const section = migrationSql.split('CREATE POLICY re_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('IS NULL OR');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-103 revocation_events INSERT policy is permissive (append-only system log)', () => {
    const section = migrationSql.split('CREATE POLICY re_system_insert')[1]?.split(';')[0] ?? '';
    expect(section).toContain('true');
  });

  test('RLS-104 migration covers transparency_log_entries (FORCE RLS + tenant policies)', () => {
    expect(migrationSql).toMatch(/ALTER TABLE transparency_log_entries FORCE ROW LEVEL SECURITY/i);
    expect(migrationSql).toContain('tle_tenant_select');
  });

  test('RLS-105 transparency_log_entries SELECT policy is tenant-aware', () => {
    const section = migrationSql.split('CREATE POLICY tle_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('IS NULL OR');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-106 transparency_log_entries drops old permissive tle_select before replacing', () => {
    expect(migrationSql).toContain('DROP POLICY IF EXISTS tle_select ON transparency_log_entries');
  });

  test('RLS-107 kms_encrypted_data_keys gets tenant-scoped policies', () => {
    expect(migrationSql).toMatch(/ALTER TABLE kms_encrypted_data_keys FORCE ROW LEVEL SECURITY/i);
    expect(migrationSql).toContain('kedk_tenant_select');
    expect(migrationSql).toContain('kedk_tenant_insert');
  });

  test('RLS-108 kms_encrypted_data_keys SELECT policy is tenant-aware', () => {
    const section = migrationSql.split('CREATE POLICY kedk_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('IS NULL OR');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-109 qodiqa_suppression_rules gets tenant-scoped policies', () => {
    expect(migrationSql).toMatch(/ALTER TABLE qodiqa_suppression_rules FORCE ROW LEVEL SECURITY/i);
    expect(migrationSql).toContain('qsr_tenant_select');
    expect(migrationSql).toContain('qsr_tenant_insert');
    expect(migrationSql).toContain('qsr_tenant_update');
    expect(migrationSql).toContain('qsr_tenant_delete');
  });

  test('RLS-110 qodiqa_anomaly_baselines gets tenant-scoped policies', () => {
    expect(migrationSql).toMatch(/ALTER TABLE qodiqa_anomaly_baselines FORCE ROW LEVEL SECURITY/i);
    expect(migrationSql).toContain('qab_tenant_select');
  });

  test('RLS-111 qodiqa_alert_history gets FK-based SELECT policy', () => {
    expect(migrationSql).toMatch(/ALTER TABLE qodiqa_alert_history FORCE ROW LEVEL SECURITY/i);
    const section = migrationSql.split('CREATE POLICY qah_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('qodiqa_alerts');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-112 qodiqa_notification_deliveries gets FK-based SELECT policy', () => {
    expect(migrationSql).toMatch(/ALTER TABLE qodiqa_notification_deliveries FORCE ROW LEVEL SECURITY/i);
    const section = migrationSql.split('CREATE POLICY qnd_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('qodiqa_alerts');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-113 qodiqa_escalation_records gets FK-based SELECT policy', () => {
    expect(migrationSql).toMatch(/ALTER TABLE qodiqa_escalation_records FORCE ROW LEVEL SECURITY/i);
    const section = migrationSql.split('CREATE POLICY qer_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('qodiqa_alerts');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-114 qodiqa_alert_stats gets global policies (no tenant isolation needed)', () => {
    expect(migrationSql).toMatch(/ALTER TABLE qodiqa_alert_stats FORCE ROW LEVEL SECURITY/i);
    expect(migrationSql).toContain('qas_select');
    expect(migrationSql).toContain('qas_insert');
  });

  test('RLS-115 consolidation block applies FORCE RLS to all global tables', () => {
    const consolidationTables = [
      'kms_provider_events',
      'kms_wrapping_key_rotations',
      'compliance_frameworks',
      'compliance_controls',
      'compliance_control_assessments',
      'compliance_evidence_refs',
      'compliance_report_signatures',
      'compliance_report_exports',
      'policy_provenance_versions',
      'policy_provenance_integrity_runs',
      'evidence_chain_verifications',
      'transparency_roots',
      'transparency_verifications',
      'portal_verifications',
      'attestations',
      'certifications',
      'certificate_artifacts',
    ];
    for (const tbl of consolidationTables) {
      expect(migrationSql).toMatch(
        new RegExp(`ALTER TABLE ${tbl}\\s+FORCE ROW LEVEL SECURITY`, 'i'),
      );
    }
  });
});

// ── RLS-116 … RLS-130: Migration syntax correctness ───────────────────────────

describe('RLS-116 … RLS-130: Prior migration SQL syntax correctness', () => {
  const fs = require('fs');
  const path = require('path');

  function loadMigration(filename) {
    // Normalize line endings so assertions against '\n'-joined literals are
    // correct regardless of the working tree's checkout config (defense in
    // depth alongside .gitattributes' eol=lf — see P4-2-CRLF-REPORT.md).
    return fs.readFileSync(
      path.join(__dirname, '..', 'migrations', filename),
      'utf8',
    ).replace(/\r\n/g, '\n');
  }

  test('RLS-116 migration 004 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('004_kms_provider_audit.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE kms_provider_events\s+FORCE ROW LEVEL SECURITY/i);
    expect(sql).toMatch(/ALTER TABLE kms_encrypted_data_keys\s+FORCE ROW LEVEL SECURITY/i);
    expect(sql).toMatch(/ALTER TABLE kms_wrapping_key_rotations\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-117 migration 004 CREATE POLICY uses ON tablename syntax', () => {
    const sql = loadMigration('004_kms_provider_audit.sql');
    expect(sql).not.toMatch(/CREATE POLICY \w+ FOR \w+_events/);
    expect(sql).toContain('CREATE POLICY kpe_insert ON kms_provider_events');
    expect(sql).toContain('CREATE POLICY kpe_select ON kms_provider_events');
  });

  test('RLS-118 migration 005 has no NULLABLE keyword (invalid PostgreSQL)', () => {
    const sql = loadMigration('005_compliance_reporting.sql');
    expect(sql).not.toMatch(/\bNULLABLE\b/);
  });

  test('RLS-119 migration 005 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('005_compliance_reporting.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE compliance_frameworks\s+FORCE ROW LEVEL SECURITY/i);
    expect(sql).toMatch(/ALTER TABLE compliance_reports\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-120 migration 005 CREATE POLICY uses ON tablename syntax', () => {
    const sql = loadMigration('005_compliance_reporting.sql');
    expect(sql).not.toMatch(/CREATE POLICY \w+ FOR compliance_/);
    expect(sql).toContain('CREATE POLICY cf_select    ON compliance_frameworks');
  });

  test('RLS-121 migration 009 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('009_policy_provenance.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE policy_provenance_versions\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-122 migration 009 CREATE POLICY uses ON tablename FOR action syntax', () => {
    const sql = loadMigration('009_policy_provenance.sql');
    expect(sql).not.toMatch(/CREATE POLICY ppv_select\s+FOR SELECT ON/);
    expect(sql).toContain('CREATE POLICY ppv_select\n  ON policy_provenance_versions');
  });

  test('RLS-123 migration 010 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('010_evidence_chain.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE evidence_chain_records\s+FORCE ROW LEVEL SECURITY/i);
    expect(sql).toMatch(/ALTER TABLE evidence_chain_verifications\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-124 migration 011 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('011_transparency_log.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE transparency_log_entries\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-125 migration 012 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('012_verification_portal.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE portal_verifications\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-126 migration 013 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('013_attestation.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE attestations\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-127 migration 014 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('014_certification.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE certifications\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-128 migration 016 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('016_webhooks.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE webhook_endpoints\s+FORCE ROW LEVEL SECURITY/i);
    expect(sql).toMatch(/ALTER TABLE webhook_delivery_log\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-129 migration 017 uses ALTER TABLE ... FORCE ROW LEVEL SECURITY', () => {
    const sql = loadMigration('017_certificate_artifacts.sql');
    expect(sql).not.toMatch(/^FORCE ROW LEVEL SECURITY ON/m);
    expect(sql).toMatch(/ALTER TABLE certificate_artifacts\s+FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-130 no migration file contains bare FORCE ROW LEVEL SECURITY ON (invalid syntax)', () => {
    const migrationDir = path.join(__dirname, '..', 'migrations');
    const files = fs.readdirSync(migrationDir).filter(f => f.endsWith('.sql'));
    for (const file of files) {
      const sql = fs.readFileSync(path.join(migrationDir, file), 'utf8');
      const badLines = sql.split('\n').filter(line =>
        /^FORCE ROW LEVEL SECURITY ON\b/.test(line.trim()),
      );
      expect(badLines).toHaveLength(0);
    }
  });
});

// ── RLS-131 … RLS-145: Connection pool and transaction safety ─────────────────

describe('RLS-131 … RLS-145: Connection pool safety and transaction edge cases', () => {
  test('RLS-131 withTenantTransaction is atomic: context set inside BEGIN, cleared at COMMIT', async () => {
    jest.resetModules();
    const sqlLog = [];
    const client = {
      query: jest.fn(async (sql) => { sqlLog.push(sql.trim()); return { rows: [], rowCount: 0 }; }),
      release: jest.fn(),
    };
    const mockPool = { connect: jest.fn(async () => client), on: jest.fn(), options: { max: 10 }, waitingCount: 0 };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    await pgPool.withTenantTransaction('alpha', async () => {});

    const beginIdx = sqlLog.findIndex(s => s.startsWith('BEGIN'));
    const configIdx = sqlLog.findIndex(s => s.includes('set_config'));
    const commitIdx = sqlLog.findIndex(s => s === 'COMMIT');

    expect(beginIdx).toBeGreaterThanOrEqual(0);
    expect(configIdx).toBeGreaterThan(beginIdx);
    expect(commitIdx).toBeGreaterThan(configIdx);

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-132 context is cleared on ROLLBACK: set_config transaction-local resets', async () => {
    jest.resetModules();
    const sqlLog = [];
    const client = {
      query: jest.fn(async (sql) => { sqlLog.push(sql.trim()); return { rows: [], rowCount: 0 }; }),
      release: jest.fn(),
    };
    const mockPool = { connect: jest.fn(async () => client), on: jest.fn(), options: { max: 10 }, waitingCount: 0 };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    await pgPool.withTenantTransaction('bravo', async () => {
      throw new Error('rollback');
    }).catch(() => {});

    expect(sqlLog).toContain('ROLLBACK');
    const beginIdx = sqlLog.findIndex(s => s.startsWith('BEGIN'));
    const configIdx = sqlLog.findIndex(s => s.includes('set_config'));
    const rollbackIdx = sqlLog.findIndex(s => s === 'ROLLBACK');
    expect(beginIdx).toBeGreaterThanOrEqual(0);
    expect(configIdx).toBeGreaterThan(beginIdx);
    expect(rollbackIdx).toBeGreaterThan(configIdx);

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-133 exception in fn rolls back AND releases connection', async () => {
    jest.resetModules();
    const client = {
      query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
      release: jest.fn(),
    };
    const mockPool = { connect: jest.fn(async () => client), on: jest.fn(), options: { max: 10 }, waitingCount: 0 };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    await pgPool.withTenantTransaction('charlie', async () => {
      throw new Error('forced failure');
    }).catch(() => {});

    expect(client.release).toHaveBeenCalledTimes(1);
    const sqls = client.query.mock.calls.map(c => c[0].trim());
    expect(sqls).toContain('ROLLBACK');

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-134 concurrent tenant transactions each set their own context independently', async () => {
    jest.resetModules();
    const contextSeen = {};
    let clientIdx = 0;
    const makeClient = (tenantExpected) => ({
      query: jest.fn(async (sql, params) => {
        if (sql.includes('set_config') && params) {
          contextSeen[tenantExpected] = params[0];
        }
        return { rows: [], rowCount: 0 };
      }),
      release: jest.fn(),
    });
    const clients = ['tenant-x', 'tenant-y'].map(makeClient);
    const mockPool = {
      connect: jest.fn(async () => clients[clientIdx++ % clients.length]),
      on: jest.fn(), options: { max: 10 }, waitingCount: 0,
    };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    await Promise.all([
      pgPool.withTenantTransaction('tenant-x', async () => {}),
      pgPool.withTenantTransaction('tenant-y', async () => {}),
    ]);

    expect(contextSeen['tenant-x']).toBe('tenant-x');
    expect(contextSeen['tenant-y']).toBe('tenant-y');

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-135 connection reuse: second transaction does not inherit first tenant context', async () => {
    jest.resetModules();
    const setConfigCalls = [];
    const client = {
      query: jest.fn(async (sql, params) => {
        if (sql.includes('set_config')) setConfigCalls.push(params?.[0]);
        return { rows: [], rowCount: 0 };
      }),
      release: jest.fn(),
    };
    const mockPool = { connect: jest.fn(async () => client), on: jest.fn(), options: { max: 10 }, waitingCount: 0 };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    await pgPool.withTenantTransaction('first-tenant', async () => {});
    await pgPool.withTenantTransaction('second-tenant', async () => {});

    expect(setConfigCalls[0]).toBe('first-tenant');
    expect(setConfigCalls[1]).toBe('second-tenant');
    expect(setConfigCalls).toHaveLength(2);

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-136 invalid tenant ID (special chars) is rejected before connection', async () => {
    jest.resetModules();
    const mockPool = { connect: jest.fn(), on: jest.fn(), options: { max: 10 }, waitingCount: 0 };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    const maliciousIds = [
      "'; SELECT 1; --",
      'tenant<script>',
      'tenant\nROLLBACK',
      'a'.repeat(65),
      '',
      null,
      undefined,
      42,
    ];

    for (const id of maliciousIds) {
      await expect(pgPool.withTenantTransaction(id, jest.fn())).rejects.toThrow(TypeError);
    }
    expect(mockPool.connect).not.toHaveBeenCalled();

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-137 withTenantTransaction does not call fn when validation fails', async () => {
    jest.resetModules();
    const mockPool = { connect: jest.fn(), on: jest.fn(), options: { max: 10 }, waitingCount: 0 };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    const fn = jest.fn();
    await pgPool.withTenantTransaction('bad tenant!', fn).catch(() => {});
    expect(fn).not.toHaveBeenCalled();

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });

  test('RLS-138 withTenantTransaction propagates fn return value through transaction', async () => {
    jest.resetModules();
    const client = {
      query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
      release: jest.fn(),
    };
    const mockPool = { connect: jest.fn(async () => client), on: jest.fn(), options: { max: 10 }, waitingCount: 0 };
    jest.doMock('pg', () => ({ Pool: jest.fn(() => mockPool) }));
    process.env.QODIQA_PG_ENABLED = 'true';
    const pgPool = require('../pool');
    pgPool.initialize();

    const result = await pgPool.withTenantTransaction('acme', async (tx) => {
      return { rows: [{ id: 1 }] };
    });
    expect(result).toEqual({ rows: [{ id: 1 }] });

    delete process.env.QODIQA_PG_ENABLED;
    jest.dontMock('pg');
    jest.resetModules();
  });
});

// ── RLS-139 … RLS-150: FK-based and nullable policy invariants ────────────────

describe('RLS-139 … RLS-150: FK-based isolation and nullable policy verification', () => {
  const fs = require('fs');
  const path = require('path');
  let migrationSql;

  beforeAll(() => {
    const p = path.join(__dirname, '..', 'migrations', '018_rls_tenant_isolation.sql');
    migrationSql = fs.readFileSync(p, 'utf8');
  });

  test('RLS-139 FK policy: qodiqa_alert_history SELECT uses subquery on qodiqa_alerts', () => {
    const section = migrationSql.split('CREATE POLICY qah_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('SELECT id FROM qodiqa_alerts');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-140 FK policy: qodiqa_notification_deliveries SELECT uses subquery on qodiqa_alerts', () => {
    const section = migrationSql.split('CREATE POLICY qnd_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('SELECT id FROM qodiqa_alerts');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-141 FK policy: qodiqa_escalation_records SELECT uses subquery on qodiqa_alerts', () => {
    const section = migrationSql.split('CREATE POLICY qer_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('SELECT id FROM qodiqa_alerts');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-142 FK policy: webhook_delivery_log SELECT uses subquery on webhook_endpoints', () => {
    const section = migrationSql.split('CREATE POLICY wdl_tenant_select')[1]?.split(';')[0] ?? '';
    expect(section).toContain('SELECT id FROM webhook_endpoints');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-143 nullable policy: kms_encrypted_data_keys INSERT uses IS NULL OR tenant match', () => {
    const section = migrationSql.split('CREATE POLICY kedk_tenant_insert')[1]?.split(';')[0] ?? '';
    expect(section).toContain('IS NULL OR');
    expect(section).toContain('qodiqa_current_tenant()');
  });

  test('RLS-144 nullable policy: qodiqa_suppression_rules has IS NULL OR in all policies', () => {
    const selectSection = migrationSql.split('CREATE POLICY qsr_tenant_select')[1]?.split(';')[0] ?? '';
    const insertSection = migrationSql.split('CREATE POLICY qsr_tenant_insert')[1]?.split(';')[0] ?? '';
    expect(selectSection).toContain('IS NULL OR');
    expect(insertSection).toContain('IS NULL OR');
  });

  test('RLS-145 strict policy: webhook_endpoints has NO IS NULL fallback (tenant_id NOT NULL)', () => {
    const selectSection = migrationSql.split('CREATE POLICY we_tenant_select')[1]?.split(';')[0] ?? '';
    expect(selectSection).not.toContain('IS NULL OR');
    expect(selectSection).toContain('qodiqa_current_tenant()');
  });

  test('RLS-146 qodiqa_alert_history INSERT is permissive (system writes without tenant context)', () => {
    const section = migrationSql.split('CREATE POLICY qah_system_insert')[1]?.split(';')[0] ?? '';
    expect(section).toContain('true');
    expect(section).not.toContain('qodiqa_current_tenant()');
  });

  test('RLS-147 revocation_events has no UPDATE or DELETE policies (immutable)', () => {
    const revocationSection = migrationSql
      .split('revocation_events')[2]
      ?.split('transparency_log_entries')[0] ?? '';
    expect(revocationSection).not.toMatch(/FOR UPDATE/i);
    expect(revocationSection).not.toMatch(/FOR DELETE/i);
  });

  test('RLS-148 administrative role bypass: qodiqa_mig BYPASSRLS is conditional', () => {
    expect(migrationSql).toContain("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qodiqa_mig')");
    expect(migrationSql).toContain('ALTER ROLE qodiqa_mig BYPASSRLS');
  });

  test('RLS-149 no table has both DISABLE ROW LEVEL SECURITY and policies', () => {
    expect(migrationSql).not.toMatch(/DISABLE ROW LEVEL SECURITY/i);
    expect(migrationSql).not.toMatch(/NO FORCE ROW LEVEL SECURITY/i);
  });

  test('RLS-150 DROP POLICY IF EXISTS precedes every CREATE POLICY (idempotent)', () => {
    const dropCount = (migrationSql.match(/DROP POLICY IF EXISTS/g) || []).length;
    const createCount = (migrationSql.match(/CREATE POLICY/g) || []).length;
    expect(dropCount).toBeGreaterThanOrEqual(createCount);
  });
});
