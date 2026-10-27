'use strict';

/**
 * test helper — a stand-in for src/infra/postgres/rolePools.js for unit
 * suites that mock the app pool (pool.js).
 *
 * Production code now sends cross-tenant SECURITY DEFINER reads through
 * rolePools.system / rolePools.reporting (separate PostgreSQL roles). Suites
 * that assert the SQL a store issues keep asserting it: each role pool here
 * forwards to the SAME mocked pool.query, so `pgPool.query` expectations hold,
 * and every forwarded call is also recorded with the pool it went to
 * (`_calls`), so a suite can assert the routing itself.
 *
 * Optional { intercept(sql, params, poolName) } answers specific SQL (return a
 * result object) before forwarding; return undefined to forward.
 *
 * Usage (inside a jest.mock factory — require is allowed there):
 *   jest.mock('<rel>/infra/postgres/rolePools', () =>
 *     require('<rel>/tests/helpers/rolePoolsDelegate')(jest.requireMock('<rel>/infra/postgres/pool')));
 */
module.exports = function rolePoolsDelegate(poolMock, { intercept } = {}) {
  const calls = [];
  const make = (name) => ({
    name,
    query: (sql, params, label) => {
      calls.push({ pool: name, sql: String(sql), label: label ?? null });
      // Optional per-suite answer for SQL the suite used to answer on another
      // mock path (e.g. a transaction mock); undefined falls through.
      const hit = intercept ? intercept(String(sql), params, name) : undefined;
      if (hit !== undefined) return Promise.resolve(hit);
      return poolMock.query(sql, params, label);
    },
    isConfigured: () => true,
    shutdown: async () => {},
  });
  return { system: make('system'), reporting: make('reporting'), shutdownAll: async () => {}, _calls: calls };
};
