'use strict';

/**
 * Fake PostgreSQL row-locking + isolation-level harness — regression
 * tests.
 *
 * Models exactly the piece of real Postgres behavior depends on, not a
 * full SQL engine:
 *   - `SELECT ... FOR UPDATE` (and `INSERT ... ON CONFLICT DO UPDATE`, which
 *     implicitly locks its conflict-target row the same way) blocks a
 *     concurrent transaction targeting the same row until the lock holder
 *     commits or rolls back.
 *   - Under REPEATABLE READ, if the row was modified by a transaction that
 *     committed AFTER this transaction's own snapshot was taken, waking up
 *     from that block raises SQLSTATE 40001 ("could not serialize access due
 *     to concurrent update") instead of returning the fresh row — this is
 * the exact mechanism behind.
 *   - Under READ COMMITTED, waking up from that block simply returns the
 *     row's current, fresh, post-commit value — no error, ever, which is why
 * pinning READ COMMITTED (ConsentStore.js) closes on these paths.
 *
 * Each transaction's writes are buffered locally (`pending`) and only merged
 * into the shared row table at COMMIT — discarded on throw (ROLLBACK) —
 * matching real transactional isolation: a later query in the SAME
 * transaction sees its own uncommitted writes, no OTHER transaction does
 * until commit.
 *
 * Deliberately narrow: recognizes only the exact SQL shapes ConsentStore.js
 * issues for create()/revoke()/suspend() (the paths these regression tests
 * exercise) and the consent_audit_log INSERT (a no-op here — audit-row
 * correctness is not what is about). Anything else throws loudly rather
 * than silently returning a wrong result.
 */

function makeFakePgPool() {
  let commitSeq = 0;
  const rows = new Map();      // id -> committed row (includes lastCommitSeq)
  const keyIndex = new Map();  // "actor|action|tenant" -> id
  const rowQueues = new Map(); // id -> tail of the per-row lock queue

  function seed(id, record) {
    rows.set(id, { ...record, lastCommitSeq: 0 });
    keyIndex.set(`${record.actor_id}|${record.action}|${record.tenant_id ?? ''}`, id);
  }

  function queueLock(id) {
    const prevTail = rowQueues.get(id) || Promise.resolve();
    let release;
    const gate = new Promise((res) => { release = res; });
    rowQueues.set(id, prevTail.then(() => gate));
    return prevTail.then(() => release);
  }

  function applyGenericUpdate(row, sql, params) {
    const setMatch = sql.match(/SET\s+([\s\S]+?)\s+WHERE/i);
    if (!setMatch) throw new Error(`fake pool: no SET clause found in: ${sql.slice(0, 80)}`);
    const updated = { ...row };
    for (const assign of setMatch[1].split(',')) {
      const m = assign.trim().match(/^(\w+)\s*=\s*(.+)$/);
      if (!m) continue;
      const [, col, rhs] = m;
      if (rhs === 'NOW()') { updated[col] = new Date(); continue; }
      if (rhs === 'NULL')  { updated[col] = null; continue; }
      const pRef = rhs.match(/^\$(\d+)$/);
      if (pRef) { updated[col] = params[Number(pRef[1]) - 1]; continue; }
      throw new Error(`fake pool: unrecognized SET assignment "${assign.trim()}"`);
    }
    return updated;
  }

  async function withTransaction(fn, opts = {}) {
    const isolationLevel = opts.isolationLevel || 'REPEATABLE READ';
    const snapshotSeq = commitSeq;
    const pending = new Map();
    const locksHeld = [];

    function currentView(id) {
      return pending.has(id) ? pending.get(id) : rows.get(id);
    }

    async function lockRow(id) {
      const release = await queueLock(id);
      locksHeld.push(release);
      const row = rows.get(id);
      if (row && isolationLevel === 'REPEATABLE READ' && row.lastCommitSeq > snapshotSeq) {
        const err = new Error('could not serialize access due to concurrent update');
        err.code = '40001';
        throw err;
      }
      if (row) pending.set(id, { ...row });
      return row ? { ...row } : null;
    }

    const tx = {
      query: async (sql, params = []) => {
        const trimmed = sql.trim();

        if (/consent_audit_log/i.test(trimmed)) {
          return { rows: [], rowCount: 1 };
        }

        if (/^SELECT[\s\S]*FOR UPDATE/i.test(trimmed)) {
          const row = await lockRow(params[0]);
          return { rows: row ? [row] : [] };
        }

        if (/^INSERT INTO consent_records[\s\S]*ON CONFLICT/i.test(trimmed)) {
          const [actor_id, action, tenant_id, state] = params;
          const key = `${actor_id}|${action}|${tenant_id ?? ''}`;
          const existingId = keyIndex.get(key);
          if (!existingId) {
            throw new Error('fake pool: fresh-insert (no prior row) races are not modeled by this harness');
          }
          const row = await lockRow(existingId);
          if (!row) return { rows: [] };
          if (row.state === 'REVOKED' || row.state === 'EXPIRED') {
            return { rows: [] }; // WHERE guard blocks the DO UPDATE, exactly like real Postgres
          }
          const updated = {
            ...row,
            state,
            revoked_at: null, revoked_by: null, revocation_reason: null,
            suspended_at: null, suspended_by: null, suspension_reason: null, suspended_until: null,
          };
          pending.set(existingId, updated);
          return { rows: [updated] };
        }

        if (/^SELECT state FROM consent_records/i.test(trimmed)) {
          const [actor_id, action, tenant_id] = params;
          const id = keyIndex.get(`${actor_id}|${action}|${tenant_id ?? ''}`);
          const row = id ? currentView(id) : null;
          return { rows: row ? [{ state: row.state }] : [] };
        }

        if (/^UPDATE consent_records/i.test(trimmed)) {
          const id = params[params.length - 1];
          const updated = applyGenericUpdate(currentView(id), trimmed, params);
          pending.set(id, updated);
          return { rows: [updated] };
        }

        throw new Error(`fake pool: unrecognized SQL shape: ${trimmed.slice(0, 80)}`);
      },
    };

    try {
      const result = await fn(tx);
      for (const [id, row] of pending) rows.set(id, { ...row, lastCommitSeq: ++commitSeq });
      return result;
    } finally {
      for (const release of locksHeld) release();
    }
  }

  return {
    seed,
    getRow: (id) => ({ ...rows.get(id) }),
    isEnabled: () => true,
    isHealthy: () => true,
    query: async () => { throw new Error('fake pool: plain query() not modeled by this harness'); },
    withTransaction,
    withTenantTransaction: (_tenantId, fn, opts) => withTransaction(fn, opts),
  };
}

module.exports = { makeFakePgPool };
