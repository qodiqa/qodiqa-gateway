'use strict';

// Batch store — persistence layer for certification batch records.
//
// createBatchStore({ dir? })
//   dir provided → file-backed (survives restarts): one JSON file per batch
//   dir omitted  → in-memory only (tests / environments without writable FS)
//
// State machine (enforced on every update):
//   pending  → running, cancelled
//   running  → completed, failed, cancelled
//   completed, failed, cancelled  → (terminal, no transitions)

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// ── ID generation ─────────────────────────────────────────────────────────────

function generateBatchId() { return 'batch_' + crypto.randomBytes(16).toString('hex'); }
function generateItemId()  { return 'item_'  + crypto.randomBytes(8).toString('hex'); }

// ── State machine ─────────────────────────────────────────────────────────────

const VALID_TRANSITIONS = Object.freeze({
  pending:   Object.freeze(['running', 'cancelled']),
  running:   Object.freeze(['completed', 'failed', 'cancelled']),
  completed: Object.freeze([]),
  failed:    Object.freeze([]),
  cancelled: Object.freeze([]),
});

function _assertTransition(current, next) {
  if (current === next) return;
  const allowed = VALID_TRANSITIONS[current] || [];
  if (!allowed.includes(next)) {
    const err = new Error(`Invalid batch state transition: ${current} → ${next}`);
    err.code = 'INVALID_TRANSITION';
    throw err;
  }
}

// ── In-memory store ───────────────────────────────────────────────────────────

function _createMemoryStore() {
  const _map = new Map();

  async function save(batch) {
    _map.set(batch.batchId, _clone(batch));
    return _clone(batch);
  }

  async function get(batchId) {
    const b = _map.get(batchId);
    return b ? _clone(b) : null;
  }

  async function update(batchId, patch) {
    const batch = _map.get(batchId);
    if (!batch) { const e = new Error(`Batch not found: ${batchId}`); e.code = 'NOT_FOUND'; throw e; }
    if (patch.status && patch.status !== batch.status) _assertTransition(batch.status, patch.status);
    const updated = Object.assign({}, batch, patch);
    _map.set(batchId, updated);
    return _clone(updated);
  }

  async function updateItem(batchId, itemId, patch) {
    const batch = _map.get(batchId);
    if (!batch) { const e = new Error(`Batch not found: ${batchId}`); e.code = 'NOT_FOUND'; throw e; }
    const idx = batch.items.findIndex(i => i.itemId === itemId);
    if (idx === -1) { const e = new Error(`Item not found: ${itemId}`); e.code = 'NOT_FOUND'; throw e; }
    batch.items[idx] = Object.assign({}, batch.items[idx], patch);
    _map.set(batchId, batch);
    return _clone(batch.items[idx]);
  }

  async function listByTenant(tenantId) {
    return Array.from(_map.values()).filter(b => b.tenantId === tenantId).map(_clone);
  }

  async function remove(batchId) {
    _map.delete(batchId);
  }

  return { save, get, update, updateItem, listByTenant, remove };
}

// ── File-backed store ─────────────────────────────────────────────────────────

function _createFileStore(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });

  const _mem  = _createMemoryStore();
  let   _init = false;

  function _filePath(batchId) { return path.join(dataDir, `${batchId}.json`); }

  function _persist(batch) {
    const tmp = _filePath(batch.batchId) + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(batch), 'utf8');
    fs.renameSync(tmp, _filePath(batch.batchId));
  }

  function _hydrate() {
    if (_init) return;
    _init = true;
    let files;
    try { files = fs.readdirSync(dataDir); } catch { return; }
    for (const f of files) {
      if (!f.endsWith('.json') || f.endsWith('.tmp.json')) continue;
      try {
        const b = JSON.parse(fs.readFileSync(path.join(dataDir, f), 'utf8'));
        _mem.save(b);
      } catch { /* skip corrupt */ }
    }
  }

  async function save(batch) {
    _hydrate();
    await _mem.save(batch);
    _persist(batch);
    return batch;
  }

  async function get(batchId) { _hydrate(); return _mem.get(batchId); }

  async function update(batchId, patch) {
    _hydrate();
    const updated = await _mem.update(batchId, patch);
    _persist(updated);
    return updated;
  }

  async function updateItem(batchId, itemId, patch) {
    _hydrate();
    await _mem.updateItem(batchId, itemId, patch);
    const b = await _mem.get(batchId);
    _persist(b);
    return b.items.find(i => i.itemId === itemId);
  }

  async function listByTenant(tenantId) { _hydrate(); return _mem.listByTenant(tenantId); }

  async function remove(batchId) {
    _hydrate();
    await _mem.remove(batchId);
    try { fs.unlinkSync(_filePath(batchId)); } catch { /* ok */ }
  }

  return { save, get, update, updateItem, listByTenant, remove };
}

// ── Batch builder ─────────────────────────────────────────────────────────────

function buildBatch({ frameworkId, items, tenantId, requestedBy, requestId }) {
  const batchId = generateBatchId();
  const now     = new Date().toISOString();
  return {
    batchId,
    frameworkId,
    tenantId:    tenantId   || null,
    requestedBy: requestedBy || null,
    requestId:   requestId  || null,
    status:      'pending',
    createdAt:   now,
    startedAt:   null,
    completedAt: null,
    cancelledAt: null,
    items: items.map(item => ({
      itemId:          generateItemId(),
      subjectId:       item.subjectId,
      controls:        item.controls || {},
      artifacts:       item.artifacts       || [],
      evidencePackages: item.evidencePackages || [],
      status:          'pending',
      certificationId: null,
      result:          null,
      error:           null,
      startedAt:       null,
      completedAt:     null,
    })),
  };
}

// ── Public factory ────────────────────────────────────────────────────────────

/**
 * @param {{ dir?: string }} [opts]
 * @returns {BatchStore}
 */
function createBatchStore(opts = {}) {
  return opts.dir ? _createFileStore(opts.dir) : _createMemoryStore();
}

function _clone(obj) { return JSON.parse(JSON.stringify(obj)); }

module.exports = { createBatchStore, buildBatch, generateBatchId, generateItemId, VALID_TRANSITIONS };
