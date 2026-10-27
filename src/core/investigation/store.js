'use strict';

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const INV_PATH = process.env.QODIQA_INVESTIGATIONS_PATH
  || path.join(__dirname, '..', '..', '..', 'data', 'investigations.json');

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_ARTIFACTS_PER_INV = 1_000;
const MAX_INVESTIGATIONS     = 10_000;

let _store = {};

(function _load() {
  if (!fs.existsSync(INV_PATH)) return;
  try {
    const raw  = fs.readFileSync(INV_PATH, 'utf8');
    const data = JSON.parse(raw);
    if (data && typeof data.investigations === 'object') {
      _store = data.investigations;
    }
  } catch {
    _store = {};
  }
})();

function _persist() {
  const tmp = INV_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, investigations: _store }, null, 2), 'utf8');
  try {
    fs.renameSync(tmp, INV_PATH);
  } catch {
    fs.copyFileSync(tmp, INV_PATH);
    try { fs.unlinkSync(tmp); } catch {}
  }
}

function _sanitizeStr(v, max) {
  if (typeof v !== 'string') return '';
  return v.trim().slice(0, max);
}

function createInvestigation({ title, investigator, notes, artifactIds } = {}) {
  if (Object.keys(_store).length >= MAX_INVESTIGATIONS) {
    throw new Error('INVESTIGATION_LIMIT_EXCEEDED');
  }

  const id  = 'INV-' + crypto.randomUUID().replace(/-/g, '').toUpperCase().slice(0, 16);
  const now = new Date().toISOString();

  const safeArtifactIds = Array.isArray(artifactIds)
    ? artifactIds.filter(x => typeof x === 'string' && UUID_V4_RE.test(x)).slice(0, MAX_ARTIFACTS_PER_INV)
    : [];

  const inv = {
    id,
    title:        _sanitizeStr(title,       256) || 'Untitled Investigation',
    investigator: _sanitizeStr(investigator, 128) || 'unknown',
    notes:        _sanitizeStr(notes,       4096),
    artifactIds:  safeArtifactIds,
    findings:     [],
    status:       'OPEN',
    createdAt:    now,
    updatedAt:    now,
  };

  _store[id] = inv;
  _persist();
  return Object.freeze({ ...inv });
}

function getInvestigation(id) {
  if (typeof id !== 'string') return null;
  return _store[id] ? Object.freeze({ ..._store[id] }) : null;
}

function listInvestigations({ page = 1, pageSize = 50 } = {}) {
  const all = Object.values(_store).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const total = all.length;
  const start = (page - 1) * pageSize;
  return { total, page, pageSize, investigations: all.slice(start, start + pageSize) };
}

const MAX_AUDIT_EVENTS_PER_INV = 500;

function appendInvestigationEvent(id, event) {
  if (typeof id !== 'string' || !_store[id]) return;
  const inv = _store[id];
  if (!Array.isArray(inv.auditEvents)) inv.auditEvents = [];
  if (inv.auditEvents.length >= MAX_AUDIT_EVENTS_PER_INV) return;
  inv.auditEvents.push(Object.freeze({ ...event, recordedAt: new Date().toISOString() }));
  inv.updatedAt = new Date().toISOString();
  _persist();
}

module.exports = { createInvestigation, getInvestigation, listInvestigations, appendInvestigationEvent };
