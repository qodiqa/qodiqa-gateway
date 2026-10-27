'use strict';

/**
 * actionHash - the binding of ONE agent action.
 *
 *   actionHash = SHA-256( "QODIQA::ACTION::V2" || JCS-P1( A ) )          (hex, lower case)
 *   A = { v: 2, tenantId, agentId, sessionId, seq, tool: { server, name, schemaHash }, args, parentRequestHash, prevActionHash }
 *
 *   agentId, sessionId   gateway-issued UUID v4
 *   seq                  safe integer >= 1, the session's nextSeq at authorisation
 *   prevActionHash       the previous action's hash of the SAME session; null exactly when seq = 1
 *   tool.schemaHash      SHA-256("QODIQA::TOOL_SCHEMA::V1" || JCS-P1(argument JSON Schema)): a changed schema is a different tool (TOOL_SCHEMA_CHANGED)
 *   args                 the exact arguments, a JSON object under JCS-P1 (decimals allowed; NFC strings, no duplicate keys, <= 64 levels, <= MAX_ARGS_BYTES)
 *   parentRequestHash    the V2 requestHash of the model request in whose context the action was proposed, or null
 *
 * The document is validated BEFORE hashing and every failure is a precise ActionHashError code; JCS-P1 failures keep their JcsError code under
 * `cause`. The same computation exists in Python (scripts/protocol/verify_action_vectors.py) and is pinned by docs/protocol/vectors/action.json.
 */

const crypto = require('crypto');
const { canonicalJcsP1, JcsError } = require('../../validation/jcsP1');

const ACTION_DOMAIN = 'QODIQA::ACTION::V2';
const TOOL_SCHEMA_DOMAIN = 'QODIQA::TOOL_SCHEMA::V1';
const MAX_ARGS_BYTES = 262_144;                 // 256 KiB of canonical arguments
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const TENANT_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SERVER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TOOL_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;

class ActionHashError extends Error {
  constructor(code, detail, cause) { super(detail ? `${code}: ${detail}` : code); this.name = 'ActionHashError'; this.code = code; if (cause) this.cause = cause; }
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Validate and normalise the parts into the exact document A (key order is irrelevant: JCS sorts). */
function buildActionDocument(p) {
  if (!isObj(p)) throw new ActionHashError('ACTION_INVALID', 'not an object');
  const bad = (code, d) => { throw new ActionHashError(code, d); };
  if (typeof p.tenantId !== 'string' || !TENANT_RE.test(p.tenantId)) bad('ACTION_INVALID_TENANT');
  if (typeof p.agentId !== 'string' || !UUID_V4.test(p.agentId)) bad('ACTION_INVALID_AGENT');
  if (typeof p.sessionId !== 'string' || !UUID_V4.test(p.sessionId)) bad('ACTION_INVALID_SESSION');
  if (!Number.isSafeInteger(p.seq) || p.seq < 1) bad('ACTION_INVALID_SEQ');
  if (!isObj(p.tool) || Object.keys(p.tool).sort().join(',') !== 'name,schemaHash,server') bad('ACTION_INVALID_TOOL', 'tool is exactly { server, name, schemaHash }');
  if (typeof p.tool.server !== 'string' || !SERVER_RE.test(p.tool.server)) bad('ACTION_INVALID_TOOL', 'server');
  if (typeof p.tool.name !== 'string' || !TOOL_RE.test(p.tool.name)) bad('ACTION_INVALID_TOOL', 'name');
  if (typeof p.tool.schemaHash !== 'string' || !HEX64.test(p.tool.schemaHash)) bad('ACTION_INVALID_TOOL', 'schemaHash');
  if (!isObj(p.args)) bad('ACTION_INVALID_ARGS', 'args must be a JSON object');
  if (p.parentRequestHash !== null && !(typeof p.parentRequestHash === 'string' && HEX64.test(p.parentRequestHash))) bad('ACTION_INVALID_PARENT');
  if (p.prevActionHash !== null && !(typeof p.prevActionHash === 'string' && HEX64.test(p.prevActionHash))) bad('ACTION_INVALID_PREV');
  if ((p.seq === 1) !== (p.prevActionHash === null)) bad('ACTION_INVALID_PREV', 'prevActionHash is null exactly when seq is 1');
  return { v: 2, tenantId: p.tenantId, agentId: p.agentId, sessionId: p.sessionId, seq: p.seq, tool: { server: p.tool.server, name: p.tool.name, schemaHash: p.tool.schemaHash },
    args: p.args, parentRequestHash: p.parentRequestHash, prevActionHash: p.prevActionHash };
}

function _canonical(value, maxBytes) {
  try { return canonicalJcsP1(value, { maxBytes }); } catch (e) { if (e instanceof JcsError) throw new ActionHashError('ACTION_ARGS_NOT_CANONICALIZABLE', e.code, e); throw e; }
}

/** @returns {string} lower-case hex SHA-256 */
function computeActionHash(parts) {
  const doc = buildActionDocument(parts);
  return crypto.createHash('sha256').update(ACTION_DOMAIN, 'utf8').update(_canonical(doc, MAX_ARGS_BYTES + 4096), 'utf8').digest('hex');
}

/** SHA-256("QODIQA::TOOL_SCHEMA::V1" || JCS-P1(schema)) - the schema is a JSON object. */
function computeSchemaHash(schema) {
  if (!isObj(schema)) throw new ActionHashError('SCHEMA_INVALID', 'a JSON Schema is an object');
  let text;
  try { text = canonicalJcsP1(schema, { maxBytes: 65_536 }); } catch (e) { if (e instanceof JcsError) throw new ActionHashError('SCHEMA_NOT_CANONICALIZABLE', e.code, e); throw e; }
  return crypto.createHash('sha256').update(TOOL_SCHEMA_DOMAIN, 'utf8').update(text, 'utf8').digest('hex');
}

/** Constant-time comparison of two hex hashes. */
function hashesEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== 64 || b.length !== 64) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

module.exports = { ACTION_DOMAIN, TOOL_SCHEMA_DOMAIN, MAX_ARGS_BYTES, ActionHashError, buildActionDocument, computeActionHash, computeSchemaHash, hashesEqual };
