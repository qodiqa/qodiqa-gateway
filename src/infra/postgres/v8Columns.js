'use strict';

/**
 * Audit v8 (migration 083): the values of the ten new audit_chain columns for one entry, in column order
 * (issued_at, protocol_version, agent_id, session_id, action_seq, action_hash, approval_ref, dlp, bytes_delivered,
 * completion_status). `m` is the entry as returned by projectEntryForMirror (text fields projected, dlp projected).
 * Entries of a lower schema version carry none of these fields, so every value is NULL for them. Shared by the
 * single-writer mirror insert and the distributed-ordering insert so both store the same shape.
 */
function v8InsertValues(m) {
  const isV8 = m.schemaVersion === 8;
  const pick = (f) => (isV8 && m[f] !== undefined ? m[f] : null);
  return [
    pick('issuedAt'), pick('protocolVersion'), pick('agentId'), pick('sessionId'), pick('actionSeq'), pick('actionHash'),
    pick('approvalRef'), isV8 && m.dlp != null ? JSON.stringify(m.dlp) : null, pick('bytesDelivered'), pick('completionStatus'),
  ];
}

module.exports = { v8InsertValues };
