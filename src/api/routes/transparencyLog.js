'use strict';

/**
 * QODIQA Transparency Log API — Component #22
 *
 * Two router factories for different trust levels:
 *
 * createTransparencyPublicRouter()
 *   — No authentication required; rate-limited only.
 *   — Mounted at /transparency in server.js (before ops auth middleware).
 *   — GET /entry/:transparencyId      — fetch entry by UUID
 *   — GET /entries                    — paginated list (no payload field)
 *   — GET /root                       — latest root digest
 *   — GET /roots                      — paginated root list
 *   — GET /verify/:transparencyId     — verify entry (integrity + sig)
 *   — GET /proof/:transparencyId      — inclusion proof for offline verification; proofVerification.valid only
 * when the proof verifies AND the entry + root signatures authenticate
 *   — GET /consistency/:from/:to      — RFC 6962 consistency proof; verification.valid only when the proof
 * verifies AND both roots' signatures authenticate
 *
 * createTransparencyAdminRouter({ requirePermission })
 *   — Requires ops auth + RBAC (via mount-level middleware in server.js).
 *   — Mounted at /transparency in server.js (after ops auth middleware).
 *   — GET  /admin/stats               — aggregate statistics (READ_TRANSPARENCY_LOG)
 *   — GET  /admin/chain/validate      — chain continuity check (READ_TRANSPARENCY_LOG)
 *   — POST /register                  — register new entry (MANAGE_TRANSPARENCY_LOG)
 *   — POST /admin/roots/generate      — trigger root generation (MANAGE_TRANSPARENCY_LOG)
 */

const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const { Router }           = require('express');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { emit }             = require('../../../services/logger');
const { success, failure, internalError } = require('../response');
const logStore             = require('../../core/transparency/logStore');
const registrar            = require('../../core/transparency/registrar');
const log                  = require('../../core/transparency/log');
const proofLookup          = require('../../core/transparency/proofLookup');
const { checkSignatureTrust } = require('../../core/transparency/signatureTrust');
const keyManager           = require('../../../services/artifact/keyManager');
const metrics              = require('../../observability/metrics');
const gapHandler           = require('../../core/transparencyGap');
const { transparencyIdParamSchema, registerEntryBodySchema } = require('../../validation/schemas/transparency.schema');
const { getReceipt } = require('../../core/transparency/receiptStore');
const RECEIPT_REQUEST_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const {
  parsePagination, parseSortOrder, withPaginationMeta,
} = require('../../utils/pagination');

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_PAGE_SIZE     = 500;
const DEFAULT_PAGE_SIZE = 50;

// ── Response helpers ──────────────────────────────────────────────────────────

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (data, req, status) call-site ergonomics — the actual
// envelope shape is built in exactly one place, response.js.
function _ok(res, data, req, status) {
  return success(res, data, status || 200);
}

function _notFound(res, req, message) {
  return failure(res, 'NOT_FOUND', message, 404);
}

function _badRequest(res, req, message) {
  return failure(res, 'INVALID_PARAM', message, 400);
}

// API-2: delegates to the centralized src/api/response.js implementation.
function _internalError(res, req, err, label) {
  return internalError(res, req, err, { label: label || 'TRANSPARENCY_API_ERROR' });
}

// Delegates to the canonical pagination utility (src/utils/pagination.js —
// API-4 remediation); kept as a thin local wrapper so call sites below don't
// need to change. Also accepts the legacy `limit`/`offset`/`sortDir`/`sort`
// aliases via that shared parser.
function _pagination(query) {
  const { page, pageSize } = parsePagination(query, { defaultPageSize: DEFAULT_PAGE_SIZE, maxPageSize: MAX_PAGE_SIZE });
  const sortOrder = parseSortOrder(query);
  return { page, pageSize, sortOrder };
}

function _actor(req) {
  return req.rbacUser?.username ?? 'system';
}

const _UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function _isUUID(s) {
  return typeof s === 'string' && _UUID_RE.test(s);
}

// ── Verification helper ───────────────────────────────────────────────────────

// Transparency key statuses whose signatures verify — the existing lifecycle policy, identical to the public trust set
// (well-known.js VERIFIABLE) and the evidence-bundle verifier (generator.js): an active key, or a deprecated one
// so historical entries stay verifiable. 'revoked' (and an unknown keyId) never verifies.
const _VERIFIABLE_TRANSPARENCY_KEY_STATUSES = new Set(['active', 'deprecated']);

/**
 * Verify a transparency entry's signature against the TRANSPARENCY key store (never the artifact key store).
 * Returns the SIGNATURE check plus the reported signatureValid / signerKeyStatus. Reasons are fixed codes only —
 * no key material, signature bytes or error text leave this function.
 *
 *   PASS  signature verifies under an active/deprecated transparency key           signatureValid true
 *   FAIL  no signer keyId, unknown keyId, a non-verifiable status (e.g. revoked),
 *         or a signature that does not verify                                      signatureValid false
 *   SKIP  the key store could not be consulted (signature not verified)            signatureValid null
 *
 * @param {object} entryRecord — DB row from transparency_log_entries
 * @returns {{ signatureValid: boolean|null, signerKeyStatus: string|null, check: object }}
 */
function _checkEntrySignature(entryRecord) {
  const keyId = entryRecord.signer_key_id ?? entryRecord.signerKeyId ?? null;
  const fail = (signerKeyStatus, reason) => ({ signatureValid: false, signerKeyStatus, check: { check: 'SIGNATURE', result: 'FAIL', reason } });
  const skip = (signerKeyStatus, reason) => ({ signatureValid: null,  signerKeyStatus, check: { check: 'SIGNATURE', result: 'SKIP', reason } });

  if (typeof keyId !== 'string' || keyId === '') return fail(null, 'SIGNER_KEY_ID_MISSING');

  let status;
  try {
    status = keyManager.getTransparencyKeyStatus(keyId);
  } catch {
    return skip(null, 'KEY_STORE_UNAVAILABLE');
  }
  if (status === null || status === undefined) return fail('unknown', 'UNKNOWN_KEY');
  if (!_VERIFIABLE_TRANSPARENCY_KEY_STATUSES.has(status)) return fail(status, 'KEY_NOT_VERIFIABLE');

  let keyInfo;
  try {
    keyInfo = keyManager.getTransparencyVerificationKey(keyId);
  } catch {
    return skip(status, 'KEY_STORE_UNAVAILABLE');
  }
  if (!keyInfo || !Buffer.isBuffer(keyInfo.pubDer)) return skip(status, 'KEY_STORE_UNAVAILABLE');

  return log.verifyEntrySignature(entryRecord, keyInfo.pubDer)
    ? { signatureValid: true, signerKeyStatus: status, check: { check: 'SIGNATURE', result: 'PASS' } }
    : fail(status, 'SIGNATURE_INVALID');
}

// ── Proof authentication (ST23-04 / ST23-07 /) ──────────────────
// The inclusion (/proof) and consistency (/consistency) verifiers are structural/hash-only by design
// (log.verifyInclusionProof, log.verifyConsistencyProof). These routes add the authentication half before any result
// is reported as valid: each record the proof rests on must be signed under a verifiable transparency key, resolved
// exactly like /verify (keyManager → transparency key store, never the artifact store; no per-request reload — R-7).
// The checks themselves are the shared signatureTrust.js (also the background root audit, ST23-03).
const _routeTransparencyKeys = Object.freeze({
  getKeyStatus: (keyId) => keyManager.getTransparencyKeyStatus(keyId),
  getPublicKey: (keyId) => keyManager.getTransparencyVerificationKey(keyId),
});

/** One authentication check row: PASS, FAIL (not authentic), or SKIP (key store unusable — not verified). */
function _authCheck(name, kind, record) {
  const r = checkSignatureTrust(kind, record, { keys: _routeTransparencyKeys });
  if (r.ok) return { check: name, result: 'PASS', keyStatus: r.keyStatus };
  return { check: name, result: r.unavailable ? 'SKIP' : 'FAIL', reason: r.code, ...(r.keyStatus ? { keyStatus: r.keyStatus } : {}) };
}

/**
 * Combine a structural verification ({ valid, checks, failedCheck, failureReason }) with authentication checks.
 * `valid` is true ONLY when the structure verifies AND every authentication check PASSes — fail-closed: a SKIP
 * (unusable key store) is not authenticated. `structurallyValid` and `authenticated` keep the two halves
 * distinguishable; the structural checks keep their original rows and order.
 */
function _withAuthentication(structural, authChecks) {
  const authenticated = authChecks.every((c) => c.result === 'PASS');
  const firstAuthGap = authChecks.find((c) => c.result !== 'PASS') || null;
  const structurallyValid = structural.valid === true;
  return {
    valid:             structurallyValid && authenticated,
    structurallyValid,
    authenticated,
    checks:            [...structural.checks, ...authChecks],
    failedCheck:       structurallyValid ? (firstAuthGap ? firstAuthGap.check : null) : structural.failedCheck,
    failureReason:     structurallyValid ? (firstAuthGap ? firstAuthGap.reason : null) : structural.failureReason,
  };
}

/**
 * Run full integrity + signature verification for a single entry record.
 * Persists the verification run (fire-and-forget).
 *
 * @param {object} entryRecord — DB row from transparency_log_entries
 * @param {string} verifiedBy
 * @returns {Promise<object>} structured verification report
 */
async function _verifyEntry(entryRecord, verifiedBy, { record = true } = {}) {
  const start = Date.now();

  // Fetch the prior entry (the one whose entry_hash matches this entry's
  // previous_entry_hash) for chain link verification. A null result here
  // (lookup failed, or genuinely no matching entry — e.g. it was spliced
  // out) is treated by verifyEntryIntegrity() as a hard failure when
  // previous_entry_hash is present, not a silent skip.
  let priorRecord = null;
  if (entryRecord.previous_entry_hash) {
    try {
      priorRecord = await logStore.getByEntryHash(entryRecord.previous_entry_hash);
    } catch { /* best-effort — verifyEntryIntegrity treats null priorRecord as FAIL */ }
  }

  // Integrity checks (payload hash, entry hash, chain link)
  const integrityResult = log.verifyEntryIntegrity(entryRecord, priorRecord);

  // Signature verification (Stage 27): the signer key is resolved from the TRANSPARENCY key store — transparency
  // leaves are signed with tr-* keys that the artifact key store never holds, so the previous artifact-store lookup
  // always threw, signatureValid stayed null and the signature never reached the verdict.
  const { signatureValid, signerKeyStatus, check: signatureCheck } = _checkEntrySignature(entryRecord);

  if (signatureValid === false) {
    metrics.transparencyVerificationFailuresTotal.inc({});
    emit('ERROR', 'TRANSPARENCY_SIGNATURE_INVALID', {
      transparencyId: entryRecord.transparency_id,
      signerKeyId:    entryRecord.signer_key_id,
      reason:         signatureCheck.reason,
    });
  } else if (!integrityResult.valid) {
    metrics.transparencyVerificationFailuresTotal.inc({});
    emit('ERROR', 'TRANSPARENCY_INTEGRITY_VIOLATION', {
      transparencyId: entryRecord.transparency_id,
      failedCheck:    integrityResult.failedCheck,
      failureReason:  integrityResult.failureReason,
    });
  }

  // The verdict covers integrity AND signature: an unverified signature (SKIP) yields PARTIAL and a rejected one
  // (FAIL) yields INVALID — VALID requires every check, the signature included, to PASS. Integrity checks come first,
  // so an integrity failure is still the reported firstFailure.
  const allChecks = [...integrityResult.checks, signatureCheck];

  const report = log.assembleVerificationReport(
    entryRecord,
    allChecks,
    { verifiedBy, signatureValid, signerKeyStatus },
  );
  // The response's integrityChecks stay the three integrity checks; the signature outcome is reported separately
  // (signatureValid / signerKeyStatus, and firstFailure when it is the first failing check).
  report.integrityChecks = integrityResult.checks;

  const durationMs = Date.now() - start;

  // Record verification (fire-and-forget). (D7 → B): only for an
  // authenticated caller — an anonymous verification is not persisted.
  if (record) logStore.recordVerification({
    transparencyId:    entryRecord.transparency_id,
    verificationType:  'ENTRY',
    verificationResult: report.overallResult,
    checksPerformed:   allChecks,
    failedCheck:       report.firstFailure?.check ?? null,
    failureReason:     report.firstFailure?.reason ?? null,
    verifiedBy,
    durationMs,
  });

  return { ...report, durationMs };
}

// ── Public router factory ─────────────────────────────────────────────────────

/**
 * Create the public-facing transparency verification router.
 * All routes are accessible without authentication.
 *
 * @returns {import('express').Router}
 */
// (NF-3): public consistency proofs read every leaf hash up to the newer
// root; bound that work (size cap) and never repeat it for the same pair
// (roots are immutable). A checkpoint-based O(log n) proof is a input.
const CONSISTENCY_MAX_LEAVES = (() => { const v = parseInt(process.env.QODIQA_TRANSPARENCY_CONSISTENCY_MAX_LEAVES || '250000', 10); return Number.isInteger(v) && v > 0 ? v : 250000; })();
const CONSISTENCY_CACHE_MAX = 256;
const _consistencyCache = new Map();

function createTransparencyPublicRouter({ optionalAuth } = {}) {
  const router = Router();
  // T-1 / R-09: this limiter runs on THIS router's public routes only (passed first on each route below),
  // not router.use(): this router is mounted before the admin stack on the same prefix, and a prefix-wide limiter also
  // ran for the admin paths — under a burst an anonymous admin path answered 429 instead of reaching the admin plane's
  // pre-auth gate (404 when disabled, OD-3). Public routes keep exactly the same limit
  // (src/api/routes/__tests__/publicRouterLimiterScope.test.js).
  const _surfaceLimit = createRateLimitMiddleware('transparency', { envelope: 'management' });
  // (D7 → B): GET /verify/:id records a verification row only for an
  // authenticated caller with READ_TRANSPARENCY_LOG; anonymous calls get the
  // full report and record nothing.
  const _optional = optionalAuth || ((_q, _s, n) => n());
  const _verifyLimit = createRateLimitMiddleware('public_verify', { envelope: 'management' });

  // ── GET /entry/:transparencyId ─────────────────────────────────────────────

  router.get('/entry/:transparencyId', _surfaceLimit, async (req, res) => {
    const { transparencyId } = req.params;

    if (!transparencyIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `transparencyId must be a valid UUID`);
    }

    try {
      const entry = await logStore.getByTransparencyId(transparencyId);
      if (!entry) {
        return _notFound(res, req, `Transparency entry not found: ${transparencyId}`);
      }
      // Exclude full payload from public listing; include payload_hash only.
      const { payload: _p, ...publicEntry } = entry;
      return _ok(res, { entry: publicEntry }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /receipt/:requestId ────────────────────────────────────────────────
  // (V2-FREEZE section 6): the signed receipt of a request's decision. Authorized by knowledge of the requestId (a UUID,
  // 122 bits) — the one deliberate exception to "every endpoint is authenticated"; the body is the receipt and nothing else
  // (no tenant, no reason). Receipts are kept for a bounded window (receiptStore.js); after it the answer is 404.
  router.get('/receipt/:requestId', _surfaceLimit, async (req, res) => {
    const { requestId } = req.params;
    if (typeof requestId !== 'string' || !RECEIPT_REQUEST_ID_RE.test(requestId)) {
      return _badRequest(res, req, 'requestId must be a valid UUID');
    }
    try {
      const receipt = await getReceipt(requestId);
      if (!receipt) return _notFound(res, req, 'Receipt not found (unknown requestId, or the retrieval window has passed).');
      return _ok(res, { receipt }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /entries ───────────────────────────────────────────────────────────

  router.get('/entries', _surfaceLimit, async (req, res) => {
    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);

      const result = await logStore.listEntries({
        entryType:   req.query.entryType   || undefined,
        artifactId:  req.query.artifactId  || undefined,
        signerKeyId: req.query.signerKeyId || undefined,
        // no public tenant filter — ?tenantId is ignored here.
        startTime:   req.query.startTime   || undefined,
        endTime:     req.query.endTime     || undefined,
        page,
        pageSize,
        sortOrder,
      });

      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /root ──────────────────────────────────────────────────────────────

  router.get('/root', _surfaceLimit, async (req, res) => {
    try {
      const rootId = req.query.rootId;
      let root;

      if (rootId) {
        if (!transparencyIdParamSchema.safeParse({ transparencyId: rootId }).success) {
          return _badRequest(res, req, `rootId must be a valid UUID`);
        }
        root = await logStore.getRootById(rootId);
        if (!root) {
          return _notFound(res, req, `Transparency root not found: ${rootId}`);
        }
      } else {
        root = await logStore.getLatestRoot();
        if (!root) {
          return _ok(res, { root: null, message: 'No roots have been generated yet' }, req);
        }
      }

      return _ok(res, { root }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /roots ─────────────────────────────────────────────────────────────

  router.get('/roots', _surfaceLimit, async (req, res) => {
    try {
      // Preserves this endpoint's pre-existing default/max (20/200), which is
      // intentionally lower than this file's /entries default/max (50/500) —
      // roots are a smaller, coarser-grained collection.
      const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 20, maxPageSize: 200 });

      const result = await logStore.listRoots({ page, pageSize });
      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /verify/:transparencyId ────────────────────────────────────────────

  router.get('/verify/:transparencyId', _surfaceLimit, _optional, _verifyLimit, async (req, res) => {
    const { transparencyId } = req.params;

    if (!transparencyIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `transparencyId must be a valid UUID`);
    }

    try {
      const entry = await logStore.getForVerification(transparencyId) /* full row as qodiqa_system; verdicts only leave */;
      if (!entry) {
        return _notFound(res, req, `Transparency entry not found: ${transparencyId}`);
      }

      // the recorder is the authenticated identity, never a caller-chosen query value.
      const verifiedBy = req.rbacUser ? (req.rbacUser.username || req.rbacUser.id) : 'public';
      const report     = await _verifyEntry(entry, verifiedBy, { record: !!req.rbacUser });

      metrics.transparencyVerificationsTotal.inc({ result: report.overallResult });

      return _ok(res, {
        transparencyId,
        verifiedAt:   new Date().toISOString(),
        durationMs:   report.durationMs,
        result:       report.overallResult,
        signatureValid: report.signatureValid,
        signerKeyStatus: report.signerKeyStatus,
        integrityChecks: report.integrityChecks,
        firstFailure:  report.firstFailure,
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /proof/:transparencyId ─────────────────────────────────────────────

  router.get('/proof/:transparencyId', _surfaceLimit, async (req, res) => {
    const { transparencyId } = req.params;

    if (!transparencyIdParamSchema.safeParse(req.params).success) {
      return _badRequest(res, req, `transparencyId must be a valid UUID`);
    }

    try {
      const entry = await logStore.getByTransparencyId(transparencyId);
      if (!entry) {
        return _notFound(res, req, `Transparency entry not found: ${transparencyId}`);
      }

      const { proof, proofVerification, message } = await proofLookup.getInclusionProofForEntry(entry);
      if (!proof) {
        return _ok(res, { transparencyId, proof: null, message }, req);
      }

      // ST23-04 / the inclusion proof is reported valid only when the leaf's entry signature and the covering
      // root's signature are both authenticated (proof.root carries the stored root's signature + signer key id).
      return _ok(res, {
        transparencyId,
        proof,
        proofVerification: _withAuthentication(proofVerification, [
          _authCheck('ENTRY_SIGNATURE', 'entry', entry),
          _authCheck('ROOT_SIGNATURE', 'root', proof.root),
        ]),
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /consistency/:fromRootId/:toRootId ─────────────────────────────────
  // RFC6962 Merkle consistency proof between two roots.
  // Proves that tree(fromRoot) is a cryptographic prefix of tree(toRoot).

  router.get('/consistency/:fromRootId/:toRootId', _surfaceLimit, async (req, res) => {
    const { fromRootId, toRootId } = req.params;

    // Reuse the UUID schema for both params
    if (!transparencyIdParamSchema.safeParse({ transparencyId: fromRootId }).success ||
        !transparencyIdParamSchema.safeParse({ transparencyId: toRootId  }).success) {
      return _badRequest(res, req, 'fromRootId and toRootId must be valid UUIDs');
    }

    try {
      const [oldRoot, newRoot] = await Promise.all([
        logStore.getRootById(fromRootId),
        logStore.getRootById(toRootId),
      ]);

      if (!oldRoot) return _notFound(res, req, `Root not found: ${fromRootId}`);
      if (!newRoot) return _notFound(res, req, `Root not found: ${toRootId}`);

      if (Number(oldRoot.seq_to) > Number(newRoot.seq_to)) {
        return _badRequest(res, req, 'fromRootId must reference an older (smaller) tree than toRootId');
      }

      // ST23-07 / both roots are authenticated on EVERY request (a key can be revoked after a proof was cached);
      // only the structural proof is cached.
      const authChecks = [
        _authCheck('FROM_ROOT_SIGNATURE', 'root', oldRoot),
        _authCheck('TO_ROOT_SIGNATURE', 'root', newRoot),
      ];

      // (NF-3): roots are immutable, so a (from, to) proof never changes —
      // serve repeats from a bounded cache; the leaf read is hash-only (no
      // tenant metadata, app-executable) and refused above a configured size.
      const cacheKey = fromRootId + ':' + toRootId;
      let structural = _consistencyCache.get(cacheKey);
      if (!structural) {
        if (Number(newRoot.seq_to) > CONSISTENCY_MAX_LEAVES) {
          return failure(res, 'CONSISTENCY_RANGE_TOO_LARGE',
            `Consistency proofs are served for trees up to ${CONSISTENCY_MAX_LEAVES} entries (QODIQA_TRANSPARENCY_CONSISTENCY_MAX_LEAVES)`, 422);
        }
        const entries = await logStore.getHashesInRange(1, Number(newRoot.seq_to));
        const allHashes = entries.map(e => e.entry_hash);

        const consistencyProofObj = log.generateConsistencyProof(oldRoot, newRoot, allHashes);
        structural = { consistencyProof: consistencyProofObj, verification: log.verifyConsistencyProof(consistencyProofObj) };
        if (_consistencyCache.size >= CONSISTENCY_CACHE_MAX) _consistencyCache.delete(_consistencyCache.keys().next().value);
        _consistencyCache.set(cacheKey, structural);
      }

      return _ok(res, {
        fromRootId, toRootId,
        consistencyProof: structural.consistencyProof,
        verification:     _withAuthentication(structural.verification, authChecks),
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  return router;
}

// ── Admin router factory ──────────────────────────────────────────────────────

/**
 * Create the admin transparency router.
 * Mounted behind ops auth + RBAC middleware in server.js.
 *
 * @param {{ requirePermission?: function(string): function }} options
 * @returns {import('express').Router}
 */
function createTransparencyAdminRouter({ requirePermission } = {}) {
  const router = Router();
  router.use(createRateLimitMiddleware('transparency_admin', { envelope: 'management' }));

  const _canRead   = permissionGuard(requirePermission, 'READ_TRANSPARENCY_LOG', 'transparencyLog');
  const _canManage = permissionGuard(requirePermission, 'MANAGE_TRANSPARENCY_LOG', 'transparencyLog');

  // ── GET /admin/stats ───────────────────────────────────────────────────────

  router.get('/admin/stats', _canRead, async (req, res) => {
    try {
      const stats = await logStore.aggregateStats();
      return _ok(res, {
        stats: stats ?? {
          entries:       { total: 0 },
          roots:         { total: 0 },
          verifications: { total: 0 },
        },
        pgEnabled: stats !== null,
        generatedAt: new Date().toISOString(),
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── GET /admin/chain/validate ──────────────────────────────────────────────

  router.get('/admin/chain/validate', _canRead, async (req, res) => {
    const startId = req.query.startId != null ? Number(req.query.startId) : undefined;
    const endId   = req.query.endId   != null ? Number(req.query.endId)   : undefined;
    // Validation range knob, not a collection listing — see
    // API-4-REMEDIATION-REPORT.md "justified exceptions". Still centralizes
    // the limit clamp via the shared utility.
    const { limit } = parsePagination(req.query, { defaultPageSize: 1_000, maxPageSize: 10_000 });

    try {
      // Fetch entries in the specified range (or entire log if no range given)
      const entries = await logStore.getEntriesInRange(
        startId ?? 1,
        endId   ?? Number.MAX_SAFE_INTEGER,
      );

      // Trim to limit
      const window  = entries.slice(0, limit);
      const result  = log.validateChainContinuity(window);

      if (!result.valid) {
        metrics.transparencyVerificationFailuresTotal.inc({});
        emit('ERROR', 'TRANSPARENCY_CHAIN_CONTINUITY_FAILURE', {
          failureId:     result.failureId,
          failureDetail: result.failureDetail,
          checkedCount:  result.checkedCount,
        });

        // Classify and handle the gap.  Detect which gap type based on detail string.
        const isHashFailure = result.failureDetail?.includes('hash') ||
                              result.failureDetail?.includes('previousEntryHash');
        const gapCtx = {
          service:   'transparency',
          artifactId: null,
          details:   {
            failureId:     result.failureId,
            failureDetail: result.failureDetail,
            checkedCount:  result.checkedCount,
            startId,
            endId,
          },
        };
        const gapHandlerFn = isHashFailure
          ? gapHandler.detectHashChainBreak
          : gapHandler.detectSequenceBreak;
        gapHandlerFn(gapCtx).catch(() => {});
      }

      // Record the run
      logStore.recordVerification({
        transparencyId:   null,
        verificationType: 'CHAIN',
        verificationResult: result.valid ? 'VALID' : 'INVALID',
        checksPerformed:  [],
        failedCheck:      result.valid ? null : 'CHAIN_CONTINUITY',
        failureReason:    result.failureDetail,
        verifiedBy:       _actor(req),
      });

      return _ok(res, {
        chainValidation: result,
        startId:  startId  ?? null,
        endId:    endId    ?? null,
        limit,
        validatedAt: new Date().toISOString(),
        validatedBy: _actor(req),
      }, req);
    } catch (err) {
      return _internalError(res, req, err);
    }
  });

  // ── POST /register ─────────────────────────────────────────────────────────

  router.post('/register', _canManage, async (req, res) => {
    const regParsed = registerEntryBodySchema.safeParse(req.body ?? {});
    if (!regParsed.success) {
      return _badRequest(res, req, regParsed.error.issues[0]?.message ?? 'Invalid request body');
    }
    const {
      entryType, artifactId, evidenceChainId, verificationId, payload, tenantId,
    } = regParsed.data;

    try {
      const result = await registrar.register({
        entryType,
        artifactId:     artifactId     || null,
        evidenceChainId: evidenceChainId || null,
        verificationId: verificationId  ?? null,
        payload:        payload         || {},
        registeredBy:   _actor(req),
        tenantId:       tenantId        || null,
      });

      metrics.transparencyEntriesTotal.inc({ entry_type: entryType });

      return _ok(res, {
        transparencyId: result.transparencyId,
        entryHash:      result.entryHash,
        keyId:          result.keyId,
        persisted:      result.persisted,
        createdAt:      result.row?.created_at ?? new Date().toISOString(),
      }, req, 201);
    } catch (err) {
      emit('ERROR', 'TRANSPARENCY_REGISTER_FAILED', {
        entryType,
        requestId: req.requestId ?? null,
        error:     err.message,
      });
      return _internalError(res, req, err, 'TRANSPARENCY_REGISTER_FAILED');
    }
  });

  // ── POST /admin/roots/generate ─────────────────────────────────────────────

  router.post('/admin/roots/generate', _canManage, async (req, res) => {
    const generatedBy = _actor(req);

    try {
      const result = await registrar.generateRoot({ generatedBy });

      return _ok(res, {
        rootId:          result.rootId,
        seqFrom:         result.seqFrom,
        seqTo:           result.seqTo,
        entryCount:      result.entryCount,
        rootHash:        result.rootHash,
        previousRootHash: result.previousRootHash,
        keyId:           result.keyId,
        persisted:       result.persisted,
        generatedAt:     result.row?.generated_at ?? new Date().toISOString(),
      }, req, 201);
    } catch (err) {
      if (err.message?.includes('no new entries') || err.message?.includes('no transparency log entries')) {
        return _badRequest(res, req, err.message);
      }
      return _internalError(res, req, err, 'TRANSPARENCY_ROOT_GENERATE_FAILED');
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  createTransparencyPublicRouter,
  createTransparencyAdminRouter,
};
