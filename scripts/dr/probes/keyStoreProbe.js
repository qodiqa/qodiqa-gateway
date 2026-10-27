'use strict';

/**
 * Key Store restore probe — runs as a CHILD PROCESS (see validate.js) so
 * QODIQA_KEYS_PATH / QODIQA_KEYS_ARCHIVE_PATH can point at restored files in
 * isolation. Exercises the real production module
 * (services/artifact/keyStore.js).
 *
 * Two tiers:
 *   1. Structural validation (validateKeyStore()) — always attempted, and
 *      does not ITSELF require the KEK. Proves the restored file parses and
 *      its structural invariants (ownership, single-active-key, lifecycle
 *      fields) hold. In practice, for any store with at least one active key
 *      (i.e. every real deployment), keyStore.js's own fail-closed load path
 *      decrypts eagerly and throws before validateKeyStore() can even run if
 *      the KEK is absent — so "structural-only, no KEK needed" is only
 *      actually reachable for an empty/never-rotated store. That is still
 *      correct, fail-closed behavior (the probe reports invalid either way
 *      — see VALIDATION_THREW below), just not a graceful partial pass for
 *      the common case; QODIQA_DR_REQUIRE_KEK_ROUNDTRIP's explicit
 *      KEK_ROUNDTRIP_REQUIRED_BUT_KEK_ABSENT reason primarily matters for
 *      the empty-store edge case where it WOULD otherwise pass.
 *   2. Cryptographic round-trip — only runs if QODIQA_KEY_ENCRYPTION_KEY is
 *      present in the environment (the KEK is deliberately NOT part of any
 *      backup — see docs/operations/backup-runbook.md §8.1; the operator
 *      setting this env var in the restore/drill environment IS the
 *      "simulate out-of-band KEK recovery" step). Two proofs run, both
 *      using the real production primitives (never reimplemented here):
 * a. Known-plaintext KEK round-trip — encrypt a fresh probe
 *           plaintext under the recovered KEK via the real
 *           services/artifact/keyEncryption.js (the same module keyStore.js
 *           itself uses to encrypt/decrypt private keys at rest), decrypt
 *           it back, and byte-compare against the original. This is the
 *           literal "encrypt -> simulate recovery -> recover KEK -> decrypt
 *           -> compare plaintext" proof — independent of any pre-existing
 *           stored key material, so it also catches a KEK that is simply
 *           wrong (would silently fail GCM auth-tag verification on the
 *           REAL stored keys below in a way that's easy to misattribute to
 *           key-store corruption instead of KEK recovery failure).
 *        b. Per-client decrypt + Ed25519 sign/verify — decrypts each
 *           client's REAL active key and performs a fresh sign+verify to
 *           prove "signatures remain valid", plus the key fingerprint
 *           (QODIQA-PROTOCOL-SPEC.md §12.3 formula) so the caller can check
 *           "key fingerprints unchanged" against the pre-restore value.
 *
 * QODIQA_DR_REQUIRE_KEK_ROUNDTRIP=true makes tier 2 MANDATORY: if set
 * and QODIQA_KEY_ENCRYPTION_KEY is absent, this probe reports valid:false
 * rather than silently degrading to structural-only validation. This is what
 * lets a scheduled/CI DR drill assert the KEK-recovery proof actually ran
 * (not merely "ran if someone happened to remember to pass a KEK") — see
 * .github/workflows/backup-restore.yml's dr-file-based job and
 * docs/operations/disaster-recovery.md's periodic KEK-recovery drill
 * section. Left unset (the default) for restore-validation runs that are
 * legitimately scoped away from KEK access (e.g. the standalone-pod K8s
 * CronJob — see deploy/kubernetes/base/backup-cronjobs.yaml's "Known scope
 * boundary" note), where skipping tier 2 is correct, disclosed behavior,
 * not a gap to paper over.
 */

const crypto = require('crypto');

// THROUGHPUT-12: services/logger.js batches INFO/WARN/ERROR stdout writes and
// flushes them asynchronously — this probe's own result line below is parsed
// positionally by validate.js's _lastJsonLine(), so any not-yet-flushed
// structured log line must be drained BEFORE that print (flush() does its
// actual work synchronously — see that file's header comment).
const _flushLogger = () => require('../../../services/logger').flush();

let keyStore, ed25519, keyEncryption;
try {
  keyStore      = require('../../../services/artifact/keyStore.js');
  ed25519       = require('../../../src/infra/crypto/ed25519.js');
  keyEncryption = require('../../../services/artifact/keyEncryption.js');
} catch (err) {
  _flushLogger();
  console.log(JSON.stringify({ valid: false, reason: `MODULE_LOAD_FAILED: ${err.message}` }));
  process.exit(1);
}

const REQUIRE_KEK_ROUNDTRIP = process.env.QODIQA_DR_REQUIRE_KEK_ROUNDTRIP === 'true';

/**
 * Known-plaintext round trip: encrypt -> recover KEK (already done —
 * QODIQA_KEY_ENCRYPTION_KEY is set in this process's env) -> decrypt ->
 * compare plaintext. Uses the REAL AES-256-GCM primitive keyStore.js itself
 * relies on, not a reimplementation.
 */
function _kekRoundTrip() {
  const plaintext = crypto.randomBytes(32);
  try {
    const encrypted = keyEncryption.encryptKeyMaterial(plaintext, { keyId: 'dr-kek-roundtrip-probe' });
    const decrypted = keyEncryption.decryptKeyMaterial(encrypted);
    return { ok: Buffer.compare(plaintext, decrypted) === 0, plaintextMatch: Buffer.compare(plaintext, decrypted) === 0 };
  } catch (err) {
    return { ok: false, plaintextMatch: false, error: err.message };
  }
}

function fingerprint(publicKeyB64) {
  return crypto.createHash('sha256').update(publicKeyB64, 'utf8').digest('hex');
}

try {
  const structural = keyStore.validateKeyStore();
  const structurallyValid = structural.violations.length === 0 && structural.expiredKeys.length === 0;

  const result = { valid: structurallyValid, structural, cryptoRoundTrip: null };

  if (process.env.QODIQA_KEY_ENCRYPTION_KEY) {
    const clientIds = [...new Set(keyStore.listKeys().map(k => k.clientId))];
    const perClient = [];
    let allOk = true;

    for (const clientId of clientIds) {
      try {
        const active = keyStore.getActiveKey(clientId);
        const probe  = crypto.createHash('sha256').update('qodiqa-dr-restore-probe', 'utf8').digest();
        const sig    = ed25519.sign(probe, active.privDer);
        const sigOk  = ed25519.verify(probe, sig, active.pubDer);
        perClient.push({
          clientId,
          keyId: active.keyId,
          signVerifyOk: sigOk,
          keyFingerprint: fingerprint(active.publicKeyB64 || active.pubDer.toString('base64')),
        });
        if (!sigOk) allOk = false;
      } catch (err) {
        perClient.push({ clientId, error: err.message });
        allOk = false;
      }
    }

    const kekRoundTrip = _kekRoundTrip();

    result.cryptoRoundTrip = { ok: allOk && kekRoundTrip.ok, perClient, kekRoundTrip };
    result.valid = result.valid && allOk && kekRoundTrip.ok;
  } else if (REQUIRE_KEK_ROUNDTRIP) {
    // this run declared (via QODIQA_DR_REQUIRE_KEK_ROUNDTRIP=true) that
    // the cryptographic KEK-recovery proof is mandatory, not best-effort —
    // fail closed rather than silently degrading to structural-only
    // validation, which is exactly the gap identified ("a DR drill can
    // report a clean pass while never actually proving keys are usable").
    result.valid = false;
    result.reason = 'KEK_ROUNDTRIP_REQUIRED_BUT_KEK_ABSENT';
  }

  _flushLogger();
  console.log(JSON.stringify(result));
  process.exit(result.valid ? 0 : 1);
} catch (err) {
  _flushLogger();
  console.log(JSON.stringify({ valid: false, reason: `VALIDATION_THREW: ${err.message}` }));
  process.exit(1);
}
