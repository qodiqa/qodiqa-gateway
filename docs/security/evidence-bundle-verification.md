# Evidence Bundle — Offline Verification Guide

**Finding**: (P4) — self-contained offline evidence bundle
**Audience**: External auditors, regulators, customers, forensic investigators, SRE/Security Engineers
**Related**: `docs/security/cryptography.md` §18 (Evidence Package), `docs/glossary.md` "Evidence Bundle"/"Evidence Package"/"Evidence Chain", `docs/operations/audit-chain-integrity-verification.md`

---

## 1. What a bundle contains and proves

Retrieve a bundle with:

```bash
curl -sf \
  -H "Authorization: Bearer $QODIQA_OPS_TOKEN" \
  "http://localhost:3000/evidence/package/$ARTIFACT_ID/bundle" \
  | jq '.data' > evidence-bundle.json
```

The bundle is a single JSON document with three top-level parts:

| Field | What it proves |
|---|---|
| `evidencePackage` | The decision itself is authentic and unaltered — full Ed25519 signature + public key, the canonical audit-chain hash input (artifact/decision/policy/timing, and as the AI **provider and model identity**), and a package-level Ed25519 seal signed with QODIQA's active key. |
| `transparency.inclusionProof` (when `transparency.available` is `true`) | The same decision was entered into QODIQA's published, tamper-evident RFC6962 transparency log — an O(log n) Merkle audit path from the decision's leaf up to a signed transparency root. |
| `integrity` (bundle-level) | Binds the two together: one more Ed25519 signature over `{ evidencePackage, transparency }` combined, so neither half can be swapped independently of the other and still verify. |

`transparency.available` may legitimately be `false` (with a `note` explaining why) — transparency roots are generated periodically, not synchronously with every decision. A bundle with `transparency.available: false` still fully proves the evidence-package half; it simply cannot yet prove transparency-log inclusion. Re-request the bundle later once a root covering that decision has been published (`POST /transparency/admin/roots/generate` triggers generation).

## 2. Verifying offline

Copy `tools/verify/verify.bundle.external.js` (repository root) — a single file with **zero dependencies beyond Node's built-in `crypto` module**, no `require()` of anything else in this repository — to any machine with Node.js installed, including one with no network access at all:

**Trust anchors are required.** the verifier trusted the keys embedded in the bundle, so a bundle fabricated by anyone verified as valid. It now verifies every seal and every transparency signature only against keys you supply, obtained from the operator over a channel you trust — never from the bundle itself.

First, save the operator's published key sets:
- `GET /.well-known/qodiqa/keys` → `qodiqa-keys.json` (evidence and bundle seal keys);
- `GET /.well-known/qodiqa/transparency-keys` → `qodiqa-transparency-keys.json`.

Then run the verifier:

```bash
node tools/verify/verify.bundle.external.js --keys qodiqa-keys.json --transparency-keys qodiqa-transparency-keys.json evidence-bundle.json
```

You can pin a seal key by its fingerprint (SHA-256 of the SPKI DER) instead of passing `--keys`:

```bash
node tools/verify/verify.bundle.external.js --pin <spki-sha256-hex> --transparency-keys qodiqa-transparency-keys.json evidence-bundle.json
```

`tools/verify/verify.evidence.external.js` (a single package) takes the same `--keys` / `--pin` arguments.

Without trust anchors the verdict is `valid: false` with `TRUST_ANCHOR_REQUIRED`. The bundle's internal consistency is still reported as `selfConsistentBundleSignature`, but that is **not** an authenticity check.

Exit codes: `0` means `valid: true`; `1` means `valid: false`; `2` means an input or trust-file error. The script also prints a full JSON report to stdout:

```json
{
  "bundleHashValid": true,
  "bundleSignatureValid": true,
  "packageValid": true,
  "transparencyProofValid": true,
  "valid": true,
  "reasons": []
}
```

- `bundleHashValid` / `bundleSignatureValid` — the bundle envelope itself is unmodified and genuinely issued by QODIQA.
- `packageValid` — the nested evidence package's own three checks (package hash, seal signature, audit-chain hash) all pass; see `reasons` for which one failed if not.
- `transparencyProofValid` — `true`/`false` if a proof was present and checked, `null` if `transparency.available` was `false` (nothing to check — does not by itself invalidate the bundle). A proof is valid only if every one of these holds:
  - the leaf's `entryHash` recomputes from its fields;
  - the entry and root signatures verify under a **trusted transparency key**;
  - the Merkle path reaches the signed root;
  - `leafIndex < treeSize = root.entryCount`;
  - the leaf is registered for **this** bundle's `artifactId`.
- `trust` — which anchor authenticated the seals (`keys` or `pin`, plus `keyId` and fingerprint), or the reason none did.

No step in this verification ever contacts a server or queries a database. The verifier trusts only the key sets you supply and the standard Ed25519/SHA-256 primitives in Node's `crypto` module.

## 3. What verification does NOT prove

Verifying a bundle proves the bundle is authentic, unmodified, and (when `transparency.available`) publicly logged. It does **not** prove:

- That the key sets **you supplied** genuinely belong to the operator. The verifier enforces the binding to your trust anchors, so the authenticity verdict is only as good as the channel you fetched them over. See `docs/glossary.md`'s Evidence Chain trust-assumption note.
- That history after the most recent externally anchored checkpoint was not rewritten by someone with database or host access to the operator's instance. Transparency signatures prove issuance, not non-rewriting; and external anchoring.
- That the *content* of the original request/response was appropriate — the bundle proves *what decision was made and by what policy rule*, not that the policy itself was well-designed.
- Anything about decisions made after the bundle was exported — a bundle is a point-in-time snapshot.

## 4. Recovery / operational notes

If evidence bundle generation itself fails (500 from `GET /evidence/package/:artifactId/bundle`) while the underlying audit chain and transparency log are both healthy, this is a generator-code defect, not a data-integrity incident — cross-check `GET /evidence/package/:artifactId/json` and `GET /transparency/proof/:transparencyId` independently; both use the same underlying data the bundle generator reads (`proofLookup.getInclusionProofForArtifact()` shares its lookup logic with the `/transparency/proof/:id` route — see `src/core/transparency/proofLookup.js`).

For recovering the underlying audit chain or transparency log data itself (as opposed to the bundle export step), see:
- `docs/operations/audit-chain-integrity-verification.md` — the production audit chain (and, per the consent audit checksum scan wired into its FULL scan).
- `docs/operations/transparency-recovery.md` — the RFC6962 transparency log.
