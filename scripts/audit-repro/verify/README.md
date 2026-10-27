# qodiqa-audit-verify — the standalone audit verifier

An independent verifier for QODIQA audit evidence. It imports **nothing** from `src/` and no npm package: only Node built-ins (`crypto`, `fs`, `path`) and its three sibling modules. This is enforced by CU-06.

It re-derives every verdict from the documented contract, so it can be audited and run without trusting QODIQA's implementation. The differential, adversarial and golden-vector suites (`scripts/audit-repro/__tests__/w7*.test.js`) hold it and production to the same verdicts.

| module | implements (SCHEMA-V6 §) |
|---|---|
| `canonical.js` | CanonicalSerialize (§3) |
| `auditContract.js` | versions and field sets (§1–2), hash (§4), entry and chain verification (§5–6), PG row projection and hash-link ordering (§6.3), checksum anchor (§7) |
| `transparency.js` | leaf/root hashes, Ed25519 signatures, RFC 6962 Merkle root and inclusion, audit ↔ transparency cross-check (§8) |
| `proof.js`, `qodiqa-proof-verify.js` | the downloadable proof `qodiqa-proof/1`: artifact signature over its envelope hash, entries, lifecycle, transparency leaf + inclusion + signed root, checkpoint + contiguous chain path, receipt |
| `anchorTrust.js` | *trust from the anchor*: reads the anchors git repository (clean tree, append-only history, optional signed commits, monotonic fork-free statements, anchored public keys) and evaluates a proof against it — `qodiqa-proof-verify.js --anchors-repo <dir>`; the only module that runs `git` |
| `qodiqa_proof_verify.py` | the same entry and proof rules in Python (standard library only, pure-Python Ed25519, ECMAScript number formatting); `--vectors` re-derives the audit vector families |
| `qodiqa-audit-verify.js` | the CLI |

Requires Node ≥ 18 (Ed25519 via `crypto.verify`).

## Usage

```bash
node scripts/audit-repro/verify/qodiqa-audit-verify.js --audit audit.log --anchor audit.log.sum
```

```bash
node scripts/audit-repro/verify/qodiqa-audit-verify.js --audit audit_chain-rows.json --format pg-json --out report.json
```

```bash
node scripts/audit-repro/verify/qodiqa-audit-verify.js --audit audit.log --transparency entries.json --roots roots.json --proofs proofs.json --keys transparency-keys.json
```

| option | meaning |
|---|---|
| `--audit <file>` | an NDJSON file log (single-node `audit.log`, or a DR snapshot from `scripts/export-audit-chain-snapshot.js`), or a JSON export of `audit_chain` rows (`--format pg-json`: an array, or `{rows:[…]}`) |
| `--format ndjson\|pg-json` | defaults to `pg-json` for `*.json`, otherwise `ndjson` |
| `--anchor <file>` | the checksum anchor `{count, tailHash, v2?}` (NDJSON only) |
| `--transparency <file>` | `transparency_log_entries` rows (snake_case or camelCase), including `payload` |
| `--roots <file>` | `transparency_roots` rows |
| `--proofs <file>` | inclusion proofs (`proofVersion 2`) |
| `--keys <file>` | the body of `GET /.well-known/qodiqa/transparency-keys` (base64 SPKI DER Ed25519 keys) |
| `--tolerate-legacy-prefix` | report pre-hash lines before the first chained entry as `UNVERIFIED_LEGACY` (the boot loader's tolerance) instead of failing (the full-chain verdict) |
| `--out <file>` | write the full JSON report (per-entry status, anomalies, per-check transparency results) |

Exit status: **0** every supplied input verifies · **1** a verdict failed · **2** usage/input error.

## What a VALID verdict means — and does not

- **It means:** every entry's fields reproduce its `canonical` byte for byte, the hash of that canonical is its `hash`, and each `prevHash` links to the previous entry from `GENESIS`. Also, when supplied, the anchor matches the log; transparency entries and roots are correctly hashed, linked and signed; and every leaf's `auditEntryHash` names a chain entry with the same decision.
- **It does not mean:** that unhashed fields (`tenantId`, `requestId`, `executionContext`, …) are genuine (SCHEMA-V6 §2.2), or that the chain was not regenerated wholesale by a writer-capable party. The audit hash is unkeyed, so detecting that needs an independently held tail or anchor, or the **signed** transparency leaves (`--transparency` + `--keys`) (SCHEMA-V6 §9).
