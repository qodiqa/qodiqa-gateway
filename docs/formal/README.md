# Formal specifications (TLA+)

Four small TLA+ specifications of the ordering rules QODIQA depends on. The claim they support is exactly this: **specification modelled** and checked with the TLC model checker within the stated bounds. They do not prove the implementation correct; they check that the rules, as written down here, cannot produce the bad states the invariants name, and each spec has a negative-control configuration that removes the rule and must produce a counterexample (so the invariants are shown to be able to fail).

| Spec | Models | Code / document it follows | Invariants |
|---|---|---|---|
| `Lifecycle.tla` | the `/ai/chat` request lifecycle: nonce consumed, INTENT before the provider call, one DECISION, crash leaves an orphan INTENT | `src/core/audit/v7Lifecycle.js`, `docs/protocol/QODIQA-PROTOCOL.md` (v7 additions) | no provider call without INTENT; ALLOW has an earlier INTENT; one DECISION per request; at most one provider call per nonce and per request; a refused request never reached the provider |
| `Nonce.tla` | single-use artifacts across a Redis restart that loses the nonce store | `src/validation/nonceStore.js` (restart barrier, `REPLAY_STATE_UNPROVABLE`) | no nonce is accepted twice |
| `DelegationChain.tla` | building and revoking delegation chains | `src/core/delegation/delegationToken.js`, `docs/protocol/DELEGATION.md` | rights only shrink; linkage; no repeated agent (so no cycle); depth bound; leaf within root; revocation propagates |
| `ActionChain.tla` | the per-session action ledger with concurrent callers | `src/core/actions/executor.js` | no duplicate sequence number; contiguous; hash-linked |

Negative controls (`*.negative.cfg`): `Lifecycle` without the INTENT rule, `Nonce` without the restart barrier, `DelegationChain` without attenuation, `ActionChain` without the "n-1 consumed" check. Each must be reported as a violation.

## Run

```bash
bash scripts/formal/run-tlc.sh
```

TLC runs in a container (`eclipse-temurin` JRE); `tla2tools.jar` (v1.8.0) is downloaded once into `scripts/formal/.cache` (untracked) and its SHA-256 is printed. Logs go to `evidence/formal/`.

## What is not modelled

Cryptography (hashes are abstract values), time beyond a small integer clock, partial failures of PostgreSQL or Redis other than a Redis restart that loses state, multi-instance behaviour, the semantic classifier and the policy engine. The state spaces are small by design (3 requests, 3 artifacts, 4 agents, 2 callers): a result holds for those bounds, not for all sizes.

## Result

All four specifications pass TLC and all four negative controls produce a counterexample: Lifecycle 856 distinct states, Nonce 175, DelegationChain 9,097, ActionChain 64. jar SHA-256 `dae639a1f51a9e13ce60c369b15f32124cf1a78017aca366b6de0ae2b5169439`.
