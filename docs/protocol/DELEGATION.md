# Delegation tokens and chains

> **Status:** normative for the delegation token and chain verification (domain `QODIQA::DELEGATION::V1`, reserved by `V2-FREEZE.md` section 1 and
> the reasons of section 7.5). Pinned by `docs/protocol/vectors/delegation.json` (`DELEG-nnn`) and re-derived by three implementations (production,
> `scripts/protocol/verify-delegation-vectors.js`, `scripts/protocol/verify_delegation_vectors.py` - the last two import nothing from QODIQA).
> Code: `src/core/delegation/delegationToken.js` (token and chain), `delegationStore.js` (state), `src/api/routes/delegations.js` (HTTP).

A **delegation** lets one agent give a *subset of its own authority* to another agent. Rights only shrink down a chain; no agent appears twice; the depth is
bounded; every link is signed and bound to its parent, so a chain verifies **offline** with the tenant's public key and nothing else.

## 1. The token

```
digest   = SHA-256( "QODIQA::DELEGATION::V1" || JCS-P1({ expiry, payload, publicKeyId, timestamp }) )      (32 bytes; JCS-P1 as V2-FREEZE section 2)
envelope = { expiry, payload, publicKeyId, signature, timestamp }          signature = Ed25519(digest), canonical base64 (88 characters, `==` padding)
payload  = { v: 1, kind: "delegation", delegationId, tenantId, parentId, parentDigest, rootAgentId, issuerAgentId, subjectAgentId,
             depth, maxDepth, classes, tools, maxActions }
```

| member | type | rule |
|---|---|---|
| `delegationId` | UUID v4 | issued by the gateway |
| `tenantId` | string | `[A-Za-z0-9_-]{1,64}`; must be the tenant that owns `publicKeyId` |
| `parentId`, `parentDigest` | UUID v4 / 64 hex, or both `null` | `null` exactly for the root grant; `parentDigest` is the **digest of the parent envelope** |
| `rootAgentId`, `issuerAgentId`, `subjectAgentId` | UUID v4 | the agent that started the chain; who gives; who receives |
| `depth`, `maxDepth` | integers 1..8 | root grant: `depth = 1`; `maxDepth` is fixed by the root grant and copied unchanged down the chain |
| `classes` | non-empty array of action classes | `read write file database external_api command communication financial delegate`; strictly ascending, no duplicates |
| `tools` | `null` or non-empty array (<= 100) of `{ server, name }` | `null` = no tool restriction; strictly ascending by `server NUL name` |
| `maxActions` | `null` or integer 1..100000 | `null` = no limit of its own |

`envelope.timestamp` is the issue time and `envelope.expiry` the end of validity (both integer milliseconds, `expiry > timestamp`). `chainHash` of a chain is the
digest (hex) of its **leaf**; because every link carries its parent's digest, it identifies the whole chain.

## 2. Chain verification

A chain is the list of envelopes, **root first**, 1 to 8 links. Links are checked one at a time, root first; the **first** failure is reported, in this order
inside a link:

1. **shape** - envelope members exactly `expiry payload publicKeyId signature timestamp`; payload members exactly as in section 1, with the types and ranges above;
   canonical signature encoding; `timestamp`/`expiry` integers with `expiry > timestamp`; non-empty `publicKeyId`. -> `DELEGATION_INVALID`
2. **signature** - the key is known and the Ed25519 signature over `digest` verifies. -> `DELEGATION_INVALID`
3. **tenant** - `payload.tenantId` equals the tenant of the key and, after the root, the root's `tenantId`. -> `DELEGATION_INVALID`
4. **linkage** - root: `parentId = null`, `depth = 1`, `rootAgentId = issuerAgentId`. Other links: `parentId` = the previous link's `delegationId`, `parentDigest` = its digest,
   `issuerAgentId` = its `subjectAgentId`, `depth` = its `depth + 1`, `maxDepth` and `rootAgentId` equal to the root's. -> `DELEGATION_INVALID`
5. **depth** - `depth <= maxDepth`. -> `DELEGATION_DEPTH_EXCEEDED`
6. **cycle** - `subjectAgentId` differs from `issuerAgentId` and is not any agent already in `[root.issuer, subject_0, subject_1, ...]`. -> `DELEGATION_CYCLE`
7. **attenuation** (not for the root) - against the parent: `classes` is a subset; if the parent lists `tools`, the child lists tools and they are a subset; if the parent has
   `maxActions`, the child has one and it is not larger; `expiry` is not after the parent's. Equal rights are allowed. -> `DELEGATION_ATTENUATION_VIOLATION`.
   Then `timestamp` is not before the parent's. -> `DELEGATION_INVALID`
8. **time** - `timestamp <= now + 5 minutes` and `expiry > now`. -> `DELEGATION_INVALID`

On success the verdict is the leaf's facts: `depth`, `maxDepth`, `chainHash`, `rootAgentId`, `issuerAgentId`, `subjectAgentId`, `tenantId`, `delegationId`, `classes`, `tools`,
`maxActions`, `expiry`. The gateway adds **key lifecycle** (a revoked or archived key verifies nothing it signs afterwards) and **state**, which a signature cannot carry:
no link revoked (`DELEGATION_REVOKED`) and every agent of the chain still active. The vectors cover the offline rules only.

## 3. Issuing, using, revoking (gateway)

* **Issue** (`POST /v1/delegations`, authenticated like `/sign`): the issuer agent is verified like every agent caller (live session; proof of possession when it has a key) and needs the
  action class `delegate`. A **root grant** may give only classes the issuer's *own identity* holds. A **child** names `parentId`; the issuer must be the parent's delegate; the chain
  must be valid and unrevoked now; the child must be an attenuation of it and not exceed the depth. A child asked for without a lifetime lives as long as its parent at most; an explicit
  longer lifetime is an attenuation violation, never silently shortened. **Issuing is itself an authorised action of the issuer's session** (class `delegate`): the live session and its action and cost budgets are checked and **charged** (a refused attempt costs too), and a `DELEGATION_ISSUED` audit entry traces it (audit schema v8). It takes **no place in the session's chain of artifacts** (`seq`, `prevActionHash`): that chain is the chain of artifacts that executors consume, and nothing executes for a delegation. The token is verified once more, as signed, before it is stored.
* **Use**: `POST /v1/actions/authorize` with `delegationId` - the agent must be the leaf's delegate, the chain valid and unrevoked, the action class and tool inside the leaf's rights; one action
  is counted against **every link that has a `maxActions`** (a parent's limit bounds everything below it), atomically, and the chain the request ran under (`chainHash`, `depth`, `rootAgentId`)
  is recorded for the request. The executor re-checks the chain before running the action and writes it into `ACTION_INTENT` / `ACTION_COMMIT` (`executionContext.delegation`).
* **Revoke** (`POST /v1/delegations/{id}/revoke`): the delegation and every descendant, in one statement. Executions running under any of them are aborted (this process at once; other replicas
  at their next authorisation or execution, which re-check the chain). `revokeAgents` also revokes the delegates of the subtree (never the root agent). Suspending or revoking an agent
  revokes the delegations it issued or holds. `DELEGATION_REVOKED` entries are written per revoked delegation (audit schema v8).

## 4. What a delegation is not

It is not a way to get rights the delegator does not have (root grants are capped by the issuer's identity, children by their parent), nor to keep rights after the delegator loses them
(agent suspension and revocation end the chain at once; a delegation's own expiry ends it; the END of the delegator's SESSION does not - revoke the delegation or the agent for that), and it does not replace the delegate's own identity: the delegate still acts only within `allowedActionClasses` of
its own identity, narrowed further by the delegation (the effective right is the intersection).
