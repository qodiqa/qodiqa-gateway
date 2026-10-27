# Install

QODIQA has two supported startup paths: an isolated **development** bootstrap for local
work, and a fail-closed **production** startup that requires explicit, real secrets. Both
paths run the exact same server code (`server.js`) — nothing about the enforcement
pipeline (cryptographic verification, consent evaluation, policy evaluation, audit
logging) differs between them.

---

## Development

```bash
git clone <repo>
cd qodiqa-gateway
npm install
redis-server &   # required — see "Why Redis is required" below
npm run dev
```

No `.env` file, no manually generated secrets, and no manually provisioned key store are
needed. **Redis is required** — see
[Why Redis is required, even in development](#why-redis-is-required-even-in-development)
below.

### What `npm run dev` does

`npm run dev` runs `scripts/bootstrap-dev.js`, which:

1. Creates a **fresh OS temporary directory** for this run (`fs.mkdtempSync` under
   `os.tmpdir()`) — never inside `data/`, `config/`, or the repository root.
2. Generates a **fresh, cryptographically random** 256-bit Key Encryption Key, using
   `crypto.randomBytes` — the same primitive production key material generation uses.
   Nothing is hard-coded and nothing is reused between runs. It also provisions a
   dev-scoped **signing identity** in an isolated store and prints its `sk_...` signing
   API key once — there is no shared `QODIQA_SIGN_TOKEN` secret; every caller of
   `POST /sign` authenticates with its own individually-issued key (see
   [docs/guides/quickstart.md "Provision a Signing Identity"](quickstart.md#provision-a-signing-identity)).
3. Sets `QODIQA_CLIENT_ID` to a fixed development identifier (`dev-local`, overridable via
   `QODIQA_DEV_CLIENT_ID`).
4. Points `QODIQA_KEYS_PATH`, `QODIQA_TRANSPARENCY_KEYS_PATH`, and `QODIQA_AUDIT_LOG` at
   files inside that fresh temp directory.
5. Provisions an active Ed25519 signing key and a transparency signing key in that isolated
   store, using **the exact same provisioning helper the Jest test suite uses**
   (`scripts/lib/keyStoreProvisioning.js`) — no duplicated logic, no separate code path to
   drift out of sync.
6. If no real AI provider key is configured (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.),
   sets `LOCAL_BASE_URL` to a default self-hosted-runtime endpoint. This is a real,
   production-supported provider type, not a mock — `POST /ai/chat` correctly returns
   `PROVIDER_UNAVAILABLE` if nothing is actually listening there.
7. Probes whether Redis is reachable at `REDIS_URL` (default `redis://localhost:6379`). If
   it is not, the bootstrap **fails fast with an actionable error and does not attempt to
   launch the server** — see
   [Why Redis is required](#why-redis-is-required-even-in-development) below.
8. If Redis is reachable but you have not already set `STRICT_REPLAY_PROTECTION` yourself,
   sets `STRICT_REPLAY_PROTECTION=false` for this run only (does not disable request-level
   fail-closed behavior — see below).
9. Sets `NODE_ENV=development`.
10. Spawns `node server.js` as a normal child process with that prepared environment —
    **the unmodified production server**, with its unmodified fail-closed startup
    validation. `scripts/bootstrap-dev.js` never `require()`s server internals to bypass a
    check; it only prepares environment variables and files before the real process starts.

Every `npm run dev` invocation repeats all steps from scratch. Two consecutive runs
never share a temp directory, a key, a token, or a client id — there is no state to leak.

### Development never touches production data

- `data/keys.json` (the production, KEK-encrypted signing key store) is never read, never
  decrypted, and never written by the development bootstrap. If it exists, it is
  completely ignored — the isolated development key store is a different file, in a
  different directory, encrypted with a different (freshly generated) key.
- `audit.log` (the production audit chain) is never appended to. Development audit entries
  go to a temp file that is discarded with the rest of the temp directory.
- No development secret is ever derived from, copied from, or falls back to a production
  value. If `QODIQA_KEY_ENCRYPTION_KEY` happens to already be set in your shell
  environment (e.g. you have a production `.env` sourced by mistake), `npm run dev`
  overrides it with a freshly generated development value rather than trusting it.

### Why Redis is required, even in development

Redis is a genuine, unconditional prerequisite for a full server boot — this is not
something the development bootstrap can or should route around. Independently of
`STRICT_REPLAY_PROTECTION` (see below), `server.js` also requires a live subscription to
the consent-revocation pub/sub channel before it finishes starting ("required
control-plane dependency" — see the "Revocation subscriber" section of `server.js`) and
calls `process.exit(1)` if that subscription cannot be established within its startup
timeout. There is **no dev-mode escape hatch** for that gate, by design: bypassing it would
mean the node could not guarantee instant enforcement of revoked consent, which this
bootstrap must never weaken.

Because of this, `scripts/bootstrap-dev.js` probes Redis reachability *before* attempting
to launch the server and fails fast with an actionable message if it is unreachable, rather
than letting the real server hang for ~10-15 seconds and then exit fatally on its own.

Start Redis locally before running `npm run dev`:

```bash
redis-server
# or (loopback only, never on all interfaces):
docker run --rm -p 127.0.0.1:6379:6379 redis:7
```

 If another Redis
already listens on 6379 (for example one holding another QODIQA instance's data), publish a different free host port
(`-p 127.0.0.1:56379:6379`) and set `REDIS_URL=redis://127.0.0.1:56379` — never point a development boot at an
existing Redis.

### Why `STRICT_REPLAY_PROTECTION` is relaxed by default in development

`server.js` is fail-closed by default for a *second*, independent reason:
`STRICT_REPLAY_PROTECTION` defaults to `true` and refuses to start unless Redis is not just
reachable but durably configured (AOF persistence: `appendonly yes`,
`appendfsync everysec`/`always`). That default is unchanged and is not weakened by the
development bootstrap.

A freshly installed local Redis defaults to RDB snapshotting, not AOF — and a simple TCP
reachability probe cannot distinguish the two. `server.js` itself documents an escape hatch
for exactly this situation (see the `STRICT_REPLAY_PROTECTION` comment in `server.js`):
*"Set `STRICT_REPLAY_PROTECTION=false` only in environments without durable Redis (e.g.
development without Redis)."* `scripts/bootstrap-dev.js` uses that existing, documented,
code-reviewed escape hatch whenever Redis is reachable but you have not made an explicit
choice yourself. It does not disable the nonce store, the anomaly store, or their
request-time fail-closed behavior: `src/validation/nonceStore.js` and
`src/validation/anomalyStore.js` still have "no in-memory fallback, no fail-open path" and
still throw/block individual requests if Redis becomes unavailable when a request actually
needs it. `STRICT_REPLAY_PROTECTION=false` only relaxes the pre-flight **startup**
durability gate, not per-request enforcement, and not the (separate, non-bypassable)
revocation-subscriber gate above.

If your local Redis has `appendonly yes` / `appendfsync everysec` configured and you want
the full production-grade startup gate in development too, set
`STRICT_REPLAY_PROTECTION=true` yourself before running `npm run dev`.

---

## Production

```bash
npm start
```

### Required environment variables

| Variable | Requirement |
|---|---|
| `QODIQA_KEY_ENCRYPTION_KEY` | 64 hex characters (256-bit AES-256-GCM key). Generate: `openssl rand -hex 32` |
| `QODIQA_EXECUTION_INVARIANT_SECRET` | 64 hex characters (256-bit HMAC-SHA256 key), different from `QODIQA_KEY_ENCRYPTION_KEY`. Required at boot in every profile (boot validator rule `secret.invariant`); the server refuses to start without it. Generate: `openssl rand -hex 32` |
| `QODIQA_CLIENT_ID` | `[A-Za-z0-9_-]{1,64}`; a real deployment identifier — not `test`/`demo`/`default` in production |
| At least one AI provider | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `LLAMA_BASE_URL`, or `LOCAL_BASE_URL` |
| A provisioned signing key | `QODIQA_KEYS_PATH` pointing **outside the repository / application directory** (production refuses a repository-resident key store), holding an active key — see [docs/guides/quickstart.md](quickstart.md) "Provision First Signing Key" |
| PostgreSQL | PostgreSQL 15–18, migrated with `node src/infra/postgres/migrate.js` before the first start (production does not migrate at startup; a CREATEROLE identity such as `qodiqa_test` is needed for the role migrations). Production refuses to boot without it (`EVIDENCE_DURABILITY_VIOLATION`) |
| Role credentials | Every migration-created role rotated or hardened; `node scripts/db/role-credentials.js --check` exits 0 (production refuses `PG_ROLE_PLACEHOLDER_CREDENTIAL`) — see `docs/operations/database-role-management.md` |
| Anchoring and witness | `QODIQA_ANCHOR_EXPORT_PATH` and a witness (`QODIQA_WITNESS_*`) — production refuses to boot without them (`bootValidator.js` rule `audit.anchoring`); see `docs/security/audit-anchoring.md` |
| A provisioned signing identity | At least one signing identity must exist for `POST /sign` to authenticate any caller — there is no `QODIQA_SIGN_TOKEN` shared secret. See [docs/guides/quickstart.md "Provision a Signing Identity"](quickstart.md#provision-a-signing-identity) |
| A provisioned consent-signer key | `GET /public-key` serves a separate, reserved `consent-signer` identity — not covered by the signing key above. Without it the route returns `500 KEY_UNAVAILABLE` indefinitely. See [docs/guides/quickstart.md "Provision the Consent-Signer Key"](quickstart.md#provision-the-consent-signer-key) |

See [`deploy/env/production.env.example`](../../deploy/env/production.env.example) for the complete list, and
[docs/guides/quickstart.md](quickstart.md) for the full manual walkthrough (secret generation, key
provisioning, Redis setup).

### Why production fails without secrets

The boot validator checks the configuration before anything else runs and exits non-zero with
**one** `FATAL BOOT_VALIDATION_FATAL` event listing every violation (`docs/configuration/boot-rules.md`;
since this replaces the older per-check events such as `NO_PROVIDER_CONFIGURED` and
`KEY_ENCRYPTION_KEY_NOT_CONFIGURED`). Key-store problems found while loading the store still emit:

- Key store empty, malformed, or contains plaintext key material →
  `KEY_MANAGER_STARTUP_FAILED` / `KEYSTORE_EMPTY`

This is intentional and is the platform's core security guarantee: QODIQA never signs or
verifies an enforcement artifact without real, explicit key material under the operator's
control. **This behavior is unchanged by the development bootstrap** — `npm start` behaves
identically today as it did before `scripts/bootstrap-dev.js` existed. The development
bootstrap does not touch `server.js`, `services/artifact/keyManager.js`,
`services/artifact/keyStore.js`, `services/secrets/secretsProvider.js`, or any other
production startup-validation code — it only prepares environment variables and isolated
files, then spawns the same, unmodified `server.js` that `npm start` runs directly.

Additionally, when `NODE_ENV=production`, `runEnvValidation()` and `runSecretValidation()`
(both called from `server.js`) reject placeholder-looking or low-entropy secret values —
so copying `deploy/env/production.env.example` verbatim without replacing its `<REPLACE_WITH_...>`
placeholders will also fail closed.

### How production isolation is preserved

`scripts/bootstrap-dev.js` is only ever invoked by `npm run dev`. It is never `require()`d
by `server.js`, `start.js`, or any production code path, and it never runs as a side
effect of `npm start`. The two entry points are completely independent:

| | `npm start` | `npm run dev` |
|---|---|---|
| Entry point | `node server.js` directly | `node scripts/bootstrap-dev.js`, which spawns `node server.js` |
| Secrets | Must already be set by the operator (real, persistent) | Generated fresh every run (random, ephemeral) |
| Key store | `QODIQA_KEYS_PATH`, outside the repository (must be pre-provisioned; production refuses a repository-resident store — the `data/keys.json` default is for non-production only) | Fresh temp file, auto-provisioned every run |
| Audit log | `audit.log` (persistent, append-only) | Fresh temp file, discarded after the run |
| `NODE_ENV` | Operator-set (expected: `production`) | Always `development` |
| Startup validation | Full — including production-only placeholder/entropy checks | Same code, but non-fatal (WARN) for those two checks, per `server.js`'s own existing `NODE_ENV` handling |

---

## See also

- [docs/guides/quickstart.md](quickstart.md) — manual production-parity local setup and first-request
  walkthrough
- [docs/security/key-management.md](../security/key-management.md) — key lifecycle, rotation, and the KEK/signing-key
  model in full
- [docs/deployment/production.md](../deployment/production.md) — full production deployment guide
- [docs/operations/runbook.md](../operations/runbook.md) — key rotation, policy reload, graceful
  shutdown
