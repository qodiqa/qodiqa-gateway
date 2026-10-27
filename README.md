# QODIQA Gateway

A self-hosted gateway that sits between your applications and AI model providers. A request reaches a provider only if your application first obtained a signed, single-use authorization for exactly that request, and every decision is recorded in a tamper-evident log that a third party can check offline.

**Status:** release 1.0.0. The signing, verification and audit paths are covered by the test suite and by a local sandbox. Adapters for hosted providers and the Kubernetes production profile have not been validated against real services; see [Scope and limitations](docs/limitations.md).

## Quick start

You need Docker with Compose v2 (nothing else for this path). The sandbox uses a built-in stand-in for the AI model that echoes your prompt, so no provider account or API key is needed.

```bash
git clone https://github.com/qodiqa/qodiqa-gateway.git && cd qodiqa-gateway
docker compose -f docker-compose.quickstart.yml up
```

One command builds the sandbox image and starts the sandbox. The `quickstart-smoke` workflow runs it from a clean checkout on a GitHub-hosted Ubuntu runner and reports each step; in three consecutive runs the image was built and the sandbox started in 45, 46 and 47 s, and the first signed request was answered and verified offline 4 s or less later. The gateway listens on `http://127.0.0.1:3000` and is ready when `curl http://127.0.0.1:3000/health` answers `{"status":"ok", ...}`. At start it prints a throwaway signing key in its log, on a line `Authorization: Bearer <key>`. Find it with `docker compose -f docker-compose.quickstart.yml logs | grep "Authorization: Bearer"` and keep the key for the next step.

Then ask the gateway to sign a request, and send that request with the signed artifact (requires `jq`):

```bash
SK=<the key from the log>
ARTIFACT=$(curl -s -X POST localhost:3000/sign -H "Authorization: Bearer $SK" -H 'content-type: application/json' \
  -d '{"request":{"method":"POST","path":"/ai/chat","body":{"prompt":"hello"}},"payload":{"userId":"me"},"ttl":60000}' \
  | jq -c '.artifact // .' | base64 | tr -d '\n')
curl -s -X POST localhost:3000/ai/chat -H 'content-type: application/json' -H "x-qodiqa-artifact: $ARTIFACT" -d '{"prompt":"hello"}'
# {"decision":"EXECUTE","response":"[sandbox] hello", ...}
```

Use the prompt `sandbox-block-me please` (in both places) to see a `BLOCK` decision. The sandbox is for evaluation, not for deployment. The full walkthrough, with the npm path (`npm ci && npm run dev:sandbox`, Node.js 22+ and Docker), is in the [Quickstart](docs/guides/quickstart.md).

## What it does

- **Authorization before execution.** Every request needs an artifact: a small document signed with an Ed25519 key (a standard public-key signature scheme). It names the HTTP method, path and body of exactly one request, a tenant (one customer or environment isolated inside the gateway) and an expiry of at most 60 seconds. It can be used once; without a valid one, nothing reaches a provider.
- **Verifiable evidence.** Decisions are appended to an audit chain (each entry contains the hash of the previous one) and to a transparency log (a Merkle tree that proves an entry is included without revealing the others), with signed receipts and downloadable proof bundles. A separate verifier that imports none of the gateway code, [`qodiqa-verify`](https://github.com/qodiqa/qodiqa-verify), checks them offline. Signed checkpoints can be anchored in an outside repository ([`qodiqa-anchors`](https://github.com/qodiqa/qodiqa-anchors)) and co-signed by witnesses (separate processes that countersign checkpoints).
- **Policy.** Per-tenant rules for consent, IP and time, attribute-based access, budgets, data residency, content rules and data-loss prevention. Policy changes can require draft, review, approval and publication by different people.
- **Agents and tools.** Agent sessions, one artifact per action, delegation that can only narrow authority (a sub-agent never gets more than its parent), human approval with a second factor, and a gateway for MCP (Model Context Protocol) servers and tools.
- **Multi-tenancy.** Per-tenant keys, one-time codes (nonces), policies and consent.
- **Operations.** PostgreSQL and Redis backing, health and readiness endpoints, Prometheus metrics, a Helm chart, a Terraform module, backup and restore tooling, SDKs for JavaScript (TypeScript), Python, Go and Java (guides for JavaScript and Python under [docs/sdk](docs/sdk/javascript/README.md); Go and Java have a README in their folder under `sdk/`), and an artifact guard for Express, FastAPI and Django services.

How one request flows is drawn in the [overview](docs/overview.md).

## Documentation

| Topic | Where |
|---|---|
| What it is, how it is designed, what it does not do | [Overview](docs/overview.md), [Design principles](docs/design-principles.md), [Scope and limitations](docs/limitations.md) |
| Index of all documents | [docs/README.md](docs/README.md) |
| HTTP API | [API overview](docs/api/overview.md), [generated reference](docs/api/REFERENCE.md), [OpenAPI contract](docs/api/openapi.json) |
| Protocol and test vectors | [Protocol](docs/protocol/QODIQA-PROTOCOL.md), [vectors](docs/protocol/vectors/) |
| Configuration | [Configuration reference](docs/configuration/reference.md) |
| Deployment and operations | [Operations index](docs/operations/README.md), [Helm](docs/operations/helm.md) |
| Security | [Security guide](docs/security/SECURITY_GUIDE.md), [Threat model](docs/security/THREAT_MODEL.md) |
| Development | [CONTRIBUTING.md](CONTRIBUTING.md), [Development guide](docs/development.md) |

## Scope and limitations

The most important limits first; the complete list is in [Scope and limitations](docs/limitations.md).

- **One instance.** A production deployment is validated with a single gateway instance. Several instances can run, but each keeps its own audit chain unless you use the PostgreSQL-ordered distributed mode, and clustering and automatic failover are not provided.
- **Content screening is optional and best-effort.** It is tuned for English and for direct requests; paraphrases and other languages are often missed, and some legitimate requests are flagged. Treat it as one layer, not as a guarantee. Screening by meaning (semantic screening) needs models and reference data that are not distributed in this repository: without them the gateway starts only with `QODIQA_SEM_EMBEDDING_ENABLED=false` (in production also `QODIQA_SEM_EMBEDDING_OFF_ACK=true`), logs a warning at start-up, and only the rule-based screening runs. The sandbox sets this for you.
- **Providers.** The local provider (Ollama) is exercised end to end. The adapters for OpenAI, Anthropic, Gemini, Mistral, Azure OpenAI and AWS Bedrock are experimental.
- **The operator vouches for the evidence** unless you run an independent witness. The evidence is tamper-evident, and a third party can check it offline, but only against public keys obtained from a source other than the gateway being checked.
- **Tenant isolation is enforced in the application layer.** Database row-level security is an additional layer, not the boundary.
- **Streaming has a weaker guarantee than buffered responses.** Output is released after each window is checked, so part of a response can reach the client before its final decision record is written.
- **Audit records are permanent.** They hold hashes of requests and outputs, never the text; anyone who can guess a short prompt can confirm it by hashing the guess.
- **No certification, no throughput figure.** The compliance tooling produces technical evidence, not an attestation, and performance has not been benchmarked for publication: size a deployment by load testing.
- **Dependencies.** PostgreSQL and Redis are required in production. Key-management integrations (Vault, AWS KMS, Google Cloud KMS, Azure Key Vault, HSM) are exercised against mocks and emulators only.
- **Packaging.** The SDKs are not published to package registries; install them from this repository. Commands are in the SDK guides under [docs/sdk](docs/sdk/javascript/README.md).
- **POSIX shell.** The commands in the guides assume a POSIX shell (Linux, macOS, or WSL / Git Bash on Windows).

## Security and licence

To report a vulnerability, see [SECURITY.md](SECURITY.md).

**Licence.** QODIQA is licensed under the Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are welcome under the same licence; see [CONTRIBUTING.md](CONTRIBUTING.md).
