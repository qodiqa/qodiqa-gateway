# Scope and limitations

This page states what QODIQA does not do and where its claims stop.

## Scope

QODIQA is an enforcement gateway. It does not intercept traffic that bypasses the gateway. Direct access to AI providers must be closed at the network level.

## No certification, no legal assessment

QODIQA provides technical controls. It is not a certification and not a legal assessment. Features that support GDPR work (data-subject requests, lawful basis recording, retention) are technical controls only. EU AI Act compliance, SOC 2 and ISO 27001 certification are not provided.

## Content screening

- Semantic screening requires model and reference resources that are **not distributed in this repository**. Without them the embedding screening layer is not available, and the gateway starts only with `QODIQA_SEM_EMBEDDING_ENABLED=false`; in production that also needs `QODIQA_SEM_EMBEDDING_OFF_ACK=true`, and the start-up log then warns that content screening is limited to the rule engine. The rule-based screening needs no external resources.
- Where screening is used, it is an English-oriented layer and not a protection guarantee. It does not catch paraphrases reliably, and it performs worse outside English.
- Detection rates measured on the developers' own data say nothing about how well detection generalizes to other data.
- Logs are sanitized automatically, but prompts and responses are not redacted by default; data loss prevention is a separate, policy-driven feature. It is pattern- and checksum-based and is not a guarantee against all personal data.

## Verification

- Verification is circular if the keys and anchors come from the same instance. To rely on a verification independently of the instance, the public keys must come from another source.
- External anchoring is opt-in, asynchronous, and covers history only up to the last anchored checkpoint. Whether witnesses are operated by independent parties is a deployment fact.
- A receipt proves that the gateway recorded a decision, not that the decision was correct.
- The offline verifiers and agent-chain models are pinned by test vectors and model checks within small bounds. A model check is not a proof that the implementation matches the model.

## Binding

Protocol V1 binds the method, the path and the body. It does not bind headers or the query string; V2 does, and V2 issuance is off by default. The artifact guard uses V1 binding and does not consume the nonce unless you provide a replay hook.

## Durability and consistency

- The supported production deployment is one gateway instance. Several instances can run, each with its own audit chain or with one PostgreSQL-ordered chain (distributed mode); clustering and automatic failover are not provided.
- When several instances run, a consent revocation is published to the others; if that fails, an instance may serve a cached ALLOW for at most 60 seconds.
- The audit chain gets an explicit COMMIT entry, and the kill-switch change is recorded in the chain, only when audit schema v8 is enabled; it is off by default.
- Durability across a sudden power loss has not been demonstrated on hardware.
- Overload limits are per process, not shared between instances.

## Providers

A local OpenAI-compatible server (for example Ollama) has been exercised against a real server. Adapters for OpenAI, Anthropic, Gemini, Mistral, Azure OpenAI and AWS Bedrock have been verified only with simulated transport; no calls to the real hosted services have been made.

## Identity

Single sign-on through OIDC, SAML 2.0 and LDAP has been validated only against test infrastructure, not against production identity providers.

## Tenancy

Row-level security is not a boundary on its own: the tenant context is a session setting that the application role can change.

## Deployment

Kubernetes and Helm were exercised on local development clusters; the production profile (TLS to PostgreSQL and Redis, shared keystore volume, network policy enforcement) needs your own validation. The SDKs are not published to any registry. The Go and Java SDKs implement protocol V1 only.

## Sandbox

`qodiqa dev` starts a local sandbox with a simulated provider and disposable PostgreSQL and Redis. No hosted sandbox is offered.

## Performance

No throughput, sustained-capacity or scalability figure is claimed.
