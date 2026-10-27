# QODIQA documentation

QODIQA Gateway sits in front of AI model providers. A request is executed only if it carries a valid signed authorization; every decision becomes signed evidence that can be checked offline.

## Where to start

| You want to | Read |
|---|---|
| Know what QODIQA is and is not | [Overview](overview.md), [Design principles](design-principles.md), [Scope and limitations](limitations.md) |
| Try it locally | [Quickstart](guides/quickstart.md), [Installation](guides/installation.md) |
| Understand the design | [Architecture overview](architecture/overview.md), [Enforcement flow](architecture/enforcement-flow.md), [Verification flow](architecture/verification-flow.md), [Glossary](glossary.md) |
| Call the API | [API overview](api/overview.md), [Generated reference](api/REFERENCE.md), [OpenAPI contract](api/openapi.json), [Versioning](api/versioning.md) |
| Implement or verify the protocol | [Protocol](protocol/QODIQA-PROTOCOL.md), [Protocol V2](protocol/PROTOCOL-V2.md), [Audit schema v8](protocol/AUDIT-SCHEMA-V8.md), [Delegation](protocol/DELEGATION.md), [Versioning](protocol/VERSIONING.md), [Test vectors](protocol/VECTORS-FORMAT.md) |
| Integrate from code | SDK guides under [sdk/](sdk/javascript/README.md) (JavaScript, Python); the Go and Java SDKs have a README in their own folder under `sdk/` |
| Configure it | [Configuration reference](configuration/reference.md), [Boot rules](configuration/boot-rules.md), [Providers](guides/providers.md), [Policy language](guides/POLICY_LANGUAGE.md) |
| Deploy it | [Production deployment](deployment/production.md), [Production checklist](deployment/production-checklist.md), [Topology](deployment/topology.md), [Redis](deployment/redis.md), [Kubernetes probes](deployment/kubernetes-probes.md), [Helm](operations/helm.md) |
| Operate it | [Operations index](operations/README.md), [Runbook](operations/runbook.md), [Monitoring](operations/monitoring.md), [Troubleshooting](operations/troubleshooting.md), [Backup and restore](operations/backup-runbook.md) |
| Secure it | [Security guide](security/SECURITY_GUIDE.md), [Threat model](security/THREAT_MODEL.md), [Cryptography](security/cryptography.md), [Key management](security/key-management.md), [Secrets](security/secrets-management.md), [RBAC](security/RBAC_MODEL.md) |
| Sign users in (OIDC, SAML, LDAP) | [Identity](guides/IDENTITY.md) |
| Hand evidence to an auditor | [Evidence bundle verification](security/evidence-bundle-verification.md), [Audit anchoring](security/audit-anchoring.md) |
| Change the code | [Development guide](development.md) |
| Read the formal models | [Formal models](formal/README.md) |

## Scope and limitations

See [Scope and limitations](limitations.md).
