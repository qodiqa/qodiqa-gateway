# Data governance: minimisation, retention, residency

Three controls decide what is sent where and how long it is kept. All three are **policy rules** in the tenant's policy set, so they are validated at load, governed by the same
maker-checker publication as every other rule, and covered by `policyHash` (the hash recorded in the audit chain changes when they change). They are not a compliance claim:
they are the mechanisms an operator uses to meet their own obligations.

## Minimisation: send the provider only what it needs

`enterprise/dlp/profiles.js` ships three rule sets (`light`, `standard`, `strict`) built from the DLP rules described in [DLP.md](DLP.md); copy the rules you want into the tenant's
policy set and edit freely. `light` redacts credentials and records personal data; `standard` redacts personal, financial and national-id data in requests and secrets in answers;
`strict` also redacts answers, screens tool arguments and results, and refuses anything classified RESTRICTED.

## Retention by data category

Retention of audit data is configured with the audit retention policies (`src/core/audit/retention.js`), per category and in days (`0` = keep, only where the category allows it).
The categories, what each contains, where it lives and who enforces it are in `src/core/dataGovernance/categories.js` (`inventory()` returns the list):

| Category | Contains | Engine | Tenant may set |
|---|---|---|---|
| `audit_security` | actor ids, client IPs, reasons | audit retention engine | 365 - 3650 days, or keep |
| `audit_access_control` | user ids, client IPs | audit retention engine | 365 - 3650 days, or keep |
| `audit_operational` | request ids, client IPs | audit retention engine | 30 - 730 days |
| `audit_provider` | provider names, request ids | audit retention engine | 30 - 730 days |
| `audit_enforcement_chain` | hashes, decisions | platform | no: never deleted automatically, its value is that it stays verifiable |
| `agent_action_ledger` | agent ids, action hashes, approver ids | platform | no: part of the verifiable action chain; follows the backup and DR policy |
| `dlp_events` | rule ids, text hashes (never the values) | platform | no: carried by the audit categories |

Retention policies are rows of `audit_retention_policies`, applied by the audit retention engine under the dedicated retention role; `ENFORCEMENT` events and legal holds are never
touched. A value outside the bounds of its category is refused. Prompts and answers are not stored by the gateway at all (only hashes), so there is no "conversation retention" to configure.

## Residency: where data may be processed

`DATA_RESIDENCY` rule:

```json
{ "id": "RESIDENCY_EU", "type": "DATA_RESIDENCY", "priority": 5, "enabled": true,
  "config": { "residencyFormat": 1, "tenantRegion": "eu", "allowedRegions": ["eu", "ch"],
              "providerRegions": { "local": "eu", "swiss-llm": "ch", "openai": "us" } } }
```

A region is a label the operator chooses (`eu`, `eu-west-1`, `us`); QODIQA compares strings and does not know geography, so **`providerRegions` is a declaration the operator is
responsible for**. The policy engine checks every request against it: a provider whose region is not allowed is refused (`RESIDENCY_CROSS_REGION_BLOCKED`) before the provider is
called, and a provider with **no declared region is refused too** (`RESIDENCY_PROVIDER_REGION_UNKNOWN`: unknown is not allowed). The same check runs for a failover target (the
failover authorisation re-evaluates the policy set for the target), so a failover cannot move data into a forbidden region.

What it does not do: it does not inspect where a provider's own infrastructure really runs, does not restrict where QODIQA itself is deployed, and does not govern what the
operator exports from the audit chain.
