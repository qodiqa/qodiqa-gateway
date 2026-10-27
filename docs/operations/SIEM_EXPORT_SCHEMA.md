# SIEM Export Schema Reference

**Status:** Accepted
**Component:** #6 — Standard SIEM Export (finding: "current export is proprietary")

QODIQA ships its operational/audit log stream to external SIEM/log-management
systems via `src/observability/logShipping/`. Three export
schemas are available, all sourced from the identical normalized event
produced by `src/observability/logShipping/schema.js`'s `normalizeEvent()`:

| Schema | Destination(s) | Format | Default |
|---|---|---|---|
| CEF (Common Event Format) | `siem` destination, syslog or HTTP | ArcSight CEF:0 over RFC 5424 syslog, or CEF-embedded JSON | Always available — unchanged by this document |
| Raw / proprietary | `elk`, `splunk` destinations | The normalized event object, serialized as-is | Default for `elk`/`splunk` (`schema: 'raw'`) |
| **Elastic Common Schema (ECS)** | `elk` destination | ECS v8.11-shaped JSON | Opt-in: `QODIQA_LOGSHIP_ELK_SCHEMA=ecs` |
| **Splunk Common Information Model (CIM)** | `splunk` destination | CIM "Alerts" data model-shaped JSON | Opt-in: `QODIQA_LOGSHIP_SPLUNK_SCHEMA=cim` |

CEF and the raw/proprietary format are **never removed** — ECS and CIM are
strictly additive, opt-in alternate output schemas on the existing `elk` and
`splunk` destinations. No new transport was introduced; this is a
field-mapping layer on top of the transports that already existed.

---

## Enabling ECS or CIM export

```bash
# ELK destination, ECS-shaped output
QODIQA_LOGSHIP_ELK_ENABLED=true
QODIQA_LOGSHIP_ELK_URL=https://logstash.company.com
QODIQA_LOGSHIP_ELK_SCHEMA=ecs        # default: raw

# Splunk destination, CIM-shaped output
QODIQA_LOGSHIP_SPLUNK_ENABLED=true
QODIQA_LOGSHIP_SPLUNK_URL=https://splunk.company.com:8088
QODIQA_LOGSHIP_SPLUNK_TOKEN=<hec-token>
QODIQA_LOGSHIP_SPLUNK_SCHEMA=cim     # default: raw
```

An unrecognized schema value (typo, unsupported name) falls back to `raw`
and emits `LOGSHIP_CONFIG_INVALID` at startup — it never hard-fails startup
and never silently ships malformed output.

A mapping-function failure at send time (malformed event, unexpected shape)
falls back to the raw event for that specific event and increments
`qodiqa_logship_schema_mapping_errors_total{destination, schema}` — delivery
is never blocked by a mapping error.

---

## ECS field mapping (`src/observability/siem/ecsMapper.js`)

Source: the normalized event `{timestamp, service, environment, tenantId,
tenantSlug, eventType, severity, requestId, traceId, message, metadata}`.

| ECS field | Source | Notes |
|---|---|---|
| `@timestamp` | `event.timestamp` | ISO 8601, unchanged |
| `ecs.version` | *(constant)* | Pinned to `8.11` |
| `event.action` | `event.eventType`, lowercased | e.g. `audit_chain_corrupted` |
| `event.category` | `event.metadata.category` | See category table below — best-effort mapping |
| `event.severity` | `event.severity` | Numeric, 0 (INFO) – 10 (FATAL/CRITICAL) |
| `event.outcome` | `event.severity` | `success` (INFO) / `unknown` (WARN) / `failure` (ERROR/CRITICAL/FATAL) |
| `trace.id` | `event.traceId` | Omitted entirely when absent |
| `service.name` | `event.service` | |
| `service.environment` | `event.environment` | |
| `message` | `event.message` | |
| `qodiqa.event_type` | `event.eventType` | Raw, unmodified — exact-match reference for searches/alerts keyed on the original event name |
| `qodiqa.tenant.id` / `.slug` | `event.tenantId` / `event.tenantSlug` | |
| `qodiqa.request.id` | `event.requestId` | |
| `qodiqa.metadata` | `event.metadata` | Full pass-through, vendor-namespaced |

### `event.category` mapping

QODIQA's internal category taxonomy (`services/logClassifier.js`) has three
values — `SECURITY`, `AUDIT`, `OPERATIONAL` — none of which map 1:1 onto
ECS's fixed controlled vocabulary. The mapping below is a defensible
approximation for SIEM routing/search, **not** an authoritative
categorization:

| QODIQA category | ECS `event.category` |
|---|---|
| `SECURITY` | `['intrusion_detection']` |
| `AUDIT` | `['iam']` |
| `OPERATIONAL` | `['process']` |
| *(unrecognized/missing)* | `['process']` |

### Example ECS-mapped event

```json
{
  "@timestamp": "2026-07-25T00:00:00.000Z",
  "ecs": { "version": "8.11" },
  "event": {
    "action": "audit_chain_corrupted",
    "category": ["intrusion_detection"],
    "severity": 10,
    "outcome": "failure"
  },
  "trace": { "id": "trace-1" },
  "service": { "name": "qodiqa", "environment": "production" },
  "message": "chain hash mismatch",
  "qodiqa": {
    "event_type": "AUDIT_CHAIN_CORRUPTED",
    "tenant": { "id": "tenant-1", "slug": "acme" },
    "request": { "id": "req-1" },
    "metadata": { "category": "SECURITY" }
  }
}
```

---

## CIM field mapping (`src/observability/siem/cimMapper.js`)

Scoped to Splunk's **Alerts** data model — the closest fit for QODIQA's
operational/security/audit event stream — rather than attempting full
coverage of every CIM data model.

| CIM field | Source | Notes |
|---|---|---|
| `_time` | `event.timestamp` | Unix epoch seconds |
| `signature` | `event.eventType` | Raw, unmodified — the alert/event name |
| `severity` | `event.severity` | CIM string enum: `informational`/`low`/`high`/`critical` |
| `severity_id` | `event.severity` | Numeric, 1 (informational) – 5 (critical) |
| `dest` | `event.service` | The QODIQA instance/service name |
| `vendor_product` | *(constant)* | `QODIQA Platform` |
| `app` | *(constant)* | `qodiqa` |
| `tenant` | `event.tenantId` | |
| `request_id` | `event.requestId` | |
| `trace_id` | `event.traceId` | Omitted entirely when absent |
| `description` | `event.message` | Truncated to 500 characters |

`user` and `src` (source IP) are **intentionally omitted** — the normalized
QODIQA event schema does not carry an acting-user identity or source IP at
the operational-log layer (that data lives in the audit chain itself, not
this stream), and populating them with a placeholder would be misleading in
Splunk's Alerts-model searches.

### Example CIM-mapped event

```json
{
  "_time": 1785024000,
  "signature": "AUDIT_CHAIN_CORRUPTED",
  "severity": "critical",
  "severity_id": 5,
  "dest": "qodiqa",
  "vendor_product": "QODIQA Platform",
  "app": "qodiqa",
  "tenant": "tenant-1",
  "request_id": "req-1",
  "trace_id": "trace-1",
  "description": "chain hash mismatch"
}
```

---

## Versioning and compatibility

- ECS is pinned to version **8.11** (`ecs.version` field). A future ECS
  version bump is a deliberate, documented change to `ecsMapper.js`, not an
  automatic drift.
- CIM has no single version field (Splunk's CIM add-on versions its own
  schema separately); the "Alerts" model field set above is the contract.
- Both mappers are pure functions (`mapToEcs(event)` / `mapToCim(event)`) —
  unit-tested independently of the transport layer
  (`src/observability/siem/__tests__/`), and exercised end-to-end via
  `src/observability/logShipping/__tests__/integration.test.js`.
- CEF (`src/observability/siem/cef.js`) and the raw/proprietary schema are
  unaffected by this document and remain the default for every destination
  unless `QODIQA_LOGSHIP_{ELK,SPLUNK}_SCHEMA` is explicitly set.
