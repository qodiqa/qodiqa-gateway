# Monitoring: Prometheus rules and Grafana dashboards

> Status: **tested and verified internally** — rules and dashboard queries are checked against the metrics the gateway registers and syntax-checked with `promtool`; not yet watched on a long-running production cluster.

## Prometheus

- `GET /metrics` needs the operator credential. The Helm chart's ServiceMonitor takes the Secret that holds it (`monitoring.serviceMonitor.bearerTokenSecret`).
- Alert rules: `deploy/helm/qodiqa/files/prometheus-rules.yaml` (also `deploy/kubernetes/overlays/examples/monitoring/prometheusrule.yaml`; a test keeps the two equal). 70 alerts on the gateway's fail-closed, integrity and dependency signals
  (kill switch, audit append and fsync, chain verifier, gap scanner, anchors, transparency, 5xx rate, disk). Every rule carries `severity`, `summary` and a `runbook_url` that resolves to a repository heading.
- Note: a labelled counter only appears at its first increment and Prometheus `increase()` never sees a series' first sample; the rules therefore either rely on seeded series or use `(increase(X[w]) > 0) or (X > 0 unless X offset w)`.

## Grafana

`deploy/monitoring/grafana/*.json` (import through the Grafana UI or provision from the directory; they use a `datasource` variable of type Prometheus):

| Dashboard | Shows |
| --- | --- |
| `qodiqa-overview.json` | requests per second, 5xx ratio, in-flight requests, kill switch; responses by status class and route family; EXECUTE/BLOCK and blocks by reason; request latency p50/p95/p99; admission control (in flight, queued, refused); event-loop delay; authentication failures and lockouts |
| `qodiqa-audit-integrity.json` | audit append latency and failures, fail-closed refusals, fsync latency, PostgreSQL mirror lag; chain-verifier violations, mirror drift, unrecoverable gaps, anchor mismatches; verifier and gap-scanner runs; pending external anchors |
| `qodiqa-providers.json` | provider failures by code, cancelled calls, accounted cost per hour and tokens per minute by provider (from the operator's tariffs) |

The files are generated (`node scripts/monitoring/generate-grafana.js`; `--check` fails on drift). Every metric a panel uses must be registered by `src/observability/metrics.js` (a unit test enforces it); `scripts/monitoring/check-promql.sh` runs every expression through `promtool`.

## Limits

- Dashboards were checked for syntax and metric names, not against a live Grafana with real traffic; panel thresholds are starting points.
- Label names come from the code (`route_family`, `status_class`, `decision`, `reason`, `provider`, `code`, `route`, `cause`, `mode`, `outcome`, `kind`, `currency`, `direction`).
