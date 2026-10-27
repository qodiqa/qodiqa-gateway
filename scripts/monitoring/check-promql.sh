#!/usr/bin/env bash
# syntax-checks every PromQL expression of the Grafana dashboards and the alert rules with promtool (docker image prom/prometheus).
# Usage: bash scripts/monitoring/check-promql.sh     (needs Docker; exits non-zero on the first invalid expression)
cd "$(dirname "$0")/../.." || exit 2
export MSYS_NO_PATHCONV=1
TMP=".promql-check"
mkdir -p "$TMP"
node -e '
const fs = require("fs"), path = require("path");
const dir = "deploy/monitoring/grafana";
const rules = [];
for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
  const d = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  for (const p of d.panels) for (const t of p.targets || []) rules.push({ record: "dash:" + f.replace(/[^a-z0-9]/gi, "_") + ":" + p.id + ":" + t.refId, expr: t.expr });
}
const yaml = "groups:\n  - name: dashboards\n    rules:\n" + rules.map((r) => "      - record: " + r.record + "\n        expr: " + JSON.stringify(r.expr)).join("\n") + "\n";
fs.writeFileSync(process.argv[1], yaml);
console.log("dashboard expressions:", rules.length);
' "$TMP/dashboards.rules.yml" || exit 1
docker run --rm -v "$(pwd -W 2>/dev/null || pwd):/repo" --entrypoint promtool prom/prometheus:v2.54.1 check rules "/repo/$TMP/dashboards.rules.yml" || exit 1
# the alert rules (PrometheusRule manifest): promtool wants the bare groups document
node -e '
const fs = require("fs");
const y = fs.readFileSync("deploy/helm/qodiqa/files/prometheus-rules.yaml", "utf8");
const i = y.indexOf("spec:\n");
const body = y.slice(i + 6).split("\n").map((l) => l.replace(/^  /, "")).join("\n");
fs.writeFileSync(process.argv[1], body);
' "$TMP/alerts.rules.yml" || exit 1
docker run --rm -v "$(pwd -W 2>/dev/null || pwd):/repo" --entrypoint promtool prom/prometheus:v2.54.1 check rules "/repo/$TMP/alerts.rules.yml"
