# Notification Channel Setup

**How to make sure a human actually hears about a CRITICAL alert.**

QODIQA's alerting framework (`src/alerting/` — see [ALERTING_FRAMEWORK.md](alerting.md)
for the full architecture) automatically **detects** operational failures:
PostgreSQL/Redis outages, HA/multi-instance violations, audit chain
corruption, signing/KMS provider failures, policy enforcement invariant
violations, replay attacks, and more. Detection alone is not delivery —
every notification channel ships **disabled by default**. This runbook is
the operator-facing checklist for turning delivery on.

---

## 1. Supported channels

| Channel | Transport | Best for |
|---|---|---|
| Webhook | Generic HMAC-signed HTTPS POST | Any custom receiver, or a Slack/Teams-compatible collector |
| Slack | Incoming Webhook (Block Kit) | Team chat visibility |
| Microsoft Teams | Incoming Webhook (Adaptive Card) | Team chat visibility (MS shops) |
| Email | SMTP (built-in), SendGrid, or Mailgun | Distribution lists, compliance archiving |
| PagerDuty | Events API v2 | Paging on-call for HIGH/CRITICAL |
| SMS | Twilio, or a generic SMS gateway webhook | CRITICAL-only, out-of-band paging |
| SIEM | Splunk HEC (HTTP) or Syslog (UDP/TCP), CEF format | Security operations center ingestion |

All 7 channels share the same delivery engine (`BaseChannel.js`): exponential
backoff retry (default 3 attempts), per-channel token-bucket rate limiting,
a bounded request timeout (10s default for HTTP channels, configurable for
Webhook via `ALERT_WEBHOOK_TIMEOUT_MS`; 15s for the SMTP raw-socket client),
and delivery is always non-blocking and never crashes the process — a
channel that is down or misconfigured only logs `ALERT_NOTIFICATION_FAILED`
and increments `qodiqa_alert_notification_failed_total`.

## 2. Configuration

See the **"NOTIFICATION CHANNELS"** section of
[`deploy/env/production.env.example`](../../deploy/env/production.env.example) for the full,
copy-pasteable variable list with placeholders and per-variable
documentation. Minimal example to get CRITICAL alerts flowing to Slack:

```bash
ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/xxxxxxxx
```

That single variable is enough — `NotificationService` enables a channel
the moment it has a configured recipient (no separate "enabled" flag is
required; `ALERT_SLACK_ENABLED=false` exists only to explicitly *disable* a
channel that otherwise has a recipient configured, e.g. temporarily during
maintenance).

### 2a. Email/SMTP transport security (STARTTLS)

The built-in raw-socket SMTP client (`ALERT_EMAIL_PROVIDER=smtp`, the default)
always negotiates STARTTLS before doing anything else, whenever the relay
advertises it in its EHLO response — this applies even when no
`ALERT_EMAIL_SMTP_USER`/`_PASS` are configured, so message content benefits
too. **AUTH LOGIN is never issued over an unencrypted socket.** If the relay
does not advertise STARTTLS and credentials are configured, the client
refuses to connect rather than send them in plaintext:

```
SMTP: relay does not advertise STARTTLS — refusing to send AUTH LOGIN
credentials in plaintext. Set ALERT_EMAIL_TRUSTED_RELAY_ONLY=true only for
a relay reachable exclusively over a trusted internal network, or switch
ALERT_EMAIL_PROVIDER to sendgrid/mailgun for Internet-facing delivery.
```

Two SMTP-only configuration flags control this behavior — both default to
the secure choice:

| Variable | Default | Purpose |
|---|---|---|
| `ALERT_EMAIL_SMTP_TLS_REJECT_UNAUTHORIZED` | `true` | Set to `false` only to accept a self-signed or internal-CA relay certificate during STARTTLS. Leave at the default for any relay with a certificate issued by a public/trusted CA. |
| `ALERT_EMAIL_TRUSTED_RELAY_ONLY` | unset (refuse) | Set to `true` only when the configured `ALERT_EMAIL_SMTP_HOST` is a relay reachable **exclusively** over a network you trust (e.g. a same-VPC internal relay with no public route) and that relay does not support STARTTLS. This permits AUTH LOGIN over plaintext for that relay only — it does not weaken TLS certificate validation. |

**Recommendation for Internet-facing deployments**: do not set
`ALERT_EMAIL_TRUSTED_RELAY_ONLY`. If your outbound relay genuinely has no
STARTTLS support, switch `ALERT_EMAIL_PROVIDER` to `sendgrid` or `mailgun`
instead — both deliver over HTTPS and never touch this code path.

You do not need to configure all 7 — pick what fits your on-call tooling.
Multiple channels can be enabled at once; severity determines fan-out (see
`SeverityModel.js`): INFO is stored-only, LOW reaches Webhook+SIEM, MEDIUM
adds Slack, HIGH adds Teams/PagerDuty/Email, and CRITICAL fans out to all 7.

**Recommended minimum for production**: one chat channel (Slack or Teams)
for visibility, plus PagerDuty for actual paging, plus SIEM if you already
run a SOC pipeline. Compliance-sensitive deployments should also set:

```bash
QODIQA_REQUIRE_NOTIFICATION_CHANNEL=true
```

This makes startup **fail closed** (`process.exit(1)`) instead of merely
warning when zero channels are configured — see §4.

## 3. Testing your configuration

Two endpoints exist specifically for this (mounted at `/alerts`, RBAC-gated,
`READ_AUDIT` permission required):

```bash
# Confirm QODIQA's own view of what's configured/reachable
curl -H "Authorization: Bearer <api-key>" https://your-host/alerts/health

# Send an actual test notification through one channel
curl -X POST -H "Authorization: Bearer <api-key>" https://your-host/alerts/test/SLACK
```

`GET /alerts/health` reports `{ enabled, ok, latencyMs, error? }` per channel.
`POST /alerts/test/:channel` sends a real INFO-severity test alert through
that one channel — confirm it actually arrives in Slack/PagerDuty/etc.,
not just that the API call returned 200.

For an end-to-end smoke test that exercises detection too (not just
delivery), see the `node -e` snippet in
[ALERTING_FRAMEWORK.md](alerting.md#testing).

## 4. Startup validation

On every startup, QODIQA logs one of three outcomes (see `server.js`,
"Startup: notification channel configuration"):

| Condition | Log event | Effect |
|---|---|---|
| ≥1 channel configured | `NOTIFICATION_CHANNELS_READY` (INFO) | Lists which channels are enabled |
| 0 channels, `QODIQA_REQUIRE_NOTIFICATION_CHANNEL` unset/false | `NO_NOTIFICATION_CHANNEL_CONFIGURED` (WARN) | Startup continues — alerts will be detected but not delivered |
| 0 channels, `QODIQA_REQUIRE_NOTIFICATION_CHANNEL=true` | `NOTIFICATION_CHANNEL_REQUIRED_BUT_MISSING` (FATAL) | `process.exit(1)` |

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `NO_NOTIFICATION_CHANNEL_CONFIGURED` at startup | No `ALERT_*` recipient env var set | Set at least one channel's URL/key per §2 |
| `GET /alerts/health` shows `enabled: false` for a channel you configured | Typo in the env var name, or `ALERT_<CHANNEL>_ENABLED=false` explicitly set | Re-check exact variable name against `deploy/env/production.env.example`; remove the `_ENABLED=false` override |
| `ALERT_NOTIFICATION_FAILED` in logs, channel shows `enabled: true` | Endpoint unreachable, wrong URL/token, or outbound firewall blocking the destination | Check `error` field in the log line; test connectivity from the QODIQA host to the destination; verify credentials haven't rotated |
| Slack/Teams message never arrives despite `ALERT_NOTIFICATION_SENT` logged | Webhook URL points to the wrong channel/workspace, or the webhook was deleted/revoked on the provider side | Regenerate the incoming webhook URL in Slack/Teams and update the env var |
| Only some alerts notify, others don't | Working as intended — severity gates which channels fire (§2); an INFO-level event is stored-only by design | Check the alert's `severity` via `GET /alerts/:id`; only MEDIUM+ triggers immediate notification |
| Email/SMTP fails with `SMTP timeout` | SMTP host/port unreachable, or TLS/auth misconfigured | Verify `ALERT_EMAIL_SMTP_HOST/_PORT` reachability and credentials; consider switching `ALERT_EMAIL_PROVIDER` to `sendgrid`/`mailgun` if outbound SMTP (port 587/465) is blocked by your network |
| Email/SMTP fails with `relay does not advertise STARTTLS` | Relay has no STARTTLS support and credentials are configured — refused by design (§2a) | If the relay is genuinely internal/trusted, set `ALERT_EMAIL_TRUSTED_RELAY_ONLY=true`; otherwise switch `ALERT_EMAIL_PROVIDER` to `sendgrid`/`mailgun` |
| Email/SMTP fails with a certificate/`unable to verify` error | Relay presents a self-signed or internal-CA certificate during STARTTLS | Install the internal CA where QODIQA runs, or — only for a relay you trust — set `ALERT_EMAIL_SMTP_TLS_REJECT_UNAUTHORIZED=false` |
| Multi-instance HA guard exits but no webhook arrived | Expected in some cases — see §6 | The stderr `FATAL` log line is the authoritative signal; the webhook is best-effort |

## 6. Notification architecture

```
Detection (DetectionEngine, per-domain detectors)
        │  eventBus 'log' events
        ▼
AlertEngine.createAlert()  ──▶  AlertStore (PostgreSQL / in-memory fallback)
        │
        ├──▶ CorrelationEngine (groups related alerts into incidents)
        │
        └──▶ NotificationService.notify()
                   │  severity → channel list (SeverityModel.js)
                   ▼
             BaseChannel.deliver()  (retry + rate limit + timeout, per channel)
                   │
                   ▼
        Webhook / Slack / Teams / Email / PagerDuty / SMS / SIEM
```

**One path runs outside this diagram entirely**: the multi-instance HA
startup guard (`src/core/audit/multiInstanceGuard.js`) calls
`process.exit(1)` at server startup *before* the alerting framework above
has initialized, so it cannot route through `NotificationService`. It uses
a separate, minimal, best-effort notifier
(`src/runtime/earlyCriticalNotify.js`) that posts directly to
`ALERT_WEBHOOK_URL` and is deliberately not awaited — the guard's exit must
stay synchronous and immediate (see that module's header comment for why).
The stderr `FATAL` diagnostic line (`src/runtime/rawStderrDiagnostic.js`,
always captured by your log aggregator/systemd/container runtime) remains
the authoritative signal for this one path; the webhook is a best-effort
addition on top of it, not a replacement.

## 7. Metrics

`GET /metrics` exposes, per channel:

- `qodiqa_alert_notification_sent_total{channel,severity}`
- `qodiqa_alert_notification_failed_total{channel,severity}`
- `qodiqa_alert_notification_retries_total{channel}`
- `qodiqa_alert_notification_rate_limited_total{channel}`

Alert on a sustained non-zero rate of `_failed_total` for any channel you
depend on — it means alerts are being generated but not reaching that
destination.

## Related documentation

| Topic | Location |
|---|---|
| Full alerting architecture, detection rules, severity model | [ALERTING_FRAMEWORK.md](alerting.md) |
| Unified metrics/alerting model, alert catalog | [metrics-and-alerting.md](metrics-and-alerting.md) |
| Environment variable reference | [deploy/env/production.env.example](../../deploy/env/production.env.example) |
| Incident response procedures | [incident-response.md](incident-response.md) |
