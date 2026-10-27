# Exposure incidents: detection, ticket, notification drafts

When sensitive data **reaches** a caller that should not have it, QODIQA raises an alert, gives the on-call person the facts, and drafts the text of the notifications that data-protection
law commonly requires. It does not decide whether an incident is notifiable, does not send anything to an authority or to people, and **makes no claim of compliance**.

## 1. Detection

The DLP stage ([DLP.md](DLP.md)) emits a `DLP_TRANSFORM` event for every rule that found something. The alert detector (`src/alerting/detection/OperationalDetector.js`) turns two kinds
of event into a `GOVERNANCE` / `DATA_EXPOSURE` alert:

| Event | Alert | Severity |
|---|---|---|
| direction `output` or `tool_output`, action `DETECT`, a credential, key material, financial or national-id rule | sensitive data delivered unchanged | HIGH |
| action `DETECT`, an `EXFIL:*` rule (new sensitive data in an answer, a data-carrying link or image, bulk records, an encoded blob) | possible exfiltration | CRITICAL |

What raises **nothing**: a rule that redacted, masked or blocked (the exposure was prevented and the audit trail records it), the input direction, personal data alone (e-mail, phone),
and classification labels. If you want exposure to be prevented rather than reported, use `REDACT` or `BLOCK`; `DETECT` is the setting that tells you after the fact.

The alert's evidence holds rule ids, the number of items, the policy id, the request id and the two text hashes. **It never holds a value.**

## 2. The ticket

The alert is the ticket: it is stored in the alert store (tenant-isolated, with its history of acknowledgements and resolutions), notified through the configured channels (e-mail, Slack,
Teams, PagerDuty, a webhook into the operator's own ticketing system, SIEM) and escalated by the existing escalation schedule for its severity. Acknowledge, resolve, suppress and
mark-false-positive work as for any alert (`/alerts/:id/...`).

## 3. Notification drafts

`GET /alerts/{id}/exposure-notification?organisation=<name>&contact=<dpo contact>` (read access to the audit data; `409 NOT_AN_EXPOSURE_ALERT` for any other alert) returns:

* `facts`: when the gateway noticed, where (answer or tool result), whether it was delivered unchanged, the categories of data **in words** (payment card numbers, API keys, ...), the number of
  items, the request reference, the text hashes;
* `clock`: the moment of detection and a **reference** deadline 72 hours later (the period GDPR Art. 33(1) uses), labelled as reference only;
* `drafts`: `internal` (incident record), `authority` (supervisory authority), `dataSubjects` (affected people), `controller` (a processor telling its controller).

Every draft begins with a statement that it is a draft, not legal advice, and that it does not assert that an obligation exists or that sending it satisfies any law. Everything the system
cannot know (how many people, the likely consequences, the measures taken, the root cause) is an explicit `[[TO FILL: ...]]` item. Drafts are in English; translate and have counsel review them
before use.

## What this is not

* It does not decide that an incident is a personal-data breach, who must be told, or by when.
* The moment the gateway detected the event is not necessarily the legal moment of "awareness".
* It cannot see exposures it was not configured to look for: a DLP rule must be in force on the direction concerned, and the limits in [DLP.md](DLP.md) (no images, no spelled-out numbers,
  no arbitrary encodings) apply.
