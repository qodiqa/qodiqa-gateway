'use strict';

/**
 * Drafts for an exposure incident: what an operator needs on the table when a DATA_EXPOSURE alert is raised - an internal summary and the text of the notifications
 * that data-protection law commonly requires (to a supervisory authority, to the affected people, from a processor to the controller). Built ONLY from facts the system holds
 * (when it noticed, which categories of data, how many items, which direction, the request id and the two text hashes); everything the system cannot know is an explicit
 * `[[TO FILL: ...]]` placeholder.
 *
 * THESE ARE DRAFTS. They are not legal advice, they do not say that a notification obligation exists, that a deadline applies, or that sending them makes anyone compliant:
 * whether an incident is a notifiable breach, to whom, and by when is a decision for the operator and their counsel. Every draft starts with that statement.
 *
 *   exposureFacts(alert)              the facts, with the data categories in words
 *   exposureClock(alert, { hours })   when the operator became aware and a reference deadline (default 72 h, the figure GDPR Art. 33(1) uses) - informational only
 *   exposureDrafts(alert, opts)       { facts, clock, drafts: { internal, authority, dataSubjects, controller } }, each { audience, subject, body }
 */

const DISCLAIMER = 'DRAFT generated from system facts. It has not been reviewed by counsel and is not legal advice. It does not state that a notification obligation exists, that any deadline '
  + 'applies, or that sending it satisfies any law. Complete or delete every [[TO FILL: ...]] item before use.';

// what a rule id means in words (data categories, never values)
const CATEGORY_WORDS = Object.freeze({
  CARD: 'payment card numbers', IBAN: 'bank account numbers (IBAN)', CNP: 'national identification numbers (Romania, CNP)', PESEL: 'national identification numbers (Poland, PESEL)',
  BSN: 'national identification numbers (Netherlands, BSN)', DE_TAX_ID: 'tax identification numbers (Germany)', US_SSN: 'national identification numbers (US SSN)',
  ES_DNI_NIE: 'national identification numbers (Spain, DNI/NIE)', UK_NINO: 'national insurance numbers (UK)', EMAIL: 'e-mail addresses', PHONE: 'telephone numbers',
  PEM_BLOCK: 'private cryptographic keys', JWT: 'authentication tokens', CODE_SECRET: 'passwords or secrets in code or configuration',
});
const wordsFor = (rule) => (rule.startsWith('KEY_') ? 'API keys or access tokens' : rule.startsWith('EXFIL:') ? 'a possible exfiltration pattern' : rule.startsWith('CLASS:') ? 'data classified ' + rule.slice(6).toLowerCase() : CATEGORY_WORDS[rule] || rule);

function exposureFacts(alert) {
  if (!alert || alert.subtype !== 'DATA_EXPOSURE') throw new TypeError('exposureFacts: not a DATA_EXPOSURE alert');
  const ev = alert.evidence || {};
  const rules = Array.isArray(ev.rules) ? ev.rules : [];
  return {
    alertId: alert.id, severity: alert.severity, tenantId: alert.tenantId || ev.tenantId || null, requestId: alert.requestId || ev.requestId || null,
    detectedAt: alert.detectedAt ? new Date(alert.detectedAt).toISOString() : null,
    where: ev.direction === 'tool_output' ? 'the result of a tool call' : 'a model answer',
    deliveredUnchanged: ev.action === 'DETECT',
    ruleIds: rules, categories: [...new Set(rules.map(wordsFor))], itemCount: Number.isInteger(ev.findings) ? ev.findings : null,
    policyId: ev.policyId || null, textHashBefore: ev.inputHashBefore || null, textHashAfter: ev.inputHashAfter || null,
  };
}

function exposureClock(alert, { hours = 72 } = {}) {
  const aware = alert && alert.detectedAt ? new Date(alert.detectedAt) : null;
  if (!aware || Number.isNaN(aware.getTime())) return { awareAt: null, referenceDeadline: null, referenceHours: hours, note: 'the detection time is unknown' };
  return {
    awareAt: aware.toISOString(), referenceDeadline: new Date(aware.getTime() + hours * 3_600_000).toISOString(), referenceHours: hours,
    note: `Reference only: ${hours} hours after the moment the operator became aware is the period GDPR Art. 33(1) uses for a notification to a supervisory authority. Whether and when it applies to this incident is for the operator and counsel to decide; the system's detection time is not necessarily the legal moment of awareness.`,
  };
}

const list = (a) => (a.length ? a.map((x) => `  - ${x}`).join('\n') : '  - [[TO FILL: categories of data]]');
const fill = (what) => `[[TO FILL: ${what}]]`;

function exposureDrafts(alert, { controller, dpo } = {}) {
  const f = exposureFacts(alert); const clock = exposureClock(alert);
  const who = (controller && controller.name) || fill('organisation name'); const contact = (dpo && dpo.contact) || fill('data protection officer or contact point');
  const factsBlock = [
    `Alert: ${f.alertId} (${f.severity})`, `Detected by the gateway at: ${f.detectedAt || fill('time')}`, `Where: ${f.where}`,
    `Delivered unchanged to the caller: ${f.deliveredUnchanged ? 'yes (the DLP rule only recorded it)' : 'no'}`,
    `Categories of data detected:\n${list(f.categories)}`, `Number of items detected: ${f.itemCount === null ? fill('count') : f.itemCount}`,
    `Request reference: ${f.requestId || fill('request id')}${f.tenantId ? ` (tenant ${f.tenantId})` : ''}`,
  ].join('\n');
  const common = (title) => `${DISCLAIMER}\n\n${title}\n\n`;
  const drafts = {
    internal: { audience: 'internal incident record', subject: `[Exposure incident] ${f.categories.join(', ') || 'sensitive data'} in ${f.where}`,
      body: common('INTERNAL INCIDENT SUMMARY') + `${factsBlock}\n\nSystem references (no values are held here): text hash before ${f.textHashBefore || 'n/a'}, after ${f.textHashAfter || 'n/a'}, policy ${f.policyId || 'n/a'}.\n\n`
        + `Reference clock: aware at ${clock.awareAt || 'unknown'}; reference deadline ${clock.referenceDeadline || 'unknown'} (${clock.referenceHours} h). ${clock.note}\n\n`
        + `Decisions to record: is this a notifiable breach? ${fill('yes / no and why')}\nWho decided and when: ${fill('name, time')}\nContainment actions: ${fill('what was done')}\nRoot cause: ${fill('cause')}\n` },
    authority: { audience: 'supervisory authority', subject: `Personal data breach notification - ${who}`,
      body: common('NOTIFICATION TO THE SUPERVISORY AUTHORITY (draft)') + `From: ${who}\nContact: ${contact}\n\n1. Nature of the breach\n${factsBlock}\n${fill('how the data came to be exposed, in plain words')}\n\n`
        + `2. Categories and approximate number of data subjects: ${fill('number of people')}; categories of personal data as listed above; approximate number of records: ${f.itemCount === null ? fill('count') : f.itemCount}.\n\n`
        + `3. Likely consequences: ${fill('assessment')}\n\n4. Measures taken or proposed to address the breach and mitigate its effects: ${fill('measures')}\n\n`
        + `5. If this notification is made after the reference period, the reasons for the delay: ${fill('reasons, if any')}\n` },
    dataSubjects: { audience: 'affected people', subject: `Important information about your personal data`,
      body: common('NOTICE TO AFFECTED PEOPLE (draft)') + `From: ${who}\n\nWe are writing to tell you about an incident that involved your personal data.\n\nWhat happened: ${fill('plain-language description')}\n`
        + `What information was involved:\n${list(f.categories)}\n\nWhat we are doing: ${fill('measures')}\nWhat you can do: ${fill('advice, e.g. change a password, watch your accounts')}\nWho to contact: ${contact}\n` },
    controller: { audience: 'the controller (when the operator acts as processor)', subject: `Personal data breach - notification from ${who}`,
      body: common('NOTIFICATION FROM A PROCESSOR TO THE CONTROLLER (draft)') + `From: ${who}\nContact: ${contact}\n\nWe became aware of the following at ${clock.awareAt || fill('time')}:\n\n${factsBlock}\n\n`
        + `Likely consequences: ${fill('assessment')}\nMeasures taken: ${fill('measures')}\nWe will send further information as it becomes available: ${fill('next update time')}\n` },
  };
  return { facts: f, clock, drafts };
}

module.exports = { DISCLAIMER, exposureFacts, exposureClock, exposureDrafts, CATEGORY_WORDS };
