'use strict';

/**
 * exposure incidents: detection -> alert (the "ticket") -> notification drafts.
 *   EX-01  detection: only sensitive data that REACHED the caller raises DATA_EXPOSURE; what was redacted, masked or blocked, and plain personal data, does not
 *   EX-02  the evidence names rules, counts and hashes - never a value
 *   EX-03  drafts: facts from the alert, placeholders for what the system cannot know, the disclaimer first, the reference clock labelled as reference
 *   EX-04  the route returns the drafts for an exposure alert and refuses other alerts
 *   EX-05  end to end through the DLP stage: a DETECT rule on an answer produces an event the detector turns into an alert
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const express = require('express');
const supertest = require('supertest');
const detector = require('../../../alerting/detection/OperationalDetector');
const { ALERT_TYPE, SEVERITY } = require('../../../alerting/constants');
const notif = require('../exposureNotifications');

const ev = (over = {}) => ({ eventType: 'DLP_TRANSFORM', direction: 'output', action: 'DETECT', rules: ['CARD', 'EMAIL'], findings: 3, policyId: 'DLP_OUT', requestId: 'req-1', tenantId: 't1',
  inputHashBefore: 'a'.repeat(64), inputHashAfter: 'a'.repeat(64), ...over });

describe('EX-01 detection', () => {
  test('sensitive data delivered unchanged in an answer or a tool result is a DATA_EXPOSURE alert', () => {
    for (const direction of ['output', 'tool_output']) {
      const r = detector.analyze(ev({ direction }));
      expect(r.triggered).toBe(true); expect(r.alert).toMatchObject({ type: ALERT_TYPE.GOVERNANCE, subtype: 'DATA_EXPOSURE', severity: SEVERITY.HIGH, tenantId: 't1', requestId: 'req-1' });
    }
  });
  test('credentials and key material count; an exfiltration signal in DETECT mode is CRITICAL', () => {
    expect(detector.analyze(ev({ rules: ['KEY_GITHUB'] })).triggered).toBe(true);
    expect(detector.analyze(ev({ rules: ['PEM_BLOCK'] })).triggered).toBe(true);
    const x = detector.analyze(ev({ rules: ['EXFIL:URL_EXFIL'] }));
    expect(x.alert).toMatchObject({ subtype: 'DATA_EXPOSURE', severity: SEVERITY.CRITICAL });
  });
  test('prevented or harmless cases raise nothing: REDACT / MASK / BLOCK, input direction, e-mail or phone alone, other events', () => {
    for (const action of ['REDACT', 'MASK', 'BLOCK']) expect(detector.analyze(ev({ action })).triggered).toBe(false);
    expect(detector.analyze(ev({ direction: 'input' })).triggered).toBe(false);
    expect(detector.analyze(ev({ direction: 'tool_input' })).triggered).toBe(false);
    expect(detector.analyze(ev({ rules: ['EMAIL', 'PHONE'] })).triggered).toBe(false);
    expect(detector.analyze(ev({ eventType: 'SOMETHING_ELSE' })).triggered).toBe(false);
    expect(detector.analyze(ev({ rules: ['CLASS:RESTRICTED'] })).triggered).toBe(false);
  });
});

describe('EX-02 evidence', () => {
  test('rule ids, counts, hashes and ids - and nothing that looks like a value', () => {
    const a = detector.analyze({ ...ev(), leakedValue: 'jane.roe@example.org' }).alert;
    expect(a.evidence).toMatchObject({ policyId: 'DLP_OUT', direction: 'output', action: 'DETECT', rules: ['CARD', 'EMAIL'], findings: 3, requestId: 'req-1', tenantId: 't1' });
    expect(JSON.stringify(a)).not.toContain('jane.roe');
  });
});

describe('EX-03 drafts', () => {
  const alert = () => ({ id: '11111111-1111-4111-8111-111111111111', subtype: 'DATA_EXPOSURE', severity: 'HIGH', tenantId: 't1', requestId: 'req-1', detectedAt: new Date('2026-10-22T10:00:00Z'),
    evidence: { direction: 'output', action: 'DETECT', rules: ['CARD', 'KEY_GITHUB', 'EXFIL:URL_EXFIL'], findings: 3, policyId: 'DLP_OUT', inputHashBefore: 'a'.repeat(64), inputHashAfter: 'b'.repeat(64) } });
  test('facts: categories in words, where, delivered unchanged', () => {
    const f = notif.exposureFacts(alert());
    expect(f).toMatchObject({ where: 'a model answer', deliveredUnchanged: true, itemCount: 3, requestId: 'req-1' });
    expect(f.categories).toEqual(['payment card numbers', 'API keys or access tokens', 'a possible exfiltration pattern']);
    expect(() => notif.exposureFacts({ subtype: 'OTHER' })).toThrow(/not a DATA_EXPOSURE/);
  });
  test('the clock is a labelled reference, computed from the detection time', () => {
    const c = notif.exposureClock(alert());
    expect(c).toMatchObject({ awareAt: '2026-10-22T10:00:00.000Z', referenceDeadline: '2026-10-25T10:00:00.000Z', referenceHours: 72 });
    expect(c.note).toMatch(/Reference only/); expect(c.note).toMatch(/counsel/);
    expect(notif.exposureClock({ detectedAt: 'garbage' }).referenceDeadline).toBeNull();
  });
  test('four drafts, each starts with the disclaimer, keeps unknowns as placeholders, never states an obligation, and carries no value', () => {
    const d = notif.exposureDrafts(alert(), { controller: { name: 'Example Ltd' }, dpo: { contact: 'dpo@example.test' } });
    expect(Object.keys(d.drafts)).toEqual(['internal', 'authority', 'dataSubjects', 'controller']);
    for (const x of Object.values(d.drafts)) {
      expect(x.body.startsWith(notif.DISCLAIMER)).toBe(true); expect(x.body).toMatch(/\[\[TO FILL: /); expect(x.subject).toBeTruthy();
      expect(x.body).not.toMatch(/you must notify|is required to notify|we comply|in compliance with/i);
    }
    expect(d.drafts.authority.body).toContain('Example Ltd'); expect(d.drafts.authority.body).toContain('dpo@example.test'); expect(d.drafts.authority.body).toContain('payment card numbers');
    expect(d.drafts.internal.body).toContain('b'.repeat(64));
    const bare = notif.exposureDrafts(alert());
    expect(bare.drafts.authority.body).toContain('[[TO FILL: organisation name]]');
  });
});

describe('EX-04 the route', () => {
  const { createAlertRouter } = require('../../../alerting/api/alertRoutes');
  const store = require('../../../alerting/storage/AlertStore');
  const app = () => { const a = express(); a.use('/alerts', createAlertRouter()); return a; };
  test('drafts for an exposure alert; 409 for another kind; 404 and 400', async () => {
    const exposure = { id: '22222222-2222-4222-8222-222222222222', subtype: 'DATA_EXPOSURE', severity: 'HIGH', tenantId: 't1', detectedAt: new Date(), evidence: { direction: 'tool_output', action: 'DETECT', rules: ['IBAN'], findings: 1 } };
    const other = { ...exposure, id: '33333333-3333-4333-8333-333333333333', subtype: 'RECONCILIATION_DIVERGENCE' };
    const spy = jest.spyOn(store, 'getAlert').mockImplementation(async (id) => (id === exposure.id ? exposure : id === other.id ? other : null));
    const ok = await supertest(app()).get(`/alerts/${exposure.id}/exposure-notification?organisation=Example%20Ltd`);
    expect(ok.status).toBe(200); expect(ok.body.facts.where).toBe('the result of a tool call'); expect(ok.body.drafts.authority.body).toContain('Example Ltd');
    expect((await supertest(app()).get(`/alerts/${other.id}/exposure-notification`)).body.error.code).toBe('NOT_AN_EXPOSURE_ALERT');
    expect((await supertest(app()).get('/alerts/44444444-4444-4444-8444-444444444444/exposure-notification')).status).toBe(404);
    expect((await supertest(app()).get('/alerts/not-a-uuid/exposure-notification')).status).toBe(400);
    spy.mockRestore();
  });
});

describe('EX-05 through the DLP stage', () => {
  test('a DETECT rule on an answer: the DLP_TRANSFORM event the stage emits is what the detector turns into an alert', async () => {
    jest.resetModules();
    const emitted = [];
    jest.doMock('../../../../services/logger', () => ({ emit: (...a) => emitted.push(a) }));
    const svc = require('../../dlp/dlpService'); const rule = require('../../../../services/policy/evaluators/dlp'); const { luhn } = require('../../../../enterprise/dlp/detectors');
    const base = '411111111111111'; let card = ''; for (let c = 0; c < 10; c++) if (luhn(base + c)) card = base + c;
    const cfg = { dlpFormat: 1, direction: 'output', action: 'DETECT', rules: ['FINANCIAL'] }; rule.validate(cfg);
    const r = svc.applyToText(`your card is ${card}`, [{ id: 'DLP_OUT', type: 'DLP', priority: 1, enabled: true, config: rule.preprocess(cfg) }]);
    await svc.recordEvents(r.events, { requestId: 'req-9', tenantId: 't9' });
    const e = emitted.find((x) => x[1] === 'DLP_TRANSFORM');
    const alert = require('../../../alerting/detection/OperationalDetector').analyze({ eventType: e[1], ...e[2] });
    expect(alert.triggered).toBe(true); expect(alert.alert).toMatchObject({ subtype: 'DATA_EXPOSURE', requestId: 'req-9', tenantId: 't9' });
    expect(JSON.stringify(alert)).not.toContain(card);
    expect(r.text).toContain(card);                                                       // DETECT delivers it unchanged: that is the exposure
  });
});
