'use strict';

/**
 * async/background tenant propagation (task brief §11).
 *
 * EscalationService._escalate() runs from a setInterval-based background
 * scan (start()/_scan(), 30s resolution) — there is no HTTP request in
 * flight when it fires, so tenant identity cannot be assumed from request
 * context. It must be re-derived explicitly: _escalate() re-fetches the
 * alert via alertStore.getAlert(alertId) and threads alert.tenantId into
 * alertStore.recordEscalation() (the fix — see AlertStore.js and
 * EscalationService.js's own comments).
 *
 * This test drives the REAL background path (schedule() + start() + fake
 * timers advancing past the scan interval) rather than calling the
 * unexported _escalate() directly, so it proves the actual wiring, not a
 * hand-picked shortcut.
 */

jest.mock('../../storage/AlertStore');

const { ALERT_TYPE, REPLAY_SUBTYPE, SEVERITY, ALERT_STATUS } = require('../../constants');
const alertStore = require('../../storage/AlertStore');
const escalationService = require('../EscalationService');

function makeAlert(overrides = {}) {
  return {
    id:               'alert-tenant-prop-1',
    type:             ALERT_TYPE.REPLAY_ATTACK,
    subtype:          REPLAY_SUBTYPE.NONCE_REUSE,
    severity:         SEVERITY.HIGH,
    status:           ALERT_STATUS.OPEN,
    riskScore:        70,
    confidence:       95,
    title:            'Test Alert',
    tenantId:         'rem061-async-tenant',
    escalationLevel:  0,
    detectedAt:       new Date(),
    ...overrides,
  };
}

describe('EscalationService background scan propagates tenantId explicitly', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    escalationService.stop();
    alertStore.getAlert.mockReset();
    alertStore.recordEscalation.mockReset().mockResolvedValue(undefined);
  });

  afterEach(() => {
    escalationService.stop();
    jest.useRealTimers();
  });

  test('recordEscalation is called with the alert\'s own tenantId, not undefined/omitted', async () => {
    const alert = makeAlert({
      nextEscalationAt: new Date(Date.now() + 1000), // due almost immediately
    });
    alertStore.getAlert.mockResolvedValue(alert);

    escalationService.schedule(alert);
    escalationService.start();

    // Advance past both the escalation deadline and the 30s scan interval.
    await jest.advanceTimersByTimeAsync(31_000);

    expect(alertStore.getAlert).toHaveBeenCalledWith(alert.id);
    expect(alertStore.recordEscalation).toHaveBeenCalledTimes(1);
    const [calledAlertId, calledMeta] = alertStore.recordEscalation.mock.calls[0];
    expect(calledAlertId).toBe(alert.id);
    expect(calledMeta.tenantId).toBe('rem061-async-tenant');
  });

  test('platform-level alert (tenantId null) still escalates, with tenantId explicitly null (never a guessed default)', async () => {
    const alert = makeAlert({
      tenantId: null,
      nextEscalationAt: new Date(Date.now() + 1000),
    });
    alertStore.getAlert.mockResolvedValue(alert);

    escalationService.schedule(alert);
    escalationService.start();
    await jest.advanceTimersByTimeAsync(31_000);

    expect(alertStore.recordEscalation).toHaveBeenCalledTimes(1);
    const [, calledMeta] = alertStore.recordEscalation.mock.calls[0];
    expect(calledMeta.tenantId).toBeNull();
  });
});
