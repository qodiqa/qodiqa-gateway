'use strict';

/**
 * 2026-10-06:
 * DM-01 writeMetricsFile carries forward the `preserve` series a failure run does not set — a failed DR
 *         backup no longer erases qodiqa_dr_backup_last_success_timestamp_seconds
 * DM-02 without `preserve` the file is still replaced as a whole (prior behaviour, every other caller)
 * DM-03 postAlert treats the shipped REPLACE_WITH_… placeholder / a non-http(s) value as unset (no request,
 *         ALERT_WEBHOOK_PLACEHOLDER on stderr) and still posts to a real https URL
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { writeMetricsFile } = require('../../scripts/dr/metricsFile');
const { postAlert, isUsableWebhook } = require('../../scripts/dr/alert');

const tmpFile = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-plm-')), 'metrics', 'qodiqa_dr_backup.prom');
const parse = (f) => Object.fromEntries(fs.readFileSync(f, 'utf8').trim().split('\n').map((l) => l.split(' ')).map(([k, v]) => [k, Number(v)]));

describe('DR metrics textfile', () => {
  test('DM-01 a failure run keeps the last success timestamp of the previous good run', () => {
    const f = tmpFile();
    writeMetricsFile(f, { qodiqa_dr_backup_success: 1, qodiqa_dr_backup_last_success_timestamp_seconds: 1700000000, qodiqa_dr_backup_duration_seconds: 3 });
    writeMetricsFile(f, { qodiqa_dr_backup_success: 0, qodiqa_dr_backup_last_failure_timestamp_seconds: 1700003600 },
      { preserve: ['qodiqa_dr_backup_last_success_timestamp_seconds'] });
    expect(parse(f)).toEqual({
      qodiqa_dr_backup_success: 0,
      qodiqa_dr_backup_last_failure_timestamp_seconds: 1700003600,
      qodiqa_dr_backup_last_success_timestamp_seconds: 1700000000,
    });
    // a value the new write sets wins over the preserved one
    writeMetricsFile(f, { qodiqa_dr_backup_success: 1, qodiqa_dr_backup_last_success_timestamp_seconds: 1700007200 },
      { preserve: ['qodiqa_dr_backup_last_success_timestamp_seconds'] });
    expect(parse(f).qodiqa_dr_backup_last_success_timestamp_seconds).toBe(1700007200);
    // no stray temp file is left next to the .prom (the textfile collector reads every *.prom)
    expect(fs.readdirSync(path.dirname(f))).toEqual(['qodiqa_dr_backup.prom']);
  });

  test('DM-02 without preserve the file is replaced as a whole; preserve on a missing file is a no-op', () => {
    const f = tmpFile();
    writeMetricsFile(f, { a_metric: 1, b_metric: 2 });
    writeMetricsFile(f, { a_metric: 3 });
    expect(parse(f)).toEqual({ a_metric: 3 });
    const g = tmpFile();
    writeMetricsFile(g, { c_metric: 4 }, { preserve: ['qodiqa_dr_backup_last_success_timestamp_seconds'] });
    expect(parse(g)).toEqual({ c_metric: 4 });
  });

  test('DM-02b the DR scripts pass preserve on their failure paths', () => {
    const backup = fs.readFileSync(path.join(__dirname, '..', '..', 'scripts', 'dr', 'backup.js'), 'utf8');
    expect(backup).toMatch(/qodiqa_dr_backup_success: 0,[\s\S]*?preserve: \['qodiqa_dr_backup_last_success_timestamp_seconds'\]/);
    const cycle = fs.readFileSync(path.join(__dirname, '..', '..', 'scripts', 'dr', 'cycle.js'), 'utf8');
    expect((cycle.match(/preserve: \[[^\]]*qodiqa_dr_restore_validation_last_success_timestamp_seconds/g) || []).length).toBe(2);
  });
});

describe('DR alert webhook', () => {
  const realFetch = global.fetch;
  let calls; let errSpy;
  beforeEach(() => {
    calls = [];
    global.fetch = async (url, opts) => { calls.push({ url, opts }); return { ok: true }; };
    errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => { global.fetch = realFetch; errSpy.mockRestore(); });

  test('DM-03 the shipped placeholder and non-URLs are treated as unset; a real https webhook is called', async () => {
    const shipped = Buffer.from('UkVQTEFDRV9XSVRIX1JFQUxfQUxFUlRfV0VCSE9PS19VUkxfQkVGT1JFX0RFUExPWV9PUFRJT05BTA==', 'base64').toString('utf8'); // base/secret.yaml
    for (const v of [shipped, 'hooks.slack.com/services/x', 'ftp://example.invalid/hook']) {
      expect(isUsableWebhook(v)).toBe(false);
      await postAlert(v, 'boom');
    }
    expect(calls).toEqual([]);
    expect(errSpy.mock.calls.map((c) => c[0]).every((l) => /ALERT_WEBHOOK_PLACEHOLDER/.test(l))).toBe(true);
    expect(errSpy).toHaveBeenCalledTimes(3);
    await postAlert(undefined, 'boom');            // unset: silent no-op, as before
    expect(errSpy).toHaveBeenCalledTimes(3);
    await postAlert('https://alerts.invalid/hook', 'boom');
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://alerts.invalid/hook');
    expect(JSON.parse(calls[0].opts.body).text).toMatch(/boom/);
  });
});
