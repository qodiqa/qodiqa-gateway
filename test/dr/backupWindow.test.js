'use strict';

/**
 * Pilot backup window. scripts/dr/backupWindow.js + backup.js;
 * the scripts/pg-backup.sh twin is covered in test/pgBackupEncryption.test.js (EN-37/38).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { assertInBackupWindow, parseWindow, inWindow } = require('../../scripts/dr/backupWindow');

const at = (hh, mm) => new Date(Date.UTC(2026, 9, 11, hh, mm, 0));
const hhmm = (d) => d.toISOString().slice(11, 16);

describe('backup window', () => {
  test('BW-1 parse and match, including a window that wraps midnight; end exclusive', () => {
    const w = parseWindow('02:00-05:00');
    expect(inWindow(w, at(2, 0))).toBe(true);
    expect(inWindow(w, at(4, 59))).toBe(true);
    expect(inWindow(w, at(5, 0))).toBe(false);
    expect(inWindow(w, at(14, 0))).toBe(false);
    const wrap = parseWindow('23:00-04:00');
    expect(inWindow(wrap, at(23, 30))).toBe(true);
    expect(inWindow(wrap, at(3, 59))).toBe(true);
    expect(inWindow(wrap, at(4, 0))).toBe(false);
    expect(inWindow(wrap, at(12, 0))).toBe(false);
  });

  test('BW-2 malformed or empty-length windows are refused (fail closed), never ignored', () => {
    for (const bad of ['2-5', '02:00', '25:00-01:00', '02:00-02:00', '02:00-05:60', 'always']) {
      expect(() => assertInBackupWindow({ QODIQA_BACKUP_WINDOW_UTC: bad }, at(3, 0))).toThrow(expect.objectContaining({ code: 'BACKUP_WINDOW_INVALID' }));
    }
  });

  test('BW-3 unset = unrestricted; outside = refused; the explicit override runs one and is logged', () => {
    expect(assertInBackupWindow({}, at(14, 0))).toEqual({ restricted: false });
    expect(assertInBackupWindow({ QODIQA_BACKUP_WINDOW_UTC: '02:00-05:00' }, at(3, 0))).toMatchObject({ inWindow: true });
    expect(() => assertInBackupWindow({ QODIQA_BACKUP_WINDOW_UTC: '02:00-05:00' }, at(14, 0))).toThrow(expect.objectContaining({ code: 'BACKUP_OUTSIDE_WINDOW' }));
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(assertInBackupWindow({ QODIQA_BACKUP_WINDOW_UTC: '02:00-05:00', QODIQA_BACKUP_WINDOW_OVERRIDE: 'true' }, at(14, 0))).toMatchObject({ overridden: true });
      expect(String(spy.mock.calls[0][0])).toMatch(/BACKUP_WINDOW_OVERRIDDEN/);
      // any value but the literal "true" is not an override
      expect(() => assertInBackupWindow({ QODIQA_BACKUP_WINDOW_UTC: '02:00-05:00', QODIQA_BACKUP_WINDOW_OVERRIDE: '1' }, at(14, 0))).toThrow();
    } finally { spy.mockRestore(); }
  });

  test('BW-4 backup.js refuses outside the window before anything is written; runs inside it', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bw-'));
    fs.mkdirSync(path.join(dir, 'data'));
    fs.writeFileSync(path.join(dir, 'audit.log'), '');
    fs.writeFileSync(path.join(dir, 'data', 'keys.json'), '{"keys":{}}');
    fs.writeFileSync(path.join(dir, 'data', 'policy-store.json'), '{"policies":{}}');
    const now = new Date();
    const outside = `${hhmm(new Date(now.getTime() + 2 * 3600e3))}-${hhmm(new Date(now.getTime() + 3 * 3600e3))}`;
    const inside = `${hhmm(new Date(now.getTime() - 60e3))}-${hhmm(new Date(now.getTime() + 5 * 60e3))}`;
    const env = {
      QODIQA_AUDIT_LOG: path.join(dir, 'audit.log'), QODIQA_KEYS_PATH: path.join(dir, 'data', 'keys.json'),
      QODIQA_KEYS_ARCHIVE_PATH: path.join(dir, 'data', 'key-archive.json'), QODIQA_POLICY_STORE: path.join(dir, 'data', 'policy-store.json'),
      QODIQA_TRANSPARENCY_KEYS_PATH: path.join(dir, 'data', 'transparency-keys.json'), QODIQA_CHECKPOINT_KEYS_PATH: path.join(dir, 'data', 'checkpoint-keys.json'),
      QODIQA_MAC_KEYS_PATH: path.join(dir, 'data', 'mac-keys.json'), QODIQA_PRQ_JOURNAL_DIR: path.join(dir, 'data', 'prq-journal'),
      ORG_STORE_PATH: path.join(dir, 'data', 'organizations.json'), TENANT_STORE_PATH: path.join(dir, 'data', 'tenants.json'),
    };
    const saved = {};
    const set = (e) => { for (const [k, v] of Object.entries(e)) { if (!(k in saved)) saved[k] = process.env[k]; process.env[k] = v; } };
    const warn = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      jest.resetModules();
      const { runBackup } = require('../../scripts/dr/backup');
      set({ ...env, QODIQA_BACKUP_WINDOW_UTC: outside });
      await expect(runBackup({ outDir: path.join(dir, 'out-refused') })).rejects.toMatchObject({ code: 'BACKUP_OUTSIDE_WINDOW' });
      expect(fs.existsSync(path.join(dir, 'out-refused'))).toBe(false);
      set({ QODIQA_BACKUP_WINDOW_UTC: inside });
      const { manifest } = await runBackup({ outDir: path.join(dir, 'out-ok') });
      expect(manifest.components.find((c) => c.name === 'keyStore').present).toBe(true);
    } finally {
      warn.mockRestore();
      for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
  });
});
