'use strict';

// Integration test for the out-of-band RBAC bootstrap script. Runs it as a
// real child process (matching how an operator invokes it) against an
// isolated, disposable store — never the real data/rbac-users.json.

const { execFileSync } = require('child_process');
const fs   = require('fs');
const os   = require('os');
const path = require('path');

const SCRIPT_PATH = path.join(__dirname, 'rbac-bootstrap-key.js');

function runScript(storePath, args = []) {
  const raw = execFileSync('node', [SCRIPT_PATH, ...args], {
    env: { ...process.env, QODIQA_RBAC_STORE_PATH: storePath },
    encoding: 'utf8',
  });
  // Structured log lines from services/logger are single-line JSON. The
  // script's own final result is printed as pretty-printed (multi-line)
  // JSON via `JSON.stringify(x, null, 2)`, which always starts with a line
  // containing only "{". Locate that boundary rather than assuming any
  // fixed number of preceding log lines.
  const lines     = raw.split('\n');
  const startIdx  = lines.map(l => l.trim()).lastIndexOf('{');
  const resultRaw = lines.slice(startIdx).join('\n');
  return JSON.parse(resultRaw);
}

describe('scripts/rbac-bootstrap-key.js', () => {
  let tmpDir, storePath;

  beforeEach(() => {
    tmpDir    = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-rbac-bootstrap-'));
    storePath = path.join(tmpDir, 'rbac-users.json');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('provisions a fresh admin with role=admin and a real API key on first run', () => {
    const result = runScript(storePath);
    expect(result.status).toBe('PROVISIONED');
    expect(result.role).toBe('admin');
    expect(result.apiKey).toMatch(/^ok_[0-9a-f]{64}$/);
  });

  it('persists the created user to the store file (real, auditable record — not synthetic)', () => {
    runScript(storePath);
    const stored = JSON.parse(fs.readFileSync(storePath, 'utf8'));
    const users  = Object.values(stored.users);
    expect(users).toHaveLength(1);
    expect(users[0].role).toBe('admin');
    expect(users[0].createdBy).toBe('BOOTSTRAP');
    // Plaintext key is never persisted — only its SHA-256 hash.
    expect(users[0].apiKeyHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('does not re-issue a key on a second run without --rotate (idempotent)', () => {
    const first  = runScript(storePath);
    const second = runScript(storePath);
    expect(second.status).toBe('ALREADY_PROVISIONED');
    expect(second.apiKey).toBeUndefined();
    expect(second.issuedAt).toBe(first.issuedAt);
  });

  it('rotates and invalidates the previous key when --rotate is passed', () => {
    const first  = runScript(storePath);
    const second = runScript(storePath, ['--rotate']);
    expect(second.status).toBe('ROTATED');
    expect(second.apiKey).not.toBe(first.apiKey);

    const stored = JSON.parse(fs.readFileSync(storePath, 'utf8'));
    const user   = Object.values(stored.users)[0];
    // The stored hash must match the NEW key, not the old one.
    const crypto = require('crypto');
    const newHash = crypto.createHash('sha256').update(second.apiKey, 'utf8').digest('hex');
    const oldHash = crypto.createHash('sha256').update(first.apiKey, 'utf8').digest('hex');
    expect(user.apiKeyHash).toBe(newHash);
    expect(user.apiKeyHash).not.toBe(oldHash);
  });

  // the out-of-band path for a peer admin's key.
  it('--user <username> issues the key of an existing operator out of band; an unknown user fails', () => {
    runScript(storePath);
    const stored = JSON.parse(fs.readFileSync(storePath, 'utf8'));
    const now = new Date().toISOString();
    stored.users['peer-admin-id'] = { id: 'peer-admin-id', username: 'peer-admin', role: 'admin', enabled: true, createdAt: now, createdBy: 'test', updatedAt: now, updatedBy: 'test' };
    fs.writeFileSync(storePath, JSON.stringify(stored, null, 2));
    const r = runScript(storePath, ['--user', 'peer-admin']);
    expect([r.status, r.username, r.role]).toEqual(['PROVISIONED', 'peer-admin', 'admin']);
    expect(r.apiKey).toMatch(/^ok_[0-9a-f]{64}$/);
    expect(() => runScript(storePath, ['--user', 'nobody-here'])).toThrow();
  });
});
