'use strict';

/**
 * SMTP STARTTLS security regression coverage.
 *
 * These tests run a real loopback TCP server that speaks just enough SMTP to
 * drive EmailChannel's raw-socket client through every branch of the
 * STARTTLS state machine, including a genuine server-side TLS upgrade
 * (self-signed test certificate below) — not a mocked `tls` module. This is
 * the only way to actually prove the property cares about: that
 * AUTH LOGIN bytes never cross the wire before the socket is TLS-wrapped.
 *
 * Each connection records every command line it receives, tagged by
 * whether it arrived before ('plaintext') or after ('secure') the STARTTLS
 * upgrade, so tests can assert AUTH LOGIN / credentials only ever appear in
 * the 'secure' bucket.
 */

const net = require('net');
const tls = require('tls');

const crypto = require('crypto');

// the loopback test server's TLS identity is GENERATED AT TEST TIME — no private key (nor
// certificate) is committed to the repository. node:crypto has no X.509 builder and no certificate-generator
// dependency exists in package.json, so a minimal self-signed X.509 v3 certificate (CN=localhost,
// subjectAltName=DNS:localhost, ECDSA P-256 / SHA-256, valid now-1h..now+1d) is DER-encoded here directly from
// RFC 5280 and signed with crypto.sign(). Offline, deterministic in shape, fresh key per test run.
function _der(tag, content) {
  const len = content.length;
  let lenBytes;
  if (len < 0x80) lenBytes = Buffer.from([len]);
  else if (len < 0x100) lenBytes = Buffer.from([0x81, len]);
  else lenBytes = Buffer.from([0x82, len >> 8, len & 0xff]);
  return Buffer.concat([Buffer.from([tag]), lenBytes, content]);
}
const _seq = (...parts) => _der(0x30, Buffer.concat(parts));
function _oid(dotted) {
  const arcs = dotted.split('.').map(Number);
  const out = [40 * arcs[0] + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const stack = [arc & 0x7f];
    for (let v = arc >> 7; v > 0; v >>= 7) stack.unshift((v & 0x7f) | 0x80);
    out.push(...stack);
  }
  return _der(0x06, Buffer.from(out));
}
function _utcTime(d) {
  const p = (n) => String(n).padStart(2, '0');
  return _der(0x17, Buffer.from(`${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}`
    + `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`, 'ascii'));
}
function generateSelfSignedLocalhostCert() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const sigAlg = _seq(_oid('1.2.840.10045.4.3.2')); // ecdsa-with-SHA256
  const name = _seq(_der(0x31, _seq(_oid('2.5.4.3'), _der(0x0c, Buffer.from('localhost', 'utf8')))));
  const now = Date.now();
  const san = _seq(_oid('2.5.29.17'), _der(0x04, _seq(_der(0x82, Buffer.from('localhost', 'ascii')))));
  const tbs = _seq(
    _der(0xa0, _der(0x02, Buffer.from([0x02]))),                       // version v3
    _der(0x02, Buffer.concat([Buffer.from([0x01]), crypto.randomBytes(8)])), // positive serial
    sigAlg,
    name,                                                              // issuer
    _seq(_utcTime(new Date(now - 3600e3)), _utcTime(new Date(now + 86400e3))),
    name,                                                              // subject
    publicKey.export({ type: 'spki', format: 'der' }),
    _der(0xa3, _seq(san)),                                             // extensions
  );
  const signature = crypto.sign('sha256', tbs, privateKey);
  const certDer = _seq(tbs, sigAlg, _der(0x03, Buffer.concat([Buffer.from([0x00]), signature])));
  const b64 = certDer.toString('base64').match(/.{1,64}/g).join('\n');
  return {
    cert: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`,
    key:  privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}
const { cert: TEST_CERT, key: TEST_KEY } = generateSelfSignedLocalhostCert();

const ALERT_ENV_KEYS = [
  'ALERT_EMAIL_PROVIDER', 'ALERT_EMAIL_FROM', 'ALERT_EMAIL_TO',
  'ALERT_EMAIL_SMTP_HOST', 'ALERT_EMAIL_SMTP_PORT',
  'ALERT_EMAIL_SMTP_USER', 'ALERT_EMAIL_SMTP_PASS',
  'ALERT_EMAIL_TRUSTED_RELAY_ONLY', 'ALERT_EMAIL_SMTP_TLS_REJECT_UNAUTHORIZED',
];

function withEnv(overrides, fn) {
  const saved = {};
  for (const key of ALERT_ENV_KEYS) saved[key] = process.env[key];
  for (const key of ALERT_ENV_KEYS) delete process.env[key];
  Object.assign(process.env, overrides);

  jest.resetModules();
  try {
    const { EmailChannel } = require('../EmailChannel');
    return fn(EmailChannel);
  } finally {
    for (const key of ALERT_ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
    jest.resetModules();
  }
}

/**
 * A minimal SMTP server that supports EHLO / STARTTLS / AUTH LOGIN / MAIL /
 * RCPT / DATA / QUIT, enough to drive EmailChannel's client through every
 * branch. Every command line is recorded, tagged 'plaintext' or 'secure'
 * depending on which side of the STARTTLS upgrade it arrived on.
 */
class FakeSmtpServer {
  constructor({ advertiseStartTls = true, validUser = 'alerts', validPass = 'hunter2' } = {}) {
    this.advertiseStartTls = advertiseStartTls;
    this.validUser = validUser;
    this.validPass = validPass;
    this.lines = []; // { phase: 'plaintext'|'secure', line: string }
    this.usedStartTls = false;
    this.server = net.createServer((socket) => this._handleConnection(socket));
  }

  listen() {
    return new Promise((resolve) => {
      this.server.listen(0, '127.0.0.1', () => resolve(this.server.address().port));
    });
  }

  close() {
    return new Promise((resolve) => this.server.close(resolve));
  }

  _handleConnection(rawSocket) {
    let active = rawSocket;
    let phase = 'plaintext';
    let authStage = null; // null | 'user' | 'pass'
    let pendingUser = null;
    let collectingData = false;
    let buf = '';

    const write = (s) => active.write(s + '\r\n');

    const handleLine = (line) => {
      this.lines.push({ phase, line });
      const upper = line.toUpperCase();

      if (upper.startsWith('EHLO')) {
        const caps = ['fake.smtp.test greets you'];
        if (this.advertiseStartTls && phase === 'plaintext') caps.push('STARTTLS');
        caps.push('AUTH LOGIN');
        write(caps.map((c, i) => `250${i === caps.length - 1 ? ' ' : '-'}${c}`).join('\r\n'));
        return;
      }
      if (upper === 'STARTTLS' && phase === 'plaintext') {
        write('220 2.0.0 Ready to start TLS');
        rawSocket.removeAllListeners('data');
        const secureSocket = new tls.TLSSocket(rawSocket, {
          isServer: true,
          cert: TEST_CERT,
          key: TEST_KEY,
        });
        this.usedStartTls = true;
        active = secureSocket;
        phase = 'secure';
        bindDataHandler(secureSocket);
        return;
      }
      if (upper === 'AUTH LOGIN') {
        authStage = 'user';
        write('334 ' + Buffer.from('Username:').toString('base64'));
        return;
      }
      if (authStage === 'user') {
        pendingUser = Buffer.from(line, 'base64').toString('utf8');
        authStage = 'pass';
        write('334 ' + Buffer.from('Password:').toString('base64'));
        return;
      }
      if (authStage === 'pass') {
        const p = Buffer.from(line, 'base64').toString('utf8');
        authStage = null;
        if (pendingUser === this.validUser && p === this.validPass) write('235 2.7.0 Authentication successful');
        else write('535 5.7.8 Authentication failed');
        return;
      }
      if (upper.startsWith('MAIL FROM')) { write('250 2.1.0 OK'); return; }
      if (upper.startsWith('RCPT TO'))   { write('250 2.1.5 OK'); return; }
      if (upper === 'DATA')              { write('354 Start mail input'); collectingData = true; return; }
      if (upper === 'QUIT')              { write('221 2.0.0 Bye'); active.end(); return; }
    };

    const bindDataHandler = (sock) => {
      sock.on('data', (chunk) => {
        buf += chunk.toString();
        if (collectingData) {
          const idx = buf.indexOf('\r\n.\r\n');
          if (idx === -1) return;
          buf = buf.slice(idx + 5);
          collectingData = false;
          write('250 2.0.0 OK: queued');
          return;
        }
        const parts = buf.split('\r\n');
        buf = parts.pop();
        for (const line of parts) handleLine(line);
      });
      sock.on('error', () => { /* loopback test socket — ignore reset noise */ });
    };

    write('220 fake.smtp.test ESMTP ready');
    bindDataHandler(rawSocket);
  }
}

describe('EmailChannel — SMTP STARTTLS security', () => {
  const ALERT = {
    id: 'alert-1', severity: 'HIGH', riskScore: 90, type: 'TEST', subtype: 'TEST',
    title: 'Test alert', description: 'desc', detectedAt: new Date().toISOString(),
  };

  test('STARTTLS is negotiated and AUTH LOGIN + credentials are only ever sent over the secure channel', async () => {
    const fake = new FakeSmtpServer({ advertiseStartTls: true, validUser: 'alerts', validPass: 'hunter2' });
    const port = await fake.listen();

    try {
      await withEnv({
        ALERT_EMAIL_PROVIDER: 'smtp',
        ALERT_EMAIL_SMTP_HOST: '127.0.0.1',
        ALERT_EMAIL_SMTP_PORT: String(port),
        ALERT_EMAIL_SMTP_USER: 'alerts',
        ALERT_EMAIL_SMTP_PASS: 'hunter2',
        ALERT_EMAIL_SMTP_TLS_REJECT_UNAUTHORIZED: 'false', // self-signed test cert
      }, async (EmailChannel) => {
        const channel = new EmailChannel();
        const result = await channel._send(ALERT, 'soc@example.com');
        expect(result.ok).toBe(true);
      });

      expect(fake.usedStartTls).toBe(true);

      const plaintextCommands = fake.lines.filter(l => l.phase === 'plaintext').map(l => l.line.toUpperCase());
      const secureCommands    = fake.lines.filter(l => l.phase === 'secure').map(l => l.line.toUpperCase());

      // AUTH LOGIN and both base64 credential lines must never appear before STARTTLS.
      expect(plaintextCommands).not.toContain('AUTH LOGIN');
      expect(plaintextCommands).not.toContain(Buffer.from('alerts').toString('base64').toUpperCase());
      expect(plaintextCommands).not.toContain(Buffer.from('hunter2').toString('base64').toUpperCase());

      expect(secureCommands).toContain('AUTH LOGIN');
      expect(secureCommands).toContain(Buffer.from('alerts').toString('base64').toUpperCase());
      expect(secureCommands).toContain(Buffer.from('hunter2').toString('base64').toUpperCase());

      // STARTTLS itself is the last thing sent in the plaintext phase.
      expect(plaintextCommands[plaintextCommands.length - 1]).toBe('STARTTLS');
    } finally {
      await fake.close();
    }
  });

  test('relay without STARTTLS + configured credentials + no trusted-relay opt-in: refuses and never sends AUTH', async () => {
    const fake = new FakeSmtpServer({ advertiseStartTls: false });
    const port = await fake.listen();

    try {
      await withEnv({
        ALERT_EMAIL_PROVIDER: 'smtp',
        ALERT_EMAIL_SMTP_HOST: '127.0.0.1',
        ALERT_EMAIL_SMTP_PORT: String(port),
        ALERT_EMAIL_SMTP_USER: 'alerts',
        ALERT_EMAIL_SMTP_PASS: 'hunter2',
        // ALERT_EMAIL_TRUSTED_RELAY_ONLY intentionally unset
      }, async (EmailChannel) => {
        const channel = new EmailChannel();
        const result = await channel._send(ALERT, 'soc@example.com');
        expect(result.ok).toBe(false);
        expect(result.message).toMatch(/STARTTLS/i);
        expect(result.message).toMatch(/ALERT_EMAIL_TRUSTED_RELAY_ONLY/);
      });

      expect(fake.usedStartTls).toBe(false);
      const commands = fake.lines.map(l => l.line.toUpperCase());
      expect(commands).not.toContain('AUTH LOGIN');
    } finally {
      await fake.close();
    }
  });

  test('relay without STARTTLS + ALERT_EMAIL_TRUSTED_RELAY_ONLY=true: explicit opt-in allows plaintext AUTH', async () => {
    const fake = new FakeSmtpServer({ advertiseStartTls: false, validUser: 'alerts', validPass: 'hunter2' });
    const port = await fake.listen();

    try {
      await withEnv({
        ALERT_EMAIL_PROVIDER: 'smtp',
        ALERT_EMAIL_SMTP_HOST: '127.0.0.1',
        ALERT_EMAIL_SMTP_PORT: String(port),
        ALERT_EMAIL_SMTP_USER: 'alerts',
        ALERT_EMAIL_SMTP_PASS: 'hunter2',
        ALERT_EMAIL_TRUSTED_RELAY_ONLY: 'true',
      }, async (EmailChannel) => {
        const channel = new EmailChannel();
        const result = await channel._send(ALERT, 'soc@example.com');
        expect(result.ok).toBe(true);
      });

      expect(fake.usedStartTls).toBe(false);
      const commands = fake.lines.map(l => l.line.toUpperCase());
      expect(commands).toContain('AUTH LOGIN');
    } finally {
      await fake.close();
    }
  });

  test('relay without STARTTLS and no credentials configured: sends without AUTH (no regression for anonymous relays)', async () => {
    const fake = new FakeSmtpServer({ advertiseStartTls: false });
    const port = await fake.listen();

    try {
      await withEnv({
        ALERT_EMAIL_PROVIDER: 'smtp',
        ALERT_EMAIL_SMTP_HOST: '127.0.0.1',
        ALERT_EMAIL_SMTP_PORT: String(port),
        // no ALERT_EMAIL_SMTP_USER / _PASS
      }, async (EmailChannel) => {
        const channel = new EmailChannel();
        const result = await channel._send(ALERT, 'soc@example.com');
        expect(result.ok).toBe(true);
      });

      const commands = fake.lines.map(l => l.line.toUpperCase());
      expect(commands).not.toContain('AUTH LOGIN');
    } finally {
      await fake.close();
    }
  });

  // a comma-separated recipient list used to be delivered to the FIRST address only.
  test('a comma-separated recipient list gets one RCPT TO per address (was: only the first)', async () => {
    const fake = new FakeSmtpServer({ advertiseStartTls: false });
    const port = await fake.listen();

    try {
      await withEnv({
        ALERT_EMAIL_PROVIDER: 'smtp',
        ALERT_EMAIL_SMTP_HOST: '127.0.0.1',
        ALERT_EMAIL_SMTP_PORT: String(port),
      }, async (EmailChannel) => {
        const channel = new EmailChannel();
        const result = await channel._send(ALERT, 'soc@example.com, oncall@example.com ,sec@example.com');
        expect(result.ok).toBe(true);
      });

      const rcpts = fake.lines.map(l => l.line).filter(l => l.toUpperCase().startsWith('RCPT TO'));
      expect(rcpts).toEqual(['RCPT TO:<soc@example.com>', 'RCPT TO:<oncall@example.com>', 'RCPT TO:<sec@example.com>']);
      const commands = fake.lines.map(l => l.line.toUpperCase());
      expect(commands.indexOf('DATA')).toBeGreaterThan(commands.lastIndexOf(commands.filter(c => c.startsWith('RCPT TO')).pop()));
    } finally {
      await fake.close();
    }
  });

  test('self-signed relay certificate is rejected by default (secure default), accepted only with explicit opt-out', async () => {
    const fake = new FakeSmtpServer({ advertiseStartTls: true, validUser: 'alerts', validPass: 'hunter2' });
    const port = await fake.listen();

    try {
      await withEnv({
        ALERT_EMAIL_PROVIDER: 'smtp',
        ALERT_EMAIL_SMTP_HOST: '127.0.0.1',
        ALERT_EMAIL_SMTP_PORT: String(port),
        ALERT_EMAIL_SMTP_USER: 'alerts',
        ALERT_EMAIL_SMTP_PASS: 'hunter2',
        // ALERT_EMAIL_SMTP_TLS_REJECT_UNAUTHORIZED intentionally left at its
        // secure default (true) against our self-signed test certificate.
      }, async (EmailChannel) => {
        const channel = new EmailChannel();
        const result = await channel._send(ALERT, 'soc@example.com');
        expect(result.ok).toBe(false);
        expect(result.message).toMatch(/certificate|self.signed|unable to verify/i);
      });
    } finally {
      await fake.close();
    }
  }, 20000);

  test('opportunistic STARTTLS on an anonymous (no-auth) relay still upgrades the transport', async () => {
    const fake = new FakeSmtpServer({ advertiseStartTls: true });
    const port = await fake.listen();

    try {
      await withEnv({
        ALERT_EMAIL_PROVIDER: 'smtp',
        ALERT_EMAIL_SMTP_HOST: '127.0.0.1',
        ALERT_EMAIL_SMTP_PORT: String(port),
        ALERT_EMAIL_SMTP_TLS_REJECT_UNAUTHORIZED: 'false',
      }, async (EmailChannel) => {
        const channel = new EmailChannel();
        const result = await channel._send(ALERT, 'soc@example.com');
        expect(result.ok).toBe(true);
      });

      expect(fake.usedStartTls).toBe(true);
    } finally {
      await fake.close();
    }
  });
});
