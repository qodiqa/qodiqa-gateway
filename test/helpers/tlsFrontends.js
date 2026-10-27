'use strict';

// step 5: loopback TLS front-ends so a REAL server.js can boot in the
// production profile (which requires PostgreSQL TLS and rediss://) on a
// machine whose PostgreSQL runs ssl=off and whose Redis is plaintext —
// without touching either service's configuration.
//
//   makeTestPki(dir)       throwaway CA + server certificate (SAN localhost,
//                          127.0.0.1), generated with openssl at test time;
//                          EC P-256, 1-day validity, written only to `dir`,
//                          never printed. Caller deletes `dir`.
//   startPgTlsFrontend()   speaks PostgreSQL's SSLRequest handshake ('S'),
//                          terminates TLS, forwards the decrypted stream to
//                          the real server. A client that does NOT request
//                          TLS is refused and counted — proof the gateway
//                          never fell back to plaintext.
//   startRedisTlsFrontend() plain TLS terminator in front of Redis.
//
// TLS therefore terminates AT THE FRONT-END: the gateway's sockets are
// encrypted and certificate-verified against the test CA, while the hop from
// the front-end to the service is plaintext loopback. BOOT_REPORT shows both
// views (client socket vs pg_stat_ssl), and any report built on this harness
// must say so.

const fs = require('fs');
const net = require('net');
const path = require('path');
const tls = require('tls');
const { spawnSync } = require('child_process');

const PG_SSL_REQUEST_CODE = 80877103;

function openssl(args, cwd) {
  const r = spawnSync('openssl', args, { cwd, encoding: 'utf8' });
  if (r.error) throw new Error(`openssl not runnable (${r.error.code}); the production-profile boot test needs it on PATH`);
  if (r.status !== 0) throw new Error(`openssl ${args[0]} failed: ${(r.stderr || '').trim().slice(0, 500)}`);
}

function makeTestPki(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes'];
  openssl(['req', '-x509', ...ec, '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=qodiqa-w2-test-ca'], dir);
  openssl(['req', ...ec, '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost'], dir);
  fs.writeFileSync(path.join(dir, 'ext.cnf'),
    'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n');
  openssl(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial',
    '-out', 'server.crt', '-days', '1', '-extfile', 'ext.cnf'], dir);
  return {
    dir,
    caPath: path.join(dir, 'ca.crt'),
    certPath: path.join(dir, 'server.crt'),
    keyPath: path.join(dir, 'server.key'),
  };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function pipeBoth(a, b, sockets) {
  sockets.add(a); sockets.add(b);
  const end = () => { a.destroy(); b.destroy(); sockets.delete(a); sockets.delete(b); };
  a.on('error', end); b.on('error', end); a.on('close', end); b.on('close', end);
  a.pipe(b); b.pipe(a);
}

function makeStop(server, sockets) {
  return () => new Promise((resolve) => {
    for (const s of sockets) s.destroy();
    sockets.clear();
    server.close(() => resolve());
  });
}

async function startPgTlsFrontend({ pki, targetHost = '127.0.0.1', targetPort = 5432 }) {
  const key = fs.readFileSync(pki.keyPath);
  const cert = fs.readFileSync(pki.certPath);
  const stats = { tlsSessions: 0, plaintextRefused: 0 };
  const sockets = new Set();
  const server = net.createServer((sock) => {
    sockets.add(sock);
    sock.on('error', () => sock.destroy());
    sock.once('data', (first) => {
      if (first.length === 8 && first.readInt32BE(4) === PG_SSL_REQUEST_CODE) {
        sock.write('S');
        const secure = new tls.TLSSocket(sock, { isServer: true, key, cert });
        secure.once('secure', () => { stats.tlsSessions++; });
        pipeBoth(secure, net.connect(targetPort, targetHost), sockets);
      } else {
        stats.plaintextRefused++;
        sock.destroy();
      }
    });
  });
  const port = await listen(server);
  return { port, stats, stop: makeStop(server, sockets) };
}

async function startRedisTlsFrontend({ pki, targetHost = '127.0.0.1', targetPort = 6379 }) {
  const stats = { tlsSessions: 0 };
  const sockets = new Set();
  const server = tls.createServer({ key: fs.readFileSync(pki.keyPath), cert: fs.readFileSync(pki.certPath) }, (secure) => {
    stats.tlsSessions++;
    pipeBoth(secure, net.connect(targetPort, targetHost), sockets);
  });
  server.on('tlsClientError', () => {});
  const port = await listen(server);
  return { port, stats, stop: makeStop(server, sockets) };
}

module.exports = { makeTestPki, startPgTlsFrontend, startRedisTlsFrontend };
