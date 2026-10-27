'use strict';

/**
 * a deterministic TCP fault-injection proxy for failure/recovery tests (test/failure/**).
 *
 * Sits between a client under test and a REAL dependency (the disposable PostgreSQL / Redis containers); the
 * dependency itself is never stopped or reconfigured. Modes, switchable at any time:
 *
 *   pass       relay bytes both ways (default)
 *   refuse()   destroy every open pipe and refuse new connections (dependency DOWN: ECONNRESET / ECONNREFUSED-like)
 *   blackhole() keep every socket open but forward nothing, in either direction, for existing AND new pipes
 *               (a SILENT partition: the client's TCP stack sees an accepted connection and ACKed bytes, never a reply)
 *   heal({ deliverHeld })  back to pass; held bytes are delivered late (deliverHeld=true, a partition that heals with
 *               the TCP connections intact) or the stalled pipes are destroyed (deliverHeld=false, the connections did
 *               not survive)
 *
 * close() destroys every pipe and closes the listener, so the test leaves no handle behind.
 */

const net = require('net');

function createFaultProxy({ targetHost, targetPort }) {
  const pipes = new Set();
  let mode = 'pass';
  let accepted = 0;
  let refused = 0;

  const server = net.createServer((client) => {
    accepted++;
    if (mode === 'refuse') { refused++; client.destroy(); return; }
    const upstream = net.connect(targetPort, targetHost);
    const p = { client, upstream, stalled: mode === 'blackhole', held: [] };
    pipes.add(p);
    const relay = (from, to) => from.on('data', (d) => { if (p.stalled) p.held.push([to, d]); else to.write(d); });
    relay(client, upstream);
    relay(upstream, client);
    for (const s of [client, upstream]) {
      s.on('error', () => {});
      s.on('close', () => { client.destroy(); upstream.destroy(); pipes.delete(p); });
    }
  });

  return {
    async listen() {
      await new Promise((r) => server.listen(0, '127.0.0.1', r));
      return server.address().port;
    },
    get port() { return server.address() && server.address().port; },
    get mode() { return mode; },
    stats: () => ({ accepted, refused, open: pipes.size }),
    refuse() {
      mode = 'refuse';
      for (const p of [...pipes]) { p.client.destroy(); p.upstream.destroy(); }
    },
    blackhole() {
      mode = 'blackhole';
      for (const p of pipes) p.stalled = true;
    },
    heal({ deliverHeld = true } = {}) {
      mode = 'pass';
      for (const p of [...pipes]) {
        if (!p.stalled) continue;
        if (deliverHeld) { p.stalled = false; for (const [to, d] of p.held.splice(0)) to.write(d); } else { p.client.destroy(); p.upstream.destroy(); }
      }
    },
    async close() {
      for (const p of [...pipes]) { p.client.destroy(); p.upstream.destroy(); }
      await new Promise((r) => server.close(() => r()));
    },
  };
}

module.exports = { createFaultProxy };
