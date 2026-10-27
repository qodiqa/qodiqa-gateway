'use strict';

/**
 * Control-plane change notifier — on the signed pub/sub.
 *
 * After a committed control-plane write, the writing replica publishes
 * { v, store, recordId, origin, at } on qodiqa:control-plane, MAC-signed with
 * the keystore MAC keyring (purpose CONTROL_PLANE). A receiving replica
 * verifies the MAC and, if valid, pulls from PostgreSQL immediately.
 *
 * A message carries no state: it only says "pull now". The data always comes
 * from PostgreSQL, so a forged message could at most cause an extra pull — and
 * unsigned or badly signed messages are rejected anyway. A LOST
 * message costs latency only: the periodic pull and the 5 s staleness bound
 * (./index.js) are the guarantee, not this channel.
 */

const { createManagedRedisClient } = require('../../infra/redis/managedClient');
const macKeyring = require('../security/macKeyring');
const { emit } = require('../../../services/logger');

const CHANNEL = 'qodiqa:control-plane';

function _canonical(m) {
  return JSON.stringify([m.v, m.store, m.recordId, m.origin, m.at]);
}

function buildMessage({ store, recordId, origin }) {
  const m = { v: 1, store, recordId, origin, at: Date.now() };
  m.signature = macKeyring.sign(macKeyring.PURPOSES.CONTROL_PLANE, _canonical(m));
  return m;
}

function verifyMessage(raw) {
  let m;
  try { m = JSON.parse(raw); } catch { return { ok: false, reason: 'MALFORMED' }; }
  if (!m || m.v !== 1 || typeof m.store !== 'string' || typeof m.recordId !== 'string' || typeof m.origin !== 'string' || typeof m.at !== 'number') {
    return { ok: false, reason: 'MALFORMED' };
  }
  let v;
  try { v = macKeyring.verify(macKeyring.PURPOSES.CONTROL_PLANE, _canonical(m), m.signature); } catch (err) { return { ok: false, reason: `KEYRING_${err.code || 'ERROR'}` }; }
  return v.ok ? { ok: true, message: m } : { ok: false, reason: /** @type {any} */ (v).reason };
}

function create({ origin, onChange }) {
  let pub = null; let sub = null; let pubReady = false; let subReady = false;
  const counters = { published: 0, received: 0, rejected: 0 };

  function _client(purpose, onReady, onDown) {
    const c = createManagedRedisClient({
      purpose,
      connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10),
      reconnectStrategy: (attempts) => Math.min(200 * Math.pow(2, attempts), 5000),
    });
    c.on('ready', onReady);
    c.on('error', (err) => { onDown(); emit('WARN', 'CONTROL_PLANE_NOTIFIER_REDIS_ERROR', { purpose, error: err.message }); });
    c.on('reconnecting', onDown);
    return c;
  }

  function _handle(raw) {
    const r = verifyMessage(raw);
    if (!r.ok) {
      counters.rejected++;
      emit('WARN', 'CONTROL_PLANE_NOTIFICATION_REJECTED', { reason: r.reason });
      return;
    }
    if (r.message.origin === origin) return;
    counters.received++;
    onChange(r.message);
  }

  async function start() {
    pub = _client('controlPlanePublisher', () => { pubReady = true; }, () => { pubReady = false; });
    sub = _client('controlPlaneSubscriber', () => {
      subReady = true;
      // Resubscribe after a reconnect and pull, in case messages were missed meanwhile.
      sub.subscribe(CHANNEL, _handle).catch(() => {});
      onChange(null);
    }, () => { subReady = false; });
    await Promise.all([pub.connect(), sub.connect()]);
  }

  async function publish({ store, recordId }) {
    if (!pub || !pubReady) return false;
    try {
      await pub.publish(CHANNEL, JSON.stringify(buildMessage({ store, recordId, origin })));
      counters.published++;
      return true;
    } catch (err) {
      emit('WARN', 'CONTROL_PLANE_NOTIFY_FAILED', { store, recordId, error: err.message });
      return false;
    }
  }

  async function stop() {
    for (const c of [sub, pub]) { if (c) { try { await c.disconnect(); } catch { /* ignore */ } } }
    pub = null; sub = null; pubReady = false; subReady = false;
  }

  function status() { return { channel: CHANNEL, publisherReady: pubReady, subscriberReady: subReady, ...counters }; }

  return { start, publish, stop, status };
}

module.exports = { CHANNEL, create, buildMessage, verifyMessage };
