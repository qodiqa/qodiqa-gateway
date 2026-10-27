'use strict';

// ELK destination adapter — Component #24
//
// Ships log events to a Logstash HTTP endpoint or Elasticsearch ingest endpoint
// using NDJSON format (one JSON object per line, Content-Type: application/x-ndjson).
//
// Error classification:
//   Retryable:     429, 502, 503, 504, network errors
//   Non-retryable: 400, 401, 403, other 4xx

const { httpsPost: defaultHttpsPost } = require('../_transport');
const { mapToEcs } = require('../../siem/ecsMapper');

// #6: a mapping-function failure must never break delivery — fall
// back to the raw event and count it, rather than dropping/throwing.
function _mapEvent(event, schema) {
  if (schema !== 'ecs') return event;
  try {
    return mapToEcs(event);
  } catch (err) {
    try {
      require('../../metrics').logShipSchemaMappingErrorsTotal.inc({ destination: 'elk', schema });
    } catch { /* metrics must never affect delivery */ }
    return event;
  }
}

/**
 * Create the ELK destination adapter.
 *
 * @param {object} config       — log ship config (config.elk must have url;
 * config.elk.schema — 'raw' (default, unchanged behavior) | 'ecs' — #6)
 * @param {object} [deps]       — injectable dependencies (for testing)
 * @param {Function} [deps.httpsPost] — HTTP POST implementation
 * @returns {{ name: string, send: Function }}
 */
function createElkDestination(config, { httpsPost = defaultHttpsPost } = {}) {
  const { url, schema = 'raw' } = config.elk;

  return {
    name: 'elk',

    /**
     * Send an array of normalized log events to the ELK endpoint.
     * Throws on non-retryable error; throws with .retryable=true for transient errors.
     *
     * @param {object[]} events
     */
    async send(events) {
      const ndjson = events.map(e => JSON.stringify(_mapEvent(e, schema))).join('\n');

      let result;
      try {
        result = await httpsPost(
          url,
          { 'Content-Type': 'application/x-ndjson' },
          ndjson,
        );
      } catch (err) {
        // Network-level error — always retryable
        err.retryable = true;
        throw err;
      }

      if (result.status >= 400) {
        const err = new Error(`ELK returned HTTP ${result.status}`);
        err.status    = result.status;
        err.retryable = result.status === 429 || result.status >= 500;
        throw err;
      }
    },
  };
}

module.exports = { createElkDestination };
