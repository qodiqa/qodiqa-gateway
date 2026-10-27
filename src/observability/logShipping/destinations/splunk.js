'use strict';

// Splunk destination adapter — Component #24
//
// Ships log events to the Splunk HTTP Event Collector (HEC).
// Reference: https://docs.splunk.com/Documentation/Splunk/latest/Data/HTTPEventCollector
//
// Endpoint: POST {url}/services/collector/event
// Auth:     Authorization: Splunk {token}
// Format:   newline-delimited HEC event objects
//           { "time": <epoch>, "event": <log object>, "sourcetype": "_json" }

const { httpsPost: defaultHttpsPost } = require('../_transport');
const { mapToCim } = require('../../siem/cimMapper');

// #6: a mapping-function failure must never break delivery — fall
// back to the raw event and count it, rather than dropping/throwing.
function _mapEvent(event, schema) {
  if (schema !== 'cim') return event;
  try {
    return mapToCim(event);
  } catch (err) {
    try {
      require('../../metrics').logShipSchemaMappingErrorsTotal.inc({ destination: 'splunk', schema });
    } catch { /* metrics must never affect delivery */ }
    return event;
  }
}

function _toHecEvent(event, schema) {
  const mapped = _mapEvent(event, schema);
  return JSON.stringify({
    time:       Math.floor(new Date(event.timestamp).getTime() / 1000),
    host:       event.service,
    sourcetype: schema === 'cim' ? 'qodiqa:cim' : '_json',
    index:      event.environment,
    event:      schema === 'cim' ? mapped : {
      ...mapped,
      // Splunk's top-level 'time' field carries the timestamp; remove duplicate
      timestamp: undefined,
    },
  });
}

/**
 * Create the Splunk HEC destination adapter.
 *
 * @param {object} config       — log ship config (config.splunk must have url and token;
 * config.splunk.schema — 'raw' (default, unchanged behavior) | 'cim' — #6)
 * @param {object} [deps]
 * @param {Function} [deps.httpsPost]
 * @returns {{ name: string, send: Function }}
 */
function createSplunkDestination(config, { httpsPost = defaultHttpsPost } = {}) {
  const { url, token, schema = 'raw' } = config.splunk;
  const endpoint = url.replace(/\/$/, '') + '/services/collector/event';

  return {
    name: 'splunk',

    async send(events) {
      // HEC accepts multiple events as newline-delimited JSON objects
      const body = events.map(e => _toHecEvent(e, schema)).join('\n');

      let result;
      try {
        result = await httpsPost(
          endpoint,
          {
            'Content-Type':  'application/json',
            'Authorization': `Splunk ${token}`,
          },
          body,
        );
      } catch (err) {
        err.retryable = true;
        throw err;
      }

      if (result.status >= 400) {
        const err = new Error(`Splunk HEC returned HTTP ${result.status}`);
        err.status    = result.status;
        err.retryable = result.status === 429 || result.status >= 500;
        throw err;
      }
    },
  };
}

module.exports = { createSplunkDestination };
