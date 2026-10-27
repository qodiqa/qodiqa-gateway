'use strict';

const _NOOP_EXPORTER = Object.freeze({
  name: 'noop',
  exportSpans: async () => {},
});

module.exports = { _NOOP_EXPORTER };
