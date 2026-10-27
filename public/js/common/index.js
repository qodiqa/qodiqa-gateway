'use strict';

/**
 * Node-only aggregator for public/js/common/*. Not referenced by
 * any <script> tag: each browser page loads the individual files it needs
 * directly via <script src="/js/common/<name>.js" defer>, in dependency
 * order. This file exists purely so Node/Jest code (direct unit tests of the
 * common modules, the dashboard test-sandbox harness) can do a single
 * `require('.../public/js/common')` instead of four.
 */
module.exports = Object.assign(
  {},
  require('./esc'),
  require('./pagination'),
  require('./badges'),
  require('./actions')
);
