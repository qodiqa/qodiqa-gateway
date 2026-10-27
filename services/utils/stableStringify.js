'use strict';

// Legacy entry point — delegates to the canonical shared utility.
// All callers that import from services/utils/ continue to work unchanged.
// New code should import directly from src/utils/stableStringify.
module.exports = require('../../src/utils/stableStringify');
