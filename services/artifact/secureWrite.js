'use strict';

// moved to src/infra/fs/secureWrite.js so the infra layer (KMS/HSM key providers) no longer
// depends on services/ (4 no-infra-to-services errors in npm run arch:check). Re-exported here for existing importers.
module.exports = require('../../src/infra/fs/secureWrite');
