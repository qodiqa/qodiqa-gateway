'use strict';

// Reviewed live routes that the generated OpenAPI document deliberately does not describe (shared by
// liveRouteParity.test.js and conditionalRoutes.test.js).
const KNOWN_UNDOCUMENTED = new Set([
  'get /docs/',                          // 301 alias of GET /docs (routeParity.test.js)
  'get /docs/assets/{name}',             // self-hosted Swagger UI static assets for GET /docs (allowlisted names only), not an API operation
  'get /diagnostics/profile/memory',     // ops-only profiling surface (item 27, D26-5)
  'get /diagnostics/profile/gc',
  'post /diagnostics/profile/cpu',
]);

module.exports = { KNOWN_UNDOCUMENTED };
