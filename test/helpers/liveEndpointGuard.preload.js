'use strict';

// preloaded (NODE_OPTIONS --require) into every Node child a test spawns, so a server.js /
// bootstrap-dev.js / script child cannot reach the LIVE PostgreSQL (5432) or Redis (6379) on this machine through a
// product default or a `.env` back-fill. See liveEndpointGuard.js. Exempt under CI=true / QODIQA_TEST_ALLOW_LIVE_PORTS=true.
require('./liveEndpointGuard').installSocketGuard();
