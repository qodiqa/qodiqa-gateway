'use strict';

const { z, integer } = require('../zod');

// Shared regex patterns (canonical single source of truth across the platform)
const UUID_RE      = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CLIENT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const KEY_ID_RE    = /^[A-Za-z0-9_-]{1,64}:key_v\d+$/;
const ACTOR_RE     = /^[a-zA-Z0-9._:@/-]{1,256}$/;
const ACTION_RE    = /^[a-zA-Z0-9 _:@/-]{1,256}$/;
const SCOPE_RE     = /^[a-zA-Z0-9_-]{1,128}$/;
const TENANT_RE    = /^[a-zA-Z0-9._:@/-]{1,128}$/;

// Canonical Zod primitives derived from those patterns
const zodUuid     = z.string().regex(UUID_RE,      'Must be a valid UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)');
const zodClientId = z.string().regex(CLIENT_ID_RE, 'Must match [A-Za-z0-9_-]{1,64}');
const zodKeyId    = z.string().regex(KEY_ID_RE,    'Must match <clientId>:key_v<n>');
const zodActorId  = z.string().trim().min(1).regex(ACTOR_RE,  'Invalid actor_id format');
const zodAction   = z.string().trim().min(1).regex(ACTION_RE, 'Invalid action format');
const zodScope    = z.string().trim().min(1).regex(SCOPE_RE,  'Invalid scope format');
const zodTenantId = z.string().trim().min(1).regex(TENANT_RE, 'Invalid tenant_id format');

// Pagination query schema — shared across multiple list endpoints. Not
// currently wired into any live route (item 9 audit: no route imports this
// export for request validation) — tightened anyway for when it is.
const paginationQuerySchema = z.object({
  page:      z.coerce.number().check(integer()).min(1).optional().default(1),
  pageSize:  z.coerce.number().check(integer()).min(1).max(500).optional().default(50),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
}).strict();

module.exports = {
  UUID_RE, CLIENT_ID_RE, KEY_ID_RE, ACTOR_RE, ACTION_RE, SCOPE_RE, TENANT_RE,
  zodUuid, zodClientId, zodKeyId, zodActorId, zodAction, zodScope, zodTenantId,
  paginationQuerySchema,
};
