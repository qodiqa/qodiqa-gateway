'use strict';

const { z } = require('../zod');
const { zodClientId, zodKeyId } = require('./common.schema');

// Path parameter schemas
const clientIdParamSchema = z.object({ clientId: zodClientId });

// POST /purge-expired — clientId is optional
const purgeExpiredBodySchema = z.object({
  clientId: zodClientId.optional(),
}).strict();

// POST /:clientId/revoke — keyId required in body, must belong to clientId.
// reason is optional free text recorded in the revocation audit trail.
const revokeKeyBodySchema = z.object({
  keyId:  zodKeyId,
  reason: z.string().max(500).optional(),
}).strict();

module.exports = { clientIdParamSchema, purgeExpiredBodySchema, revokeKeyBodySchema };
