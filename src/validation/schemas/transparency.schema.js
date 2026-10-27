'use strict';

const { z } = require('../zod');
const { zodUuid } = require('./common.schema');

const VALID_ENTRY_TYPES = ['ARTIFACT', 'EVIDENCE', 'VERIFICATION', 'POLICY', 'AUDIT', 'SYSTEM'];

// Path parameter schemas
const transparencyIdParamSchema = z.object({ transparencyId: zodUuid });

// POST /register body
const registerEntryBodySchema = z.object({
  entryType:       z.enum(/** @type {any} */ (VALID_ENTRY_TYPES), { error: () => `entryType must be one of: ${VALID_ENTRY_TYPES.join(', ')}` }),
  artifactId:      z.string().optional().nullable(),
  evidenceChainId: z.string().optional().nullable(),
  verificationId:  z.string().optional().nullable(),
  payload:         z.record(z.string(), z.unknown()).optional().default({}),
  tenantId:        z.string().optional().nullable(),
}).strict();

module.exports = { transparencyIdParamSchema, registerEntryBodySchema, VALID_ENTRY_TYPES };
