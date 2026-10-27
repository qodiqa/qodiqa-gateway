'use strict';

const { z } = require('../zod');

const externalIdentity = z.object({ issuer: z.string().min(1), subject: z.string().min(1) }).strict();

// POST /signing-identities
const createSigningIdentitySchema = z.object({
  name:             z.string().min(1, 'name is required'),
  tenantId:         z.string().min(1, 'tenantId is required'),
  environment:      z.string().min(1, 'environment is required'),
  allowedProviders: z.array(z.string().min(1)).min(1).nullable().optional(),
  permissions:      z.array(z.string().min(1)).min(1, 'permissions must be a non-empty array'),
  maxTtlMs:         z.number().finite().positive().nullable().optional(),
  // an identity authenticated by an OIDC bearer token of the linked (issuer, subject) instead of an API key
  credentialType:   z.enum(['api-key', 'oidc']).optional(),
  externalIdentity: externalIdentity.optional(),
  requireAssurance: z.boolean().optional(),
}).strict().superRefine((val, ctx) => {
  if (val.requireAssurance && val.credentialType !== 'oidc') ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'requireAssurance is only for credentialType "oidc"' });
  if (val.credentialType === 'oidc' && !val.externalIdentity) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'externalIdentity is required for credentialType "oidc"' });
  if (val.credentialType !== 'oidc' && val.externalIdentity) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'externalIdentity is only for credentialType "oidc"' });
});

// PUT /signing-identities/:id — at least one field must be provided
const updateSigningIdentitySchema = z.object({
  name:             z.string().min(1).optional(),
  tenantId:         z.string().min(1).optional(),
  environment:      z.string().min(1).optional(),
  allowedProviders: z.array(z.string().min(1)).min(1).nullable().optional(),
  permissions:      z.array(z.string().min(1)).min(1).optional(),
  maxTtlMs:         z.number().finite().positive().nullable().optional(),
  enabled:          z.boolean().optional(),
  externalIdentity: externalIdentity.optional(),
  requireAssurance: z.boolean().optional(),
}).strict().superRefine((val, ctx) => {
  const fields = ['name', 'tenantId', 'environment', 'allowedProviders', 'permissions', 'maxTtlMs', 'enabled', 'externalIdentity', 'requireAssurance'];
  if (fields.every((f) => val[f] === undefined)) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: 'At least one field must be provided',
    });
  }
});

module.exports = { createSigningIdentitySchema, updateSigningIdentitySchema };
