'use strict';

const { z } = require('../zod');

// the (issuer, subject) a user signs in with through single sign-on
const externalIdentity = z.object({ issuer: z.string().min(1), subject: z.string().min(1) }).strict();

// POST /rbac/users
const createUserSchema = z.object({
  username: z.string().min(1, 'username is required'),
  role:     z.string().min(1, 'role is required'),
  externalIdentity: externalIdentity.optional(),
}).strict();

// PUT /rbac/users/:id — at least one field must be provided
const updateUserSchema = z.object({
  username: z.string().min(1).optional(),
  role:     z.string().min(1).optional(),
  enabled:  z.boolean().optional(),
  externalIdentity: externalIdentity.nullable().optional(),    // null unlinks
}).strict().superRefine((val, ctx) => {
  if (val.username === undefined && val.role === undefined && val.enabled === undefined && val.externalIdentity === undefined) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: 'At least one of username, role, enabled, or externalIdentity must be provided',
    });
  }
});

// POST /rbac/roles
const createRoleSchema = z.object({
  name:        z.string().min(1, 'name is required'),
  description: z.string().optional(),
  permissions: z.array(z.string()).min(1, 'permissions must be a non-empty array'),
}).strict();

// PUT /rbac/roles/:id — at least one field must be provided
const updateRoleSchema = z.object({
  name:        z.string().min(1).optional(),
  description: z.string().optional(),
  permissions: z.array(z.string()).min(1).optional(),
  enabled:     z.boolean().optional(),
}).strict().superRefine((val, ctx) => {
  if (val.name === undefined && val.description === undefined && val.permissions === undefined && val.enabled === undefined) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: 'At least one of name, description, permissions, or enabled must be provided',
    });
  }
});

// POST /rbac/roles/validate
const validatePermissionsSchema = z.object({
  permissions: z.array(z.string()).min(1, 'permissions must be a non-empty array'),
}).strict();

module.exports = {
  createUserSchema,
  updateUserSchema,
  createRoleSchema,
  updateRoleSchema,
  validatePermissionsSchema,
};
