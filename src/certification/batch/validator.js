'use strict';

// Request validation for batch certification endpoints.

const MAX_BATCH_ITEMS     = 100;
const MAX_ARTIFACTS       = 50;
const MAX_EVIDENCE_PKGS   = 50;

function validateCreateBatch(body) {
  if (!body || typeof body !== 'object') {
    return 'Request body is required';
  }

  const { frameworkId, items } = body;

  if (!frameworkId || typeof frameworkId !== 'string' || !frameworkId.trim()) {
    return 'frameworkId is required and must be a non-empty string';
  }

  if (!Array.isArray(items) || items.length === 0) {
    return 'items must be a non-empty array';
  }

  if (items.length > MAX_BATCH_ITEMS) {
    return `items must not exceed ${MAX_BATCH_ITEMS} entries`;
  }

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (!item || typeof item !== 'object') {
      return `items[${i}] must be an object`;
    }
    if (!item.subjectId || typeof item.subjectId !== 'string' || !item.subjectId.trim()) {
      return `items[${i}].subjectId is required and must be a non-empty string`;
    }
    if (item.artifacts !== undefined) {
      if (!Array.isArray(item.artifacts)) {
        return `items[${i}].artifacts must be an array`;
      }
      if (item.artifacts.length > MAX_ARTIFACTS) {
        return `items[${i}].artifacts must not exceed ${MAX_ARTIFACTS} entries`;
      }
    }
    if (item.evidencePackages !== undefined) {
      if (!Array.isArray(item.evidencePackages)) {
        return `items[${i}].evidencePackages must be an array`;
      }
      if (item.evidencePackages.length > MAX_EVIDENCE_PKGS) {
        return `items[${i}].evidencePackages must not exceed ${MAX_EVIDENCE_PKGS} entries`;
      }
    }
    if (item.controls !== undefined && (typeof item.controls !== 'object' || Array.isArray(item.controls))) {
      return `items[${i}].controls must be an object`;
    }
  }

  return null;
}

module.exports = { validateCreateBatch };
