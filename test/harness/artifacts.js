'use strict';

/**
 * Reusable sign/verify payload logic shared by acceptance tests and by
 * (which is now a thin CLI wrapper around
 * buildVerifyPayload, rather than a standalone reimplementation of the same
 * substitution logic).
 */

const path = require('path');

const { readJson } = require('./filesystem');
const { post } = require('./http');

const PAYLOADS_DIR = path.join(__dirname, '..', 'payloads');

/**
 * Calls POST /sign against a running server (see helpers/server.js) with a
 * given payload and signing API key, returning the full helpers/http.js
 * response.
 *
 * TRUST-1 remediation: /sign no longer accepts a shared X-QODIQA-Sign-Token
 * header — every caller authenticates with its own per-identity signing API
 * key via `Authorization: Bearer <key>` (see src/middleware/signAuth.js).
 * The `signToken` parameter name is unchanged so every existing caller of
 * this helper keeps working; its value is now a per-identity key (obtained
 * via helpers/environment.js's buildWorkingEnv() or
 * helpers/logs.js's extractSignToken()), never a shared secret.
 */
async function callSign(baseUrl, signToken, payload, extraHeaders = {}) {
  await require('./redis').waitForReplayBarrier(); // REL-01: see helpers/redis.js
  return post(`${baseUrl}/sign`, {
    headers: { Authorization: `Bearer ${signToken}`, ...extraHeaders },
    body: payload,
  });
}

/**
 * Calls POST /verify against a running server with a given payload.
 */
function callVerify(baseUrl, payload, extraHeaders = {}) {
  return post(`${baseUrl}/verify`, {
    headers: { ...extraHeaders },
    body: payload,
  });
}

const AI_CHAT_ARTIFACT_HEADER = 'x-qodiqa-artifact';

/**
 * Calls POST /ai/chat against a running server. Unlike /verify (whose nonce
 * store is deliberately read-only/dry-run — see
 * src/validation/dryRunStores.js), /ai/chat's enforcement pipeline uses the
 * real nonce store (server.js mounts createAiChatRouter without a _store
 * override), so this is the route that actually exercises replay
 * protection end-to-end.
 *
 * The artifact travels as a base64-encoded JSON header
 * (x-qodiqa-artifact), not the JSON body — see src/api/routes/aiChat.js.
 * The request used for binding verification is built from the real
 * incoming HTTP request (method POST, path /ai/chat, body = { prompt,
 * model }), so an artifact must be signed against exactly that request
 * shape for /ai/chat to accept it.
 *
 * @param {object} artifact  the `artifact` object from a real /sign response
 * @param {{ prompt: string, model?: string }} body
 */
function callAiChat(baseUrl, artifact, body, extraHeaders = {}) {
  const header = Buffer.from(JSON.stringify(artifact), 'utf8').toString('base64');
  return post(`${baseUrl}/ai/chat`, {
    headers: { [AI_CHAT_ARTIFACT_HEADER]: header, ...extraHeaders },
    body,
  });
}

/**
 * Builds the `request` object an artifact must be signed against for
 * /ai/chat to accept it (see callAiChat's doc comment).
 */
function buildAiChatRequest(body) {
  return { method: 'POST', path: '/ai/chat', body };
}

/**
 * Loads payloads/verify-template.json and substitutes its {{ARTIFACT}}
 * placeholder with a real `artifact` object (as a nested JSON object, never
 * a string) — the same substitution
 * performs for manual testing, exposed here as a plain function so
 * automated tests never need to shell out to that CLI script.
 *
 * @param {object} artifact  the `artifact` object from a real /sign response
 * @param {object} [requestOverride]  overrides the template's `request` field if provided
 */
function buildVerifyPayload(artifact, requestOverride) {
  const template = readJson(path.join(PAYLOADS_DIR, 'verify-template.json'));
  if (template.artifact !== '{{ARTIFACT}}') {
    throw new Error('payloads/verify-template.json no longer contains the expected {{ARTIFACT}} placeholder');
  }
  template.artifact = artifact;
  if (requestOverride) template.request = requestOverride;
  return template;
}

function loadPayload(filename) {
  return readJson(path.join(PAYLOADS_DIR, filename));
}

module.exports = {
  PAYLOADS_DIR,
  AI_CHAT_ARTIFACT_HEADER,
  callSign,
  callVerify,
  callAiChat,
  buildAiChatRequest,
  buildVerifyPayload,
  loadPayload,
};
