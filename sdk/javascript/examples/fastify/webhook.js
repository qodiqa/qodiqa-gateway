/**
 * Fastify webhook handler — QODIQA signature verification
 *
 * Fastify does not expose the raw request body via req.body — after parsing the
 * buffer is gone.  Use the addContentTypeParser API to capture raw bytes before
 * JSON parsing, OR use rawBody via the fastify-raw-body plugin.
 */

'use strict';

const Fastify = require('fastify');
const {
  verifyWebhookSignature,
  WebhookVerifier,
  InvalidSignatureError,
  ExpiredSignatureError,
  MalformedSignatureError,
  InvalidTimestampError,
} = require('@qodiqa/sdk');

const fastify = Fastify({ logger: true });
const WEBHOOK_SECRET = process.env.QODIQA_WEBHOOK_SECRET;

// ---------------------------------------------------------------------------
// Capture the raw body for the webhook route.
//
// We register a custom content-type parser for 'application/json' that keeps
// the raw buffer and stores it on req.rawBody before handing off to Fastify's
// default JSON parser.
// ---------------------------------------------------------------------------

fastify.addContentTypeParser(
  'application/json',
  { parseAs: 'buffer' },
  (req, body, done) => {
    req.rawBody = body; // Buffer
    try {
      done(null, JSON.parse(body.toString('utf8')));
    } catch (err) {
      done(err);
    }
  },
);

// ---------------------------------------------------------------------------
// Verification helper (reusable across routes)
// ---------------------------------------------------------------------------

const verifier = new WebhookVerifier(WEBHOOK_SECRET);

function verifyQodiqaSignature(req, reply) {
  const signature = req.headers['x-qodiqa-signature'];
  const timestamp = req.headers['x-qodiqa-timestamp'];
  if (!signature) {
    reply.status(400).send({ error: 'Missing X-QODIQA-Signature header' });
    return false;
  }
  if (!timestamp) {
    reply.status(400).send({ error: 'Missing X-QODIQA-Timestamp header' });
    return false;
  }

  try {
    verifier.verify(req.rawBody, signature, timestamp);
    return true;
  } catch (err) {
    if (
      err instanceof InvalidSignatureError ||
      err instanceof ExpiredSignatureError ||
      err instanceof MalformedSignatureError ||
      err instanceof InvalidTimestampError
    ) {
      reply.status(401).send({ error: err.message });
      return false;
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Webhook route
// ---------------------------------------------------------------------------

fastify.post('/webhooks/qodiqa', async (req, reply) => {
  if (!verifyQodiqaSignature(req, reply)) return;

  const event = req.body;
  req.log.info({ eventType: event.type }, 'Received webhook event');

  switch (event.type) {
    case 'sign.created':
      req.log.info({ artifactId: event.data?.artifactId }, 'Artifact signed');
      break;
    case 'verify.passed':
      req.log.info({ artifactId: event.data?.artifactId }, 'Verification passed');
      break;
    case 'verify.failed':
      req.log.warn({ artifactId: event.data?.artifactId, reason: event.data?.reason }, 'Verification failed');
      break;
    case 'policy.blocked':
      req.log.warn({ requestId: event.data?.requestId, reason: event.data?.reason }, 'Request blocked by policy');
      break;
    case 'consent.granted':
      req.log.info({ consentId: event.data?.consentId }, 'Consent granted');
      break;
    case 'consent.revoked':
      req.log.info({ consentId: event.data?.consentId }, 'Consent revoked');
      break;
    case 'key.rotated':
      req.log.info({ keyId: event.data?.keyId }, 'Signing key rotated');
      break;
    default:
      req.log.info({ eventType: event.type }, 'Unhandled webhook event type');
  }

  return { received: true };
});

// ---------------------------------------------------------------------------
// Secret rotation example
// ---------------------------------------------------------------------------

// const rotatingVerifier = new WebhookVerifier([
//   process.env.QODIQA_WEBHOOK_SECRET_NEW,
//   process.env.QODIQA_WEBHOOK_SECRET_OLD,
// ]);

fastify.listen({ port: 3002 }, (err) => {
  if (err) throw err;
});
