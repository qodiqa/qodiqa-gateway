/**
 * Express webhook handler — QODIQA signature verification
 *
 * IMPORTANT: The raw request body must be captured BEFORE any body-parser
 * middleware runs, because body-parser consumes and potentially modifies the
 * stream.  The signature is computed over the exact bytes sent by QODIQA.
 */

'use strict';

const express = require('express');
const {
  verifyWebhookSignature,
  WebhookVerifier,
  MalformedSignatureError,
  ExpiredSignatureError,
  InvalidSignatureError,
  InvalidTimestampError,
} = require('@qodiqa/sdk');

const app = express();
const WEBHOOK_SECRET = process.env.QODIQA_WEBHOOK_SECRET;

// ---------------------------------------------------------------------------
// Option A: Verify with the convenience function in a route-specific handler.
//
// Use express.raw() on the specific route to capture the raw buffer.
// ---------------------------------------------------------------------------

app.post(
  '/webhooks/qodiqa',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const signature = req.headers['x-qodiqa-signature'];
    const timestamp = req.headers['x-qodiqa-timestamp'];
    if (!signature) {
      return res.status(400).json({ error: 'Missing X-QODIQA-Signature header' });
    }
    if (!timestamp) {
      return res.status(400).json({ error: 'Missing X-QODIQA-Timestamp header' });
    }

    try {
      verifyWebhookSignature({
        body: req.body,          // Buffer — raw bytes from express.raw()
        signature,
        timestamp,
        secret: WEBHOOK_SECRET,
      });
    } catch (err) {
      if (err instanceof ExpiredSignatureError) {
        return res.status(401).json({ error: 'Webhook replay detected', detail: err.message });
      }
      if (err instanceof InvalidSignatureError || err instanceof MalformedSignatureError || err instanceof InvalidTimestampError) {
        return res.status(401).json({ error: 'Invalid webhook signature', detail: err.message });
      }
      throw err; // unexpected — let the global error handler deal with it
    }

    // Signature is valid — parse and process the event.
    const event = JSON.parse(req.body.toString('utf8'));

    switch (event.type) {
      case 'sign.created':
        console.log('Artifact signed:', event.data?.artifactId);
        break;
      case 'verify.passed':
        console.log('Verification passed:', event.data?.artifactId);
        break;
      case 'verify.failed':
        console.warn('Verification failed:', event.data?.artifactId, event.data?.reason);
        break;
      case 'policy.blocked':
        console.warn('Request blocked by policy:', event.data?.requestId, event.data?.reason);
        break;
      case 'consent.granted':
        console.log('Consent granted:', event.data?.consentId);
        break;
      case 'consent.revoked':
        console.log('Consent revoked:', event.data?.consentId);
        break;
      case 'key.rotated':
        console.log('Signing key rotated:', event.data?.keyId);
        break;
      default:
        console.log('Unhandled webhook event type:', event.type);
    }

    res.status(200).json({ received: true });
  },
);

// ---------------------------------------------------------------------------
// Option B: Reusable WebhookVerifier middleware
// ---------------------------------------------------------------------------

const verifier = new WebhookVerifier(WEBHOOK_SECRET);

function qodiqaWebhookMiddleware(req, res, next) {
  const signature = req.headers['x-qodiqa-signature'];
  const timestamp = req.headers['x-qodiqa-timestamp'];
  if (!signature) {
    return res.status(400).json({ error: 'Missing X-QODIQA-Signature header' });
  }
  if (!timestamp) {
    return res.status(400).json({ error: 'Missing X-QODIQA-Timestamp header' });
  }

  try {
    verifier.verify(req.rawBody ?? req.body, signature, timestamp);
  } catch (err) {
    if (
      err instanceof InvalidSignatureError ||
      err instanceof ExpiredSignatureError ||
      err instanceof MalformedSignatureError ||
      err instanceof InvalidTimestampError
    ) {
      return res.status(401).json({ error: err.message });
    }
    return next(err);
  }

  next();
}

// Secret rotation: pass an array of secrets during the transition period.
//
// const rotatingVerifier = new WebhookVerifier([
//   process.env.QODIQA_WEBHOOK_SECRET_NEW,
//   process.env.QODIQA_WEBHOOK_SECRET_OLD,
// ]);

app.post(
  '/webhooks/qodiqa/v2',
  express.raw({ type: 'application/json' }),
  qodiqaWebhookMiddleware,
  (req, res) => {
    const event = JSON.parse(req.body.toString('utf8'));
    console.log('Verified event:', event.type);
    res.status(200).json({ received: true });
  },
);

app.listen(3001, () => console.log('Webhook server listening on :3001'));
