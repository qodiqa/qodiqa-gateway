'use strict';

/**
 * QODIQA SDK — Express middleware example
 *
 * This demonstrates how to use QODIQA to enforce every AI request that
 * flows through an Express application.
 *
 * Install dependencies:
 *   npm install express
 *   npm install @qodiqa/sdk   (or use the local build)
 *
 * Run:
 *   QODIQA_API_KEY=ok_<64hex> QODIQA_SIGN_TOKEN=<token> node examples/express/middleware.js
 */

const express = require('express');
const { QodiqaClient, QodiqaError, AuthenticationError } = require('@qodiqa/sdk');

// ---------------------------------------------------------------------------
// QODIQA client singleton
// ---------------------------------------------------------------------------

const qodiqa = new QodiqaClient({
  apiKey: process.env.QODIQA_API_KEY,
  signToken: process.env.QODIQA_SIGN_TOKEN,
  baseUrl: process.env.QODIQA_BASE_URL || 'http://localhost:3000',
  timeout: 10_000,
  maxRetries: 1,
});

// ---------------------------------------------------------------------------
// QODIQA enforcement middleware
// ---------------------------------------------------------------------------

/**
 * Express middleware that:
 * 1. Signs the incoming AI request using the configured sign token.
 * 2. Attaches the artifact to `req.qodiqaArtifact` and `req.qodiqaArtifactB64`
 *    so downstream handlers can use them.
 * 3. Blocks requests whose signed artifact cannot be issued (e.g. policy deny).
 */
async function qodiqaSignMiddleware(req, res, next) {
  try {
    // payload.provider is intentionally omitted for non-/ai/chat paths (it's
    // ignored there) and for /ai/chat itself it only needs to be set
    // explicitly once more than one AI provider is enabled server-side —
    // /sign auto-resolves it otherwise (400 PROVIDER_REQUIRED if ambiguous).
    const signed = await qodiqa.sign.sign({
      request: {
        method: req.method,
        path: req.path,
        body: req.body || {},
      },
      payload: {
        userId: req.headers['x-user-id'] || 'anonymous',
        ip: req.ip,
      },
      ttl: 60_000, // 1 minute
    });

    req.qodiqaArtifact = signed.artifact;
    req.qodiqaArtifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');
    req.qodiqaArtifactId = signed.artifactId;

    next();
  } catch (err) {
    if (err instanceof QodiqaError) {
      res.status(err.status || 500).json({
        error: 'QODIQA enforcement failed',
        reason: err.message,
        requestId: err.requestId,
      });
    } else {
      next(err);
    }
  }
}

/**
 * Middleware that verifies the attached artifact matches the current request
 * before allowing it to proceed.
 */
async function qodiqaVerifyMiddleware(req, res, next) {
  if (!req.qodiqaArtifactB64) {
    return res.status(400).json({ error: 'Missing QODIQA artifact. Use qodiqaSignMiddleware first.' });
  }

  try {
    const verification = await qodiqa.verify.verify(req.qodiqaArtifactB64, {
      artifact: req.qodiqaArtifact,
      request: {
        method: req.method,
        path: req.path,
        body: req.body || {},
      },
    });

    req.qodiqaDecision = verification.decision;

    if (verification.decision === 'BLOCK') {
      return res.status(403).json({
        error: 'Request blocked by QODIQA enforcement',
        decision: verification.decision,
        reason: verification.reason,
        requestId: verification.requestId,
      });
    }

    next();
  } catch (err) {
    if (err instanceof QodiqaError) {
      res.status(err.status || 500).json({
        error: 'Verification failed',
        reason: err.message,
        requestId: err.requestId,
      });
    } else {
      next(err);
    }
  }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

// Health endpoint (no enforcement needed)
app.get('/health', async (_req, res) => {
  try {
    const health = await qodiqa.healthCheck();
    res.json(health);
  } catch (err) {
    res.status(503).json({ error: 'QODIQA unreachable', details: err.message });
  }
});

// AI chat endpoint — guarded by sign + verify middleware
app.post(
  '/api/chat',
  qodiqaSignMiddleware,
  qodiqaVerifyMiddleware,
  async (req, res) => {
    try {
      const { prompt, model } = req.body;

      if (!prompt) {
        return res.status(400).json({ error: 'prompt is required' });
      }

      // The artifact header is already prepared by qodiqaSignMiddleware
      const chatResponse = await qodiqa.chat.create(req.qodiqaArtifactB64, {
        prompt,
        model,
      });

      if (chatResponse.decision === 'BLOCK') {
        return res.status(403).json({
          error: 'AI request blocked',
          reason: chatResponse.reason,
          requestId: chatResponse.requestId,
        });
      }

      res.json({
        text: chatResponse.aiText,
        model: chatResponse.model,
        tokenUsage: chatResponse.tokenUsage,
        requestId: chatResponse.requestId,
        artifactId: req.qodiqaArtifactId,
      });
    } catch (err) {
      if (err instanceof QodiqaError) {
        res.status(err.status || 500).json({ error: err.message, requestId: err.requestId });
      } else {
        res.status(500).json({ error: 'Internal server error' });
      }
    }
  },
);

// Global error handler
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.PORT || '4000', 10);
app.listen(PORT, () => {
  console.log(`Express + QODIQA middleware running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log('  GET  /health     — liveness');
  console.log('  POST /api/chat   — enforced AI chat (requires JSON body: { prompt, model? })');
});
