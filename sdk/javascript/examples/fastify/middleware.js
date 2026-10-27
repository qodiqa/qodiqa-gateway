'use strict';

/**
 * QODIQA SDK — Fastify plugin example
 *
 * Demonstrates integrating QODIQA enforcement into a Fastify application
 * using a reusable plugin and per-route pre-handler hooks.
 *
 * Install dependencies:
 *   npm install fastify
 *   npm install @qodiqa/sdk   (or use the local build)
 *
 * Run:
 *   QODIQA_SIGN_TOKEN=<token> QODIQA_BASE_URL=http://localhost:3000 node examples/fastify/middleware.js
 */

const Fastify = require('fastify');
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
// QODIQA Fastify plugin
// ---------------------------------------------------------------------------

/**
 * Fastify plugin that adds a `qodiqaEnforce` decorator and a pre-handler
 * hook factory for signing and verifying AI requests.
 *
 * @param {import('fastify').FastifyInstance} fastify
 */
async function qodiqaPlugin(fastify) {
  // Expose the QODIQA client on every request via decorator
  fastify.decorateRequest('qodiqaArtifact', null);
  fastify.decorateRequest('qodiqaArtifactB64', null);
  fastify.decorateRequest('qodiqaArtifactId', null);

  /**
   * Pre-handler that signs the request body and attaches the artifact.
   * Use this as a `preHandler` hook on routes that need QODIQA enforcement.
   */
  fastify.decorate('qodiqaSignHook', async (request, reply) => {
    try {
      // payload.provider is intentionally omitted for non-/ai/chat paths (it's
      // ignored there) and for /ai/chat itself it only needs to be set
      // explicitly once more than one AI provider is enabled server-side —
      // /sign auto-resolves it otherwise (400 PROVIDER_REQUIRED if ambiguous).
      const signed = await qodiqa.sign.sign({
        request: {
          method: request.method,
          path: request.url,
          body: request.body || {},
        },
        payload: {
          userId: request.headers['x-user-id'] || 'anonymous',
          ip: request.ip,
        },
        ttl: 60_000,
      });

      request.qodiqaArtifact = signed.artifact;
      request.qodiqaArtifactB64 = Buffer.from(
        JSON.stringify(signed.artifact),
      ).toString('base64');
      request.qodiqaArtifactId = signed.artifactId;
    } catch (err) {
      if (err instanceof QodiqaError) {
        return reply.code(err.status || 500).send({
          error: 'QODIQA enforcement failed',
          reason: err.message,
          requestId: err.requestId,
        });
      }
      throw err;
    }
  });

  /**
   * Pre-handler that verifies the signed artifact matches the current request.
   * Must run after `qodiqaSignHook`.
   */
  fastify.decorate('qodiqaVerifyHook', async (request, reply) => {
    if (!request.qodiqaArtifactB64) {
      return reply.code(400).send({
        error: 'Missing QODIQA artifact — ensure qodiqaSignHook runs first.',
      });
    }

    try {
      const verification = await qodiqa.verify.verify(request.qodiqaArtifactB64, {
        artifact: request.qodiqaArtifact,
        request: {
          method: request.method,
          path: request.url,
          body: request.body || {},
        },
      });

      if (verification.decision === 'BLOCK') {
        return reply.code(403).send({
          error: 'Request blocked by QODIQA enforcement',
          decision: verification.decision,
          reason: verification.reason,
          requestId: verification.requestId,
        });
      }
    } catch (err) {
      if (err instanceof QodiqaError) {
        return reply.code(err.status || 500).send({
          error: 'Verification failed',
          reason: err.message,
          requestId: err.requestId,
        });
      }
      throw err;
    }
  });
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

async function buildApp() {
  const app = Fastify({ logger: true });

  // Register the QODIQA plugin
  await app.register(qodiqaPlugin);

  // Health endpoint — no enforcement needed
  app.get('/health', async (_request, _reply) => {
    try {
      return await qodiqa.healthCheck();
    } catch (err) {
      throw app.httpErrors?.serviceUnavailable?.('QODIQA unreachable') ?? err;
    }
  });

  // Enforced AI chat endpoint
  app.post(
    '/api/chat',
    {
      preHandler: [
        async (req, reply) => app.qodiqaSignHook(req, reply),
        async (req, reply) => app.qodiqaVerifyHook(req, reply),
      ],
    },
    async (request, reply) => {
      const { prompt, model } = request.body;

      if (!prompt) {
        return reply.code(400).send({ error: 'prompt is required' });
      }

      try {
        const chatResponse = await qodiqa.chat.create(request.qodiqaArtifactB64, {
          prompt,
          model,
        });

        if (chatResponse.decision === 'BLOCK') {
          return reply.code(403).send({
            error: 'AI request blocked',
            reason: chatResponse.reason,
            requestId: chatResponse.requestId,
          });
        }

        return {
          text: chatResponse.aiText,
          model: chatResponse.model,
          tokenUsage: chatResponse.tokenUsage,
          requestId: chatResponse.requestId,
          artifactId: request.qodiqaArtifactId,
        };
      } catch (err) {
        if (err instanceof AuthenticationError) {
          return reply.code(401).send({ error: err.message });
        }
        if (err instanceof QodiqaError) {
          return reply.code(err.status || 500).send({
            error: err.message,
            requestId: err.requestId,
          });
        }
        throw err;
      }
    },
  );

  return app;
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

buildApp()
  .then((app) => {
    const port = parseInt(process.env.PORT || '4001', 10);
    return app.listen({ port, host: '0.0.0.0' }).then(() => {
      console.log(`Fastify + QODIQA enforcement running on http://localhost:${port}`);
      console.log('Endpoints:');
      console.log('  GET  /health    — liveness');
      console.log('  POST /api/chat  — enforced AI chat (JSON body: { prompt, model? })');
    });
  })
  .catch((err) => {
    console.error('Failed to start:', err);
    process.exit(1);
  });
