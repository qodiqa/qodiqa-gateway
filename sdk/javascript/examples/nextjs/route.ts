/**
 * QODIQA SDK — Next.js App Router API route example
 *
 * Place this file at:  app/api/ai/chat/route.ts
 *
 * This route:
 * 1. Signs the incoming request using QODIQA.
 * 2. Calls the QODIQA-enforced AI chat endpoint.
 * 3. Returns the AI response or a BLOCK decision to the client.
 *
 * Environment variables required (set in .env.local):
 *   QODIQA_SIGN_TOKEN=<your-sign-token>
 *   QODIQA_BASE_URL=http://localhost:3000    (or production URL)
 *   QODIQA_API_KEY=ok_<64hex>               (optional, for ops endpoints)
 */

import { NextRequest, NextResponse } from 'next/server';
import {
  QodiqaClient,
  QodiqaError,
  AuthenticationError,
  ValidationError,
} from '@qodiqa/sdk';

// ---------------------------------------------------------------------------
// Client (singleton — instantiated once per cold start)
// ---------------------------------------------------------------------------

const qodiqa = new QodiqaClient({
  signToken: process.env['QODIQA_SIGN_TOKEN'],
  apiKey: process.env['QODIQA_API_KEY'],
  baseUrl: process.env['QODIQA_BASE_URL'] ?? 'http://localhost:3000',
  timeout: 15_000,
  maxRetries: 1,
});

// ---------------------------------------------------------------------------
// Request body type
// ---------------------------------------------------------------------------

interface ChatRequestBody {
  prompt: string;
  model?: string;
  userId?: string;
}

// ---------------------------------------------------------------------------
// POST handler
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest): Promise<NextResponse> {
  // Parse and validate body
  let body: ChatRequestBody;
  try {
    body = (await req.json()) as ChatRequestBody;
  } catch {
    return NextResponse.json(
      { error: 'Invalid JSON body' },
      { status: 400 },
    );
  }

  const { prompt, model, userId = 'anonymous' } = body;

  if (!prompt || typeof prompt !== 'string' || prompt.trim() === '') {
    return NextResponse.json(
      { error: 'prompt must be a non-empty string' },
      { status: 400 },
    );
  }

  // ---------------------------------------------------------------------------
  // Step 1: Sign the request
  // ---------------------------------------------------------------------------
  let artifactB64: string;
  let signed: Awaited<ReturnType<typeof qodiqa.sign.sign>>;

  try {
    // payload.provider is not set here — /sign auto-resolves it to the
    // single enabled AI provider. With more than one provider configured,
    // /sign returns 400 PROVIDER_REQUIRED and payload.provider must be set
    // explicitly (e.g. payload: { provider: 'openai' }). See api.md#sign.
    signed = await qodiqa.sign.sign({
      request: {
        method: 'POST',
        path: '/ai/chat',
        body: { prompt, model },
      },
      payload: {
        userId,
        source: 'nextjs-app-router',
      },
      ttl: 60_000,
    });

    artifactB64 = Buffer.from(JSON.stringify(signed.artifact)).toString('base64');
  } catch (err) {
    if (err instanceof AuthenticationError) {
      return NextResponse.json(
        { error: 'QODIQA sign token is missing or invalid' },
        { status: 401 },
      );
    }
    if (err instanceof QodiqaError) {
      return NextResponse.json(
        { error: 'Failed to sign request', reason: err.message },
        { status: err.status ?? 500 },
      );
    }
    throw err;
  }

  // ---------------------------------------------------------------------------
  // Step 2: Execute AI chat with QODIQA enforcement
  // ---------------------------------------------------------------------------
  try {
    const chat = await qodiqa.chat.create(artifactB64, { prompt, model });

    if (chat.decision === 'BLOCK') {
      return NextResponse.json(
        {
          blocked: true,
          reason: chat.reason,
          requestId: chat.requestId,
          artifactId: signed.artifactId,
        },
        { status: 403 },
      );
    }

    return NextResponse.json(
      {
        text: chat.aiText ?? null,
        model: chat.model ?? null,
        tokenUsage: chat.tokenUsage ?? null,
        requestId: chat.requestId,
        artifactId: signed.artifactId,
        decision: chat.decision,
      },
      { status: 200 },
    );
  } catch (err) {
    if (err instanceof ValidationError) {
      return NextResponse.json(
        { error: err.message },
        { status: 400 },
      );
    }
    if (err instanceof QodiqaError) {
      return NextResponse.json(
        {
          error: 'QODIQA enforcement failed',
          reason: err.message,
          requestId: err.requestId,
        },
        { status: err.status ?? 500 },
      );
    }
    // Unknown/unexpected errors — let Next.js handle them
    throw err;
  }
}

// ---------------------------------------------------------------------------
// GET handler — health probe
// ---------------------------------------------------------------------------

export async function GET(): Promise<NextResponse> {
  try {
    const health = await qodiqa.healthCheck();
    return NextResponse.json(health);
  } catch (err) {
    return NextResponse.json(
      { error: 'QODIQA unreachable', details: err instanceof Error ? err.message : String(err) },
      { status: 503 },
    );
  }
}
