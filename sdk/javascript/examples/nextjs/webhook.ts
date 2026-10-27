/**
 * Next.js App Router webhook route — QODIQA signature verification
 *
 * Next.js App Router provides the raw body via request.bytes() (or .arrayBuffer()),
 * which is what we need for accurate signature verification.
 *
 * File: app/api/webhooks/qodiqa/route.ts
 */

import { NextRequest, NextResponse } from 'next/server';
import {
  verifyWebhookSignature,
  InvalidSignatureError,
  ExpiredSignatureError,
  MalformedSignatureError,
  InvalidTimestampError,
} from '@qodiqa/sdk';

const WEBHOOK_SECRET = process.env.QODIQA_WEBHOOK_SECRET!;

export async function POST(request: NextRequest): Promise<NextResponse> {
  const signature = request.headers.get('x-qodiqa-signature');
  const timestamp = request.headers.get('x-qodiqa-timestamp');
  if (!signature) {
    return NextResponse.json(
      { error: 'Missing X-QODIQA-Signature header' },
      { status: 400 },
    );
  }
  if (!timestamp) {
    return NextResponse.json(
      { error: 'Missing X-QODIQA-Timestamp header' },
      { status: 400 },
    );
  }

  // Capture the raw body as a Buffer before any parsing.
  const rawBody = Buffer.from(await request.arrayBuffer());

  try {
    verifyWebhookSignature({
      body: rawBody,
      signature,
      timestamp,
      secret: WEBHOOK_SECRET,
    });
  } catch (err) {
    if (err instanceof ExpiredSignatureError) {
      return NextResponse.json(
        { error: 'Webhook replay detected', detail: err.message },
        { status: 401 },
      );
    }
    if (
      err instanceof InvalidSignatureError ||
      err instanceof MalformedSignatureError ||
      err instanceof InvalidTimestampError
    ) {
      return NextResponse.json(
        { error: 'Invalid webhook signature', detail: err.message },
        { status: 401 },
      );
    }
    throw err; // unexpected — let Next.js error handling deal with it
  }

  // Signature verified — parse and process the event.
  const event = JSON.parse(rawBody.toString('utf8')) as {
    type: string;
    id: string;
    [key: string]: unknown;
  };

  console.log('Verified QODIQA webhook event:', event.type, event.id);

  // Route event.type to your own handler, e.g.:
  // switch (event.type) {
  //   case 'sign.created':  await handleSignCreated(event);  break;
  //   case 'verify.failed': await handleVerifyFailed(event); break;
  // }

  return NextResponse.json({ received: true }, { status: 200 });
}

// Disable Next.js body parsing so we receive raw bytes via request.arrayBuffer().
export const config = {
  api: {
    bodyParser: false,
  },
};
