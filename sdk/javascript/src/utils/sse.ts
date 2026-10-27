import { ServerError } from '../errors.js';

// ---------------------------------------------------------------------------
// SSE frame parsing
// ---------------------------------------------------------------------------
//
// API-10 remediation: QODIQA's server (src/streaming/
// streamEnforcer.js `_writeSSE()`) now emits native SSE framing — an
// `event:` line (matching the `data:` JSON payload's own `event` property)
// and an `id:` line ahead of every `data:` line, plus a `retry:` hint on the
// first frame. This is additive: the JSON payload shape is unchanged from
// before, kept for one deprecation cycle so this parser (and any other
// data:-only consumer) doesn't need to change to keep working.
//
// This parser deliberately keeps reading only the `data:` line(s) of each
// frame rather than switching to the native `event:`/`id:` fields as its
// primary source of truth — `extractPayload()` below already filters for
// lines starting with `data:` specifically (not "the whole frame"), so the
// new `event:`/`id:`/`retry:` lines are transparently ignored without any
// change needed here. `Last-Event-ID` reconnection and full multi-line
// `data:`/comment-line support remain out of scope: QODIQA's server doesn't
// support HTTP-level stream resumption, so implementing that half of the
// spec here would be unfaithful to the actual contract, not a robustness
// improvement.

const DATA_PREFIX = 'data:';
const DONE_SENTINEL = '[DONE]';

/**
 * Reads a `ReadableStream<Uint8Array>` of `data: <json>\n\n`-framed SSE
 * output and yields each frame's parsed JSON payload. Stops (without
 * yielding) when the `[DONE]` sentinel is read, or when the stream ends.
 *
 * Throws `ServerError` if a `data:` frame's payload is not `[DONE]` and not
 * valid JSON — a protocol violation, not a condition to silently skip.
 *
 * Returns (as the generator's return value, i.e. the value of a `yield*`
 * expression) `true` when the `[DONE]` sentinel was read and `false` when the
 * body ended without it — P15-03: the HTTP client turns the latter
 * into a `NetworkError`, because the server always writes `[DONE]` last, so a
 * body that ends without it was truncated in transit.
 */
export async function* parseSSEStream(
  body: ReadableStream<Uint8Array>,
): AsyncGenerator<unknown, boolean> {
  const reader = body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (value) buffer += decoder.decode(value, { stream: true });

      if (done) {
        buffer += decoder.decode();
        // A well-behaved stream always ends with `[DONE]` already consumed
        // out of the buffer below; any leftover non-blank content here means
        // the connection closed mid-frame (e.g. a network interruption).
        if (buffer.trim() !== '') {
          const payload = extractPayload(buffer);
          if (payload === DONE_SENTINEL) return true;
          if (payload !== null) {
            yield parsePayload(payload);
          }
        }
        return false;
      }

      let boundary: number;
      while ((boundary = buffer.indexOf('\n\n')) !== -1) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);

        const payload = extractPayload(frame);
        if (payload === null) continue; // blank frame between events — ignore
        if (payload === DONE_SENTINEL) return true;

        yield parsePayload(payload);
      }
    }
  } finally {
    reader.releaseLock();
  }
}

/** Extracts the payload string from a single SSE frame's `data:` line(s). */
function extractPayload(frame: string): string | null {
  const lines = frame.split('\n').filter((line) => line.startsWith(DATA_PREFIX));
  if (lines.length === 0) return null;
  // QODIQA never splits one event across multiple `data:` lines, but join
  // defensively per the SSE spec's own multi-line join rule rather than
  // silently dropping anything past the first line.
  return lines.map((line) => line.slice(DATA_PREFIX.length).trimStart()).join('\n');
}

function parsePayload(payload: string): unknown {
  try {
    return JSON.parse(payload);
  } catch {
    throw new ServerError(
      `Received a malformed SSE event from the server (not valid JSON, not "[DONE]"): ${payload.slice(0, 200)}`,
    );
  }
}
