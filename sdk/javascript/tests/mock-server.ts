import * as http from 'http';
import type { IncomingMessage, ServerResponse } from 'http';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MockResponse {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

interface CallLogEntry {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
}

// ---------------------------------------------------------------------------
// SSE streaming mocks
// ---------------------------------------------------------------------------

/** Wraps a raw string so `mockStream()` writes it verbatim as a `data:` payload — used to test malformed-event handling without JSON.stringify escaping it into valid JSON. */
export class RawFrame {
  constructor(public readonly text: string) {}
}

/** Sentinel marking where the server writes the raw `data: [DONE]\n\n` terminator, distinct from any JSON-serializable frame value. */
export const DONE_FRAME: unique symbol = Symbol('DONE_FRAME');

export interface MockStreamConfig {
  status?: number;
  headers?: Record<string, string>;
  /**
   * Each item becomes one `data: <payload>\n\n` frame, written in order.
   * A plain value is JSON-serialized; `RawFrame` is written verbatim
   * (e.g. to simulate a malformed event); `DONE_FRAME` writes the literal
   * `[DONE]` sentinel exactly like the real server's `_writeSSE(res, '[DONE]')`.
   */
  frames: Array<unknown | RawFrame | typeof DONE_FRAME>;
  /** Delay in ms before writing each frame. Default 0 (all frames flushed back-to-back). */
  frameDelayMs?: number;
  /** If true, destroys the socket after the last frame instead of calling `res.end()` — simulates a dropped connection mid-stream. */
  interrupt?: boolean;
  /** If true, sends headers and then never writes anything — simulates a hung connection, for exercising client-side timeouts. */
  hang?: boolean;
}

// ---------------------------------------------------------------------------
// MockServer
// ---------------------------------------------------------------------------

/**
 * A lightweight HTTP mock server built on Node's built-in `http` module.
 * No external dependencies required.
 *
 * Usage:
 * ```ts
 * const server = new MockServer();
 * const baseUrl = await server.start();
 * server.mock('GET', '/health', { status: 200, body: { status: 'ok', uptime: 42 } });
 * // ... run tests ...
 * await server.stop();
 * ```
 */
export class MockServer {
  private routes: Map<string, MockResponse> = new Map();
  private sequenceRoutes: Map<string, MockResponse[]> = new Map();
  private sseRoutes: Map<string, MockStreamConfig> = new Map();
  private callLog: CallLogEntry[] = [];
  private server: http.Server;

  constructor() {
    this.server = http.createServer(
      (req: IncomingMessage, res: ServerResponse) => {
        this.handleRequest(req, res).catch((err: unknown) => {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({ error: String(err instanceof Error ? err.message : err) }),
          );
        });
      },
    );
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Register a mock response for a given HTTP method + path combination.
   * Later calls with the same key overwrite earlier ones.
   */
  mock(method: string, path: string, response: MockResponse): void {
    const key = this.routeKey(method.toUpperCase(), path);
    this.routes.set(key, response);
  }

  /**
   * Start listening on a random available port.
   *
   * @returns The base URL to pass to `QodiqaClient`, e.g. `http://127.0.0.1:54321`
   */
  async start(): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server.address();
        if (!addr || typeof addr === 'string') {
          reject(new Error('Could not determine server address'));
          return;
        }
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });
  }

  /** Stop the server and release the port. */
  async stop(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  /**
   * Register a sequence of responses for a route, served in FIFO order.
   * The last response is kept and repeated once the queue is exhausted.
   */
  mockSequence(method: string, path: string, responses: MockResponse[]): void {
    if (responses.length === 0) throw new Error('responses must not be empty');
    const key = this.routeKey(method.toUpperCase(), path);
    this.sequenceRoutes.set(key, [...responses]);
  }

  /**
   * Register an SSE streaming response for a route — writes
   * `Content-Type: text/event-stream` and each of `config.frames` as its
   * own `data: <payload>\n\n` frame (see `MockStreamConfig`).
   */
  mockStream(method: string, path: string, config: MockStreamConfig): void {
    const key = this.routeKey(method.toUpperCase(), path);
    this.sseRoutes.set(key, config);
  }

  /** Clear all registered routes and call logs. */
  reset(): void {
    this.routes.clear();
    this.sequenceRoutes.clear();
    this.sseRoutes.clear();
    this.callLog = [];
  }

  /** Returns a snapshot of all requests the mock server has received. */
  getCallLog(): CallLogEntry[] {
    return [...this.callLog];
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private routeKey(method: string, path: string): string {
    // Strip query string for route matching.
    // Use a tab character as separator so colons in path params don't confuse splits.
    const cleanPath = path.split('?')[0] as string;
    return `${method}\t${cleanPath}`;
  }

  private async handleRequest(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const method = (req.method ?? 'GET').toUpperCase();
    const url = req.url ?? '/';

    // Collect request body
    let rawBody = '';
    for await (const chunk of req) {
      rawBody += chunk;
    }

    let parsedBody: unknown = null;
    if (rawBody) {
      try {
        parsedBody = JSON.parse(rawBody);
      } catch {
        parsedBody = rawBody;
      }
    }

    // Log the incoming request
    const incomingHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (v !== undefined) {
        incomingHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
      }
    }

    this.callLog.push({
      method,
      path: url,
      body: parsedBody,
      headers: incomingHeaders,
    });

    const sseConfig = this.findSSEMock(method, url);
    if (sseConfig) {
      await this.writeStreamResponse(res, sseConfig);
      return;
    }

    const mock = this.findMockResponse(method, url);

    if (!mock) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          decision: 'BLOCK',
          reason: 'NOT_FOUND',
          details: { message: `No mock registered for ${method} ${url}` },
          requestId: 'mock-not-found',
        }),
      );
      return;
    }

    this.writeResponse(res, mock);
  }

  private findSSEMock(method: string, url: string): MockStreamConfig | undefined {
    const cleanUrl = url.split('?')[0] ?? '';
    const exactKey = this.routeKey(method, url);
    if (this.sseRoutes.has(exactKey)) return this.sseRoutes.get(exactKey);

    for (const [routeKey, config] of this.sseRoutes.entries()) {
      const tabIdx = routeKey.indexOf('\t');
      const routeMethod = routeKey.slice(0, tabIdx);
      const routePath = routeKey.slice(tabIdx + 1);
      if (routeMethod !== method) continue;
      if (this.pathMatches(cleanUrl, routePath)) return config;
    }
    return undefined;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private async writeStreamResponse(
    res: ServerResponse,
    config: MockStreamConfig,
  ): Promise<void> {
    res.writeHead(config.status ?? 200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      ...config.headers,
    });
    // flushHeaders isn't on the ServerResponse type in older @types/node but
    // exists at runtime; the writeHead above already flushes for chunked
    // responses with no body buffering, so no extra call is required here.

    if (config.hang) {
      // Deliberately never write or end — simulates a connection the server
      // accepted but never sent SSE data on, for exercising client timeouts.
      return;
    }

    // API-10 remediation: mirrors the real server's native SSE framing
    // (src/streaming/streamEnforcer.js `_writeSSE()`) — an `event:` line
    // derived from the frame's own `event` property, plus a monotonically
    // increasing `id:` line — ahead of `data:`, so this mock is an honest
    // regression fixture for the actual current wire format, not the
    // pre-API-10 data-only shape.
    let seq = 0;
    for (const frame of config.frames) {
      if (config.frameDelayMs) await this.sleep(config.frameDelayMs);
      res.write(this.buildSSEFrame(frame, seq++));
    }

    if (config.interrupt) {
      // Simulates a dropped connection mid-stream: destroy the socket
      // without a clean SSE termination ([DONE] was never sent).
      res.socket?.destroy();
      return;
    }

    res.end();
  }

  private serializeFrame(frame: unknown): string {
    if (frame === DONE_FRAME) return '[DONE]';
    if (frame instanceof RawFrame) return frame.text;
    return JSON.stringify(frame);
  }

  private buildSSEFrame(frame: unknown, seq: number): string {
    let out = '';
    if (
      frame !== DONE_FRAME &&
      !(frame instanceof RawFrame) &&
      frame !== null &&
      typeof frame === 'object' &&
      typeof (frame as { event?: unknown }).event === 'string'
    ) {
      out += `event: ${(frame as { event: string }).event}\n`;
    }
    out += `id: mock:${seq}\n`;
    out += `data: ${this.serializeFrame(frame)}\n\n`;
    return out;
  }

  private findMockResponse(method: string, url: string): MockResponse | undefined {
    const cleanUrl = url.split('?')[0] ?? '';

    // Sequence routes take priority — serve next in queue, keep last when exhausted.
    for (const [routeKey, queue] of this.sequenceRoutes.entries()) {
      if (queue.length === 0) continue;
      const tabIdx = routeKey.indexOf('\t');
      const routeMethod = routeKey.slice(0, tabIdx);
      const routePath = routeKey.slice(tabIdx + 1);
      if (routeMethod !== method) continue;
      if (cleanUrl !== routePath && !this.pathMatches(cleanUrl, routePath)) continue;
      return queue.length > 1 ? queue.shift()! : queue[0]!;
    }

    // Exact match in static routes.
    const exactKey = this.routeKey(method, url);
    if (this.routes.has(exactKey)) return this.routes.get(exactKey);

    // Param-pattern match in static routes.
    for (const [routeKey, mock] of this.routes.entries()) {
      const tabIdx = routeKey.indexOf('\t');
      const routeMethod = routeKey.slice(0, tabIdx);
      const routePath = routeKey.slice(tabIdx + 1);
      if (routeMethod !== method) continue;
      if (this.pathMatches(cleanUrl, routePath)) return mock;
    }

    return undefined;
  }

  private writeResponse(res: ServerResponse, mock: MockResponse): void {
    const responseHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      ...mock.headers,
    };

    res.writeHead(mock.status, responseHeaders);
    res.end(JSON.stringify(mock.body));
  }

  /**
   * Very simple path matching that handles Express-style `:param` segments.
   * e.g. routePath `/audit/:id` matches requestPath `/audit/abc123`
   */
  private pathMatches(requestPath: string, routePath: string): boolean {
    const reqParts = requestPath.split('/').filter(Boolean);
    const routeParts = routePath.split('/').filter(Boolean);

    if (reqParts.length !== routeParts.length) return false;

    for (let i = 0; i < routeParts.length; i++) {
      const rp = routeParts[i] as string;
      const ep = reqParts[i] as string;
      if (rp.startsWith(':')) continue; // wildcard segment
      if (rp !== ep) return false;
    }

    return true;
  }
}
