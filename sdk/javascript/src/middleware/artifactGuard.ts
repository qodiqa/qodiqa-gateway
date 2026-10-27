import { ArtifactVerifier } from '../verification/artifactVerifier.js';
import type { KeyProvider } from '../verification/keyProviders.js';
import { requestHash } from '../verification/domainHash.js';
import type { ArtifactVerificationResult } from '../verification/types.js';

/**
 * Middleware for an EXISTING Node application (Express, Connect, Fastify with middie, plain `http`): lets a request through only when it carries a QODIQA artifact that
 *   1. verifies offline against the trust bundle (genuine signature, known active key, not expired, not from the future), and
 *   2. is bound to THIS request: `payload.requestHash` equals the V1 request hash of (method, path without query, parsed JSON body).
 *
 * The artifact travels base64-encoded (JSON) in the `x-qodiqa-artifact` header, the way the gateway's own routes read it. Nothing is sent to the gateway: the guard needs only the public
 * keys. It does NOT consume the artifact's nonce (replay protection is the gateway's job, via POST /verify): pass `replayGuard` to add your own, e.g. a call to the gateway.
 *
 *   app.use(express.json());
 *   app.use('/protected', artifactGuard({ keys: new StaticKeyProvider(trustBundle) }));
 *   // downstream: req.qodiqa = { artifact, payload, keyId, result }
 *
 * A refusal is a JSON error, 401 for a missing/unreadable/invalid artifact and 403 for an artifact that is valid but bound to another request. Protocol V1 binding only.
 */

export interface GuardRequest {
  method?: string;
  path?: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  [key: string]: unknown;
}

export interface GuardResponse {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(chunk?: string): unknown;
}

export interface ArtifactGuardOptions {
  /** Trust bundle (StaticKeyProvider, RemoteKeyProvider, ...). */
  keys: KeyProvider;
  /** Header that carries the base64 artifact. Default `x-qodiqa-artifact`. */
  header?: string;
  /** Clock tolerance in ms for the verifier. Default 0. */
  clockToleranceMs?: number;
  /** Require the artifact to be bound to this request (default true). Turning it off only proves "some genuine artifact". */
  bindRequest?: boolean;
  /** The body as the signer saw it. Default: `req.body` (after your JSON parser), `{}` when absent. */
  getBody?: (req: GuardRequest) => unknown;
  /** The path as the signer saw it (no query). Default: the pathname of `originalUrl` (the full request target, also behind an Express mount point), else `url`, else `req.path`. */
  getPath?: (req: GuardRequest) => string;
  /** Extra check after verification (replay store, tenant allow-list ...); return false to refuse with 403 QODIQA_REPLAY_OR_POLICY. */
  replayGuard?: (info: GuardInfo, req: GuardRequest) => boolean | Promise<boolean>;
  /** Largest accepted header value in bytes. Default 16384. */
  maxHeaderBytes?: number;
  /** Test hook: the clock. */
  now?: () => number;
}

export interface GuardInfo {
  artifact: Record<string, unknown>;
  payload: Record<string, unknown>;
  keyId: string | null;
  result: ArtifactVerificationResult;
}

type Next = (err?: unknown) => void;

function send(res: GuardResponse, status: number, code: string, message: string): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(JSON.stringify({ status: 'error', error: { code, message } }));
}

function headerOf(req: GuardRequest, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

// The FULL path the signer saw. Express strips a mount point from `req.path` and `req.url` (app.use('/protected', guard) sees '/echo'), but `originalUrl` keeps the whole request target: prefer it.
function pathOf(req: GuardRequest): string {
  const raw = req.originalUrl ?? req.url;
  if (typeof raw === 'string' && raw) {
    try {
      return new URL(raw, 'http://localhost').pathname;
    } catch {
      /* fall through to req.path */
    }
  }
  return typeof req.path === 'string' && req.path ? req.path : '/';
}

/** The artifact-guard middleware: `(req, res, next)`. */
export function artifactGuard(options: ArtifactGuardOptions): (req: GuardRequest, res: GuardResponse, next: Next) => Promise<void> {
  if (!options || !options.keys) throw new TypeError('artifactGuard requires a `keys` KeyProvider');
  const header = (options.header ?? 'x-qodiqa-artifact').toLowerCase();
  const bind = options.bindRequest !== false;
  const maxBytes = options.maxHeaderBytes ?? 16384;
  const verifier = new ArtifactVerifier({ keys: options.keys, clockToleranceMs: options.clockToleranceMs ?? 0, ...(options.now ? { _now: options.now() } : {}) });

  return async function qodiqaArtifactGuard(req, res, next) {
    try {
      const raw = headerOf(req, header);
      if (!raw) return send(res, 401, 'QODIQA_ARTIFACT_REQUIRED', `The ${header} header is required.`);
      if (raw.length > maxBytes) return send(res, 401, 'QODIQA_ARTIFACT_INVALID', 'The artifact is too large.');
      let artifact: unknown;
      try {
        artifact = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
      } catch {
        return send(res, 401, 'QODIQA_ARTIFACT_INVALID', 'The artifact is not base64-encoded JSON.');
      }
      const verifierNow = options.now ? new ArtifactVerifier({ keys: options.keys, clockToleranceMs: options.clockToleranceMs ?? 0, _now: options.now() }) : verifier;
      const result = await verifierNow.verify(artifact);
      if (result.verificationStatus !== 'valid') {
        return send(res, 401, 'QODIQA_ARTIFACT_INVALID', `The artifact was refused (${result.failedStage ?? 'invalid'}).`);
      }
      const art = artifact as Record<string, unknown>;
      const payload = art.payload as Record<string, unknown>;
      if (bind) {
        const method = String(req.method ?? 'GET');
        const body = options.getBody ? options.getBody(req) : req.body;
        const path = options.getPath ? options.getPath(req) : pathOf(req);
        let expected: string;
        try {
          expected = requestHash(method, path, body === undefined || body === null ? {} : body);
        } catch {
          return send(res, 403, 'QODIQA_REQUEST_MISMATCH', 'The request cannot be bound to the artifact.');
        }
        const claimed = payload.requestHash;
        if (typeof claimed !== 'string' || claimed.length !== expected.length || !timingSafeEqualHex(claimed, expected)) {
          return send(res, 403, 'QODIQA_REQUEST_MISMATCH', 'The artifact was issued for a different request.');
        }
      }
      const info: GuardInfo = { artifact: art, payload, keyId: result.keyId, result };
      if (options.replayGuard && !(await options.replayGuard(info, req))) {
        return send(res, 403, 'QODIQA_REPLAY_OR_POLICY', 'The artifact was refused by the replay guard.');
      }
      (req as Record<string, unknown>).qodiqa = info;
      return next();
    } catch (err) {
      return next(err);
    }
  };
}

function timingSafeEqualHex(a: string, b: string): boolean {
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
