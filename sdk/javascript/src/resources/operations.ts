import { BaseResource } from './base.js';
import { AuthenticationError, ValidationError } from '../errors.js';
import type { HttpClient } from '../http.js';
import type { AuthProvider } from '../auth.js';
import { OPERATIONS } from '../generated/operations.js';
import type { OperationArgs, OperationDescriptor, OperationMethods } from '../generated/operations.js';

/**
 * Operation-complete access to the HTTP contract: `client.operations.<operationId>(args)` for every documented operation, generated from docs/api/openapi.json
 * (scripts/sdk/generate-operations.js; `npm run sdk:check` fails on drift). The hand-written resources (`client.sign`, `client.chat`, ...) stay the typed, documented path for the
 * main flows; this layer is for everything else, with correct URLs, verbs and credentials and checked parameters, but request/response bodies typed as `unknown`.
 *
 *   await client.operations.getPolicyVersion({ path: { policyId: 'p1', v: 3 } });
 *   await client.operations.listAlerts();
 *   client.operations.call('streamAlerts')   // SSE operations return an async generator
 *
 * Credentials: `ops` operations use `apiKey`, `sign` operations use `signToken`, `none` send no credential, `optional` send `apiKey` when one is configured.
 */
export class OperationsResource extends BaseResource {
  constructor(http: HttpClient, auth: AuthProvider) {
    super(http, auth);
    for (const id of Object.keys(OPERATIONS)) {
      Object.defineProperty(this, id, {
        enumerable: true,
        value: (args?: OperationArgs) => this.call(id, args),
      });
    }
  }

  /** Every operation id this SDK version can call. */
  list(): readonly OperationDescriptor[] {
    return Object.values(OPERATIONS);
  }

  describe(id: string): OperationDescriptor {
    const d = OPERATIONS[id];
    if (!d) throw new ValidationError(`Unknown operation "${id}"`);
    return d;
  }

  /** Calls an operation by id. SSE operations return an AsyncGenerator, all others a Promise. */
  call(id: string, args: OperationArgs = {}): Promise<unknown> | AsyncGenerator<unknown> {
    const d = this.describe(id);
    const { path, query, headers } = this.prepare(d, args);
    const opts = {
      method: d.method,
      path,
      ...(Object.keys(query).length ? { query } : {}),
      headers,
      ...(args.body !== undefined ? { body: args.body } : {}),
      ...(args.timeout !== undefined ? { timeout: args.timeout } : {}),
      ...(args.signal ? { signal: args.signal } : {}),
      ...(d.response === 'binary' ? { responseType: 'binary' as const } : {}),
    };
    return d.response === 'sse' ? this.http.stream(opts) : this.http.request<unknown>(opts);
  }

  private prepare(d: OperationDescriptor, args: OperationArgs): { path: string; query: Record<string, string | number | boolean>; headers: Record<string, string> } {
    const given = args.path ?? {};
    for (const k of Object.keys(given)) if (!d.pathParams.includes(k)) throw new ValidationError(`${d.id}: unknown path parameter "${k}"`);
    const path = d.path.replace(/\{([^}]+)\}/g, (_m, name: string) => {
      const v = given[name];
      if (v === undefined || v === null || String(v) === '') throw new ValidationError(`${d.id}: path parameter "${name}" is required`);
      return encodeURIComponent(String(v));
    });
    const query: Record<string, string | number | boolean> = {};
    for (const [k, v] of Object.entries(args.query ?? {})) {
      if (!d.query.includes(k)) throw new ValidationError(`${d.id}: unknown query parameter "${k}"`);
      if (v !== undefined) query[k] = v;
    }
    for (const k of d.requiredQuery) if (query[k] === undefined) throw new ValidationError(`${d.id}: query parameter "${k}" is required`);
    if (d.body === 'none' && args.body !== undefined) throw new ValidationError(`${d.id}: this operation takes no request body`);
    if (d.bodyRequired && args.body === undefined) throw new ValidationError(`${d.id}: a request body is required`);
    if (d.body === 'form' || d.body === 'raw') throw new ValidationError(`${d.id}: ${d.body} request bodies are not supported by the generic client`);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(args.headers ?? {})) {
      if (!d.headers.some((h) => h.toLowerCase() === k.toLowerCase())) throw new ValidationError(`${d.id}: unknown header "${k}"`);
      headers[k] = v;
    }
    Object.assign(headers, this.credential(d));
    return { path, query, headers };
  }

  private credential(d: OperationDescriptor): Record<string, string> {
    switch (d.auth) {
      case 'none': return {};
      case 'sign': return this.auth.getSignTokenHeader();
      case 'optional':
        try { return this.auth.getAuthHeader(); } catch (e) { if (e instanceof AuthenticationError) return {}; throw e; }
      default: return this.auth.getAuthHeader();
    }
  }
}

// `client.operations.<operationId>(...)` is typed by intersecting the resource with the generated method table.
export type OperationsClient = OperationsResource & OperationMethods;
