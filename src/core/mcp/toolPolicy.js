'use strict';

/**
 * Per-tool constraints on the ARGUMENTS of a call: which paths, hosts, SQL operations and commands a tool of a sensitive class may touch, enforced at the
 * gateway - before the artifact is issued and again before the call - not left to the MCP server.
 *
 *   policy.constraints = [ { arg: '/path', kind: 'path_prefix', values: ['/data/public'] },
 *                          { arg: '/url', kind: 'url_host', values: ['api.example.com', '*.cdn.example.com:8443'] },
 *                          { arg: '/sql', kind: 'sql_operations', values: ['SELECT'] },
 *                          { arg: '/command', kind: 'command_allowlist', values: ['git status', 'ls -l'] } ]
 *
 * `arg` is a JSON pointer into the arguments; the value there must be a string (a missing or non-string value is refused - fail closed).
 * DEFAULT DENY: a tool of class file / database / external_api / command is callable only if its policy carries at least one constraint of the matching kind
 * (`ACTION_POLICY_REQUIRED`); a constraint that is not met is `ACTION_POLICY_DENIED`. The checks are deliberately conservative text checks - a path with a `..` segment
 * or an encoded separator is refused, SQL with a second statement is refused, a command with a shell metacharacter is refused unless it is exactly an allowed line - and they
 * do not replace the MCP server's own sandboxing (a symlink inside an allowed directory is the server's to resolve).
 */

const path = require('path');
const net = require('net');
const { blockedAddressReason } = require('../../../services/providers/ssrf');

const REQUIRED_KIND = Object.freeze({ file: 'path_prefix', database: 'sql_operations', external_api: 'url_host', command: 'command_allowlist' });
const KINDS = Object.freeze(['path_prefix', 'url_host', 'sql_operations', 'command_allowlist']);
const SQL_OPS = Object.freeze(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'EXPLAIN', 'SHOW', 'WITH']);
const MAX_CONSTRAINTS = 32;
const MAX_VALUES = 64;
const MAX_VALUE_LEN = 512;

class PolicyError extends Error { constructor(code, detail) { super(detail ? `${code}: ${detail}` : code); this.name = 'ToolError'; this.code = code; this.status = 400; } }

const POINTER_RE = /^(\/[^/~]*(~[01][^/~]*)*)+$/;
function pointerGet(obj, pointer) {
  let cur = obj;
  for (const raw of pointer.split('/').slice(1)) {
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (cur === null || typeof cur !== 'object' || !Object.prototype.hasOwnProperty.call(cur, key)) return { found: false };
    cur = cur[key];
  }
  return { found: true, value: cur };
}

/** Validate a policy.constraints value (registration time). @returns the normalised array */
function assertValidConstraints(constraints) {
  if (constraints === undefined) return undefined;
  if (!Array.isArray(constraints) || constraints.length > MAX_CONSTRAINTS) throw new PolicyError('INVALID_POLICY', `constraints is an array of at most ${MAX_CONSTRAINTS}`);
  return constraints.map((c) => {
    if (!c || typeof c !== 'object' || Array.isArray(c) || Object.keys(c).some((k) => !['arg', 'kind', 'values'].includes(k))) throw new PolicyError('INVALID_POLICY', 'a constraint is exactly { arg, kind, values }');
    if (typeof c.arg !== 'string' || !POINTER_RE.test(c.arg) || c.arg.length > 200) throw new PolicyError('INVALID_POLICY', 'arg is a JSON pointer such as /path');
    if (!KINDS.includes(c.kind)) throw new PolicyError('INVALID_POLICY', `kind is one of ${KINDS.join(', ')}`);
    if (!Array.isArray(c.values) || !c.values.length || c.values.length > MAX_VALUES || c.values.some((v) => typeof v !== 'string' || !v || v.length > MAX_VALUE_LEN || /[\u0000]/.test(v))) throw new PolicyError('INVALID_POLICY', `values is 1..${MAX_VALUES} non-empty strings`);
    const values = [...new Set(c.values)];
    if (c.kind === 'sql_operations') for (const v of values) if (!SQL_OPS.includes(v)) throw new PolicyError('INVALID_POLICY', `sql operation ${v}: one of ${SQL_OPS.join(', ')}`);
    if (c.kind === 'path_prefix') for (const v of values) if (normaliseAllowedPath(v) === null) throw new PolicyError('INVALID_POLICY', `path prefix ${v} must be absolute with no .. segment`);
    if (c.kind === 'url_host') for (const v of values) if (!/^(\*\.)?[A-Za-z0-9.-]+(:\d{1,5})?$/.test(v) && !net.isIP(v.replace(/:\d+$/, ''))) throw new PolicyError('INVALID_POLICY', `host ${v}`);
    return { arg: c.arg, kind: c.kind, values };
  });
}

function normaliseAllowedPath(p) {
  const s = p.replace(/\\/g, '/');
  if (!/^(\/|[A-Za-z]:\/)/.test(s) || s.split('/').includes('..')) return null;
  const n = path.posix.normalize(s);
  return n.length > 1 ? n.replace(/\/+$/, '') : n;
}

function checkPath(value, prefixes) {
  if (/%[0-9a-fA-F]{2}/.test(value)) { let d; try { d = decodeURIComponent(value); } catch { return 'undecodable path'; } if (d !== value) return 'an encoded path is refused'; }
  if (/\u0000/.test(value)) return 'NUL in path';
  const s = value.replace(/\\/g, '/');
  if (s.split('/').includes('..')) return 'a .. segment';
  const n = normaliseAllowedPath(s);
  if (n === null) return 'not an absolute path';
  const ok = prefixes.some((p) => { const q = normaliseAllowedPath(p); return q !== null && (n === q || n.startsWith(q === '/' ? '/' : `${q}/`)); });
  return ok ? null : 'outside the allowed directories';
}

function checkUrlHost(value, hosts) {
  let u; try { u = new URL(value); } catch { return 'not a URL'; }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return 'protocol';
  if (u.username || u.password) return 'credentials in the URL';
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  const isIp = net.isIP(host) !== 0;
  if (isIp && blockedAddressReason(host, { blockPrivate: true, blockLoopback: true })) return 'a private or reserved address';
  const ok = hosts.some((h) => {
    const [hh, hp] = h.toLowerCase().split(/:(?=\d+$)/);
    if (hp && hp !== port) return false;
    if (hh.startsWith('*.')) return host.endsWith(hh.slice(1)) && host.length > hh.length - 1;
    return host === hh;
  });
  return ok ? null : 'host not allowed';
}

function stripSql(sql) {
  let out = ''; let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    if (c === '-' && sql[i + 1] === '-') { while (i < sql.length && sql[i] !== '\n') i++; out += ' '; continue; }
    if (c === '/' && sql[i + 1] === '*') { const e = sql.indexOf('*/', i + 2); if (e < 0) return null; i = e + 2; out += ' '; continue; }
    if (c === "'" || c === '"') { const q = c; i++; while (i < sql.length && !(sql[i] === q && sql[i + 1] !== q)) i += sql[i] === q ? 2 : 1; if (i >= sql.length) return null; i++; out += ' '; continue; }
    if (c === '$') { const m = /^\$[A-Za-z_]*\$/.exec(sql.slice(i)); if (m) { const e = sql.indexOf(m[0], i + m[0].length); if (e < 0) return null; i = e + m[0].length; out += ' '; continue; } }
    out += c; i++;
  }
  return out;
}

function checkSql(value, ops) {
  const s = stripSql(value);
  if (s === null) return 'unterminated string or comment';
  const t = s.trim().replace(/;\s*$/, '');
  if (t.includes(';')) return 'more than one statement';
  const m = /^\(?\s*([A-Za-z]+)/.exec(t);
  const op = m ? m[1].toUpperCase() : '';
  if (!ops.includes(op)) return `operation ${op || '?'} not allowed`;
  if (op === 'SELECT' && /\bINTO\b/i.test(t) && !ops.includes('INSERT')) return 'SELECT ... INTO writes';
  if ((op === 'WITH' || op === 'EXPLAIN') && /\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT)\b/i.test(t) && !ops.includes('INSERT') && !ops.includes('UPDATE') && !ops.includes('DELETE')) return 'a write inside a read statement';
  return null;
}

function checkCommand(value, allowed) {
  if (allowed.includes(value)) return null;
  return /[;&|`$<>()\n\r\\{}]/.test(value) ? 'a shell metacharacter in a command that is not on the allowlist' : 'command not on the allowlist';
}

const CHECKS = { path_prefix: checkPath, url_host: checkUrlHost, sql_operations: checkSql, command_allowlist: checkCommand };

/** Does this tool's policy permit calling it at all? (default deny for the sensitive classes) */
function requirementProblem(tool) {
  const need = REQUIRED_KIND[tool.actionClass];
  if (!need) return null;
  const cs = (tool.policy && tool.policy.constraints) || [];
  return cs.some((c) => c.kind === need) ? null : { code: 'ACTION_POLICY_REQUIRED', detail: `a ${tool.actionClass} tool needs a ${need} constraint` };
}

/** @returns {{ ok: true } | { ok: false, code: 'ACTION_POLICY_REQUIRED'|'ACTION_POLICY_DENIED', detail: string }} */
function check(tool, args) {
  const req = requirementProblem(tool);
  if (req) return { ok: false, ...req };
  for (const c of (tool.policy && tool.policy.constraints) || []) {
    const v = pointerGet(args, c.arg);
    if (!v.found || typeof v.value !== 'string') return { ok: false, code: 'ACTION_POLICY_DENIED', detail: `${c.arg}: missing or not a string` };
    const problem = CHECKS[c.kind](v.value, c.values);
    if (problem) return { ok: false, code: 'ACTION_POLICY_DENIED', detail: `${c.arg}: ${problem}` };
  }
  return { ok: true };
}

module.exports = { REQUIRED_KIND, KINDS, SQL_OPS, PolicyError, assertValidConstraints, requirementProblem, check, pointerGet };
