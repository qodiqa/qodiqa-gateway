#!/usr/bin/env node
'use strict';

/**
 * Fail-closed runtime preflight for every gate run.
 *
 * Both the 2026-08-22 and 2026-09-05 independent audits lost their runtime
 * half to environment state discovered late (Redis down, PG migrations
 * behind, Ollama unreachable, a production keystore path pointed inside the
 * repo) -- this script checks all of that up front, once, before any gate
 * runs, and fails loudly with a reason list instead of letting a gate fail
 * confusingly deep inside its own run.
 *
 * Checks: Redis PING, PostgreSQL migration version (qodiqa_migrations vs.
 * the migrations directory's own file count), Ollama /api/tags, the
 * production keystore-path invariant (QODIQA_KEYS_PATH must resolve outside
 * the repo tree when NODE_ENV=production), and free RAM (CLAUDE.md's
 * documented 6 GB pre-flight floor).
 *
 * No new dependencies -- uses only Node built-ins plus `pg`/`redis`, both
 * already project dependencies (same reuse as,
 * whose Redis/Ollama probe patterns this script mirrors exactly, including
 * the reconnectStrategy:false fix for node-redis's default infinite retry).
 *
 * Usage: node scripts/preflight-runtime.js   (exit 0 = all checks pass;
 *   exit 1 = one or more failed, reasons printed to stderr and stdout)
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..');
require('dotenv').config({ path: path.join(REPO_ROOT, '.env') });

const MIGRATIONS_DIR = path.join(REPO_ROOT, 'src', 'infra', 'postgres', 'migrations');
const MIN_FREE_RAM_GB = 6; // CLAUDE.md's documented pre-flight floor (48 GB machine)

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ── Redis ────────────────────────────────────────────────────────────────────
async function checkRedis() {
  let createClient;
  try {
    ({ createClient } = require('redis'));
  } catch (err) {
    return { ok: false, reason: `redis module unavailable: ${err.message}` };
  }
  const client = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    socket: { connectTimeout: 2000, reconnectStrategy: false },
  });
  client.on('error', () => {
    // Surfaced via the catch below. node-redis v4 retries forever by default
    // without reconnectStrategy: false, which would hang this one-shot check
    //.
  });
  try {
    await withTimeout(client.connect(), 3000, 'redis connect');
    await withTimeout(client.ping(), 2000, 'redis ping');
    await client.quit();
    return { ok: true };
  } catch (err) {
    try { client.destroy(); } catch { /* already closed / never connected */ }
    // node-redis's connect() rejects with an AggregateError whose own
    // .message is empty (the real detail lives in .code and .errors[]) --
    // surface all three so "unknown error" never hides a real ECONNREFUSED.
    const detail = err.message || (err.errors || []).map((e) => e.message).join('; ') || err.code || 'unknown error';
    return { ok: false, reason: `Redis unreachable: ${detail}` };
  }
}

// ── PostgreSQL migration version ────────────────────────────────────────────
async function checkPostgresMigrations() {
  let Client;
  try {
    ({ Client } = require('pg'));
  } catch (err) {
    return { ok: false, reason: `pg module unavailable: ${err.message}` };
  }

  let expected;
  try {
    expected = fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql')).length;
  } catch (err) {
    return { ok: false, reason: `cannot read migrations directory ${MIGRATIONS_DIR}: ${err.message}` };
  }

  const client = new Client({
    host: process.env.QODIQA_PG_HOST || 'localhost',
    port: Number(process.env.QODIQA_PG_PORT) || 5432,
    user: process.env.QODIQA_PG_USER,
    password: process.env.QODIQA_PG_PASSWORD,
    database: process.env.QODIQA_PG_DATABASE || 'qodiqa',
    connectionTimeoutMillis: 2000,
  });
  try {
    await withTimeout(client.connect(), 3000, 'postgres connect');
    const res = await withTimeout(client.query('SELECT max(version) AS v FROM qodiqa_migrations'), 2000, 'postgres query');
    await client.end();
    const applied = Number(res.rows[0] && res.rows[0].v);
    if (!Number.isInteger(applied)) {
      return { ok: false, reason: 'qodiqa_migrations.max(version) did not return an integer' };
    }
    if (applied < expected) {
      return { ok: false, reason: `PostgreSQL migrations behind: applied ${applied}, expected ${expected} (${MIGRATIONS_DIR} has ${expected} .sql files)` };
    }
    return { ok: true, applied, expected };
  } catch (err) {
    try { client.end(); } catch { /* already closed / never connected */ }
    return { ok: false, reason: `PostgreSQL unreachable or migration check failed: ${err.message}` };
  }
}

// ── Ollama ───────────────────────────────────────────────────────────────────
async function checkOllama() {
  // Not LOCAL_BASE_URL (.env) -- that is the OpenAI-compatible '.../v1' path
  // the provider adapter uses, not Ollama's native API root /api/tags hangs
  // off.
  const base = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
  try {
    const res = await fetch(`${base}/api/tags`, { signal: AbortSignal.timeout(2000) });
    if (!res.ok) return { ok: false, reason: `Ollama returned HTTP ${res.status} at ${base}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: `Ollama unreachable at ${base}: ${err.message}` };
  }
}

// ── Production keystore-path invariant ──────────────────────────────────────
function checkKeystorePath() {
  if (process.env.NODE_ENV !== 'production') {
    return { ok: true, skipped: 'NODE_ENV is not production' };
  }
  const keysPath = process.env.QODIQA_KEYS_PATH;
  if (!keysPath) {
    return { ok: false, reason: 'QODIQA_KEYS_PATH is not set (required outside the repo in production)' };
  }
  const resolved = path.resolve(keysPath);
  const rel = path.relative(REPO_ROOT, resolved);
  if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) {
    return { ok: false, reason: `QODIQA_KEYS_PATH (${resolved}) resolves inside the repo tree -- must be outside in production` };
  }
  return { ok: true };
}

// ── Free RAM ─────────────────────────────────────────────────────────────────
function checkFreeRam() {
  const freeGb = os.freemem() / 1024 / 1024 / 1024;
  if (freeGb < MIN_FREE_RAM_GB) {
    return { ok: false, reason: `Free RAM ${freeGb.toFixed(1)} GB is below the ${MIN_FREE_RAM_GB} GB pre-flight floor` };
  }
  return { ok: true, freeGb: Number(freeGb.toFixed(1)) };
}

async function main() {
  const results = {
    redis: await checkRedis(),
    postgresMigrations: await checkPostgresMigrations(),
    ollama: await checkOllama(),
    keystorePath: checkKeystorePath(),
    freeRam: checkFreeRam(),
  };

  const failures = Object.entries(results).filter(([, r]) => !r.ok);

  console.log(JSON.stringify(results, null, 2));

  if (failures.length > 0) {
    console.error('');
    console.error('PREFLIGHT FAILED:');
    for (const [name, r] of failures) {
      console.error(`  - ${name}: ${r.reason}`);
    }
    process.exitCode = 1;
  } else {
    console.error('');
    console.error('PREFLIGHT PASSED: all checks green.');
  }
}

if (require.main === module) {
  main();
}

module.exports = { checkRedis, checkPostgresMigrations, checkOllama, checkKeystorePath, checkFreeRam };
