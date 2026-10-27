'use strict';

/**
 * AWS Signature Version 4 request signing - dependency-free, header-based.
 *
 *   sign({ method, url, headers, body, region, service, accessKeyId, secretAccessKey, sessionToken?, now? })
 *     -> { headers }   the headers to send: host, x-amz-date, x-amz-content-sha256, x-amz-security-token (if any), authorization, plus the caller's
 *
 * Implements the documented algorithm (canonical request -> string to sign -> HMAC chain). It is exercised against the signature examples published in the AWS Signature
 * Version 4 documentation and test suite (see __tests__/sigv4.test.js). Only the header form is supported (no presigned URLs); the canonical URI of non-S3 services is
 * the URI-encoded path with each segment encoded once more (double-encoding), as AWS specifies for every service but S3.
 */

const crypto = require('crypto');

const ALGORITHM = 'AWS4-HMAC-SHA256';
const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data, 'utf8').digest();

/** RFC 3986 encoding, as AWS requires (encodeURIComponent leaves !'()* alone). */
const awsEncode = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

function canonicalUri(pathname, service) {
  const p = pathname || '/';
  // `new URL` already percent-encodes the path once; non-S3 services encode each segment a second time, after normalising the path (redundant slashes collapsed, dot segments resolved).
  if (service === 's3') return p;
  const out = [];
  for (const seg of p.split('/')) { if (seg === '' || seg === '.') continue; if (seg === '..') out.pop(); else out.push(seg); }
  const normal = '/' + out.join('/') + (p.length > 1 && p.endsWith('/') && out.length ? '/' : '');
  return normal.split('/').map((seg) => awsEncode(seg)).join('/');
}

function canonicalQuery(searchParams) {
  const pairs = [];
  for (const [k, v] of searchParams) pairs.push([awsEncode(k), awsEncode(v)]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}

function amzDate(date) { return date.toISOString().replace(/[:-]|\.\d{3}/g, ''); }        // 20150830T123600Z

function signingKey(secretAccessKey, dateStamp, region, service) {
  return hmac(hmac(hmac(hmac('AWS4' + secretAccessKey, dateStamp), region), service), 'aws4_request');
}

function sign({ method = 'POST', url, headers = {}, body = '', region, service, accessKeyId, secretAccessKey, sessionToken = null, now = new Date(), signContentSha = true }) {
  if (!url || !region || !service || !accessKeyId || !secretAccessKey) throw new Error('sigv4: url, region, service, accessKeyId and secretAccessKey are required');
  const u = new URL(url);
  const payloadHash = sha256Hex(body === undefined || body === null ? '' : body);
  const date = amzDate(now);
  const dateStamp = date.slice(0, 8);

  const h = {};
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = String(v).trim().replace(/\s+/g, ' ');
  h.host = u.host;
  h['x-amz-date'] = date;
  if (signContentSha) h['x-amz-content-sha256'] = payloadHash;
  if (sessionToken) h['x-amz-security-token'] = sessionToken;

  const names = Object.keys(h).sort();
  const canonicalHeaders = names.map((n) => `${n}:${h[n]}\n`).join('');
  const signedHeaders = names.join(';');
  const canonicalRequest = [method.toUpperCase(), canonicalUri(u.pathname, service), canonicalQuery(u.searchParams), canonicalHeaders, signedHeaders, payloadHash].join('\n');

  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [ALGORITHM, date, scope, sha256Hex(canonicalRequest)].join('\n');
  const signature = crypto.createHmac('sha256', signingKey(secretAccessKey, dateStamp, region, service)).update(stringToSign, 'utf8').digest('hex');

  h.authorization = `${ALGORITHM} Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: h, canonicalRequest, stringToSign, signature, signedHeaders };
}

module.exports = { sign, signingKey, sha256Hex, awsEncode, amzDate, ALGORITHM };
