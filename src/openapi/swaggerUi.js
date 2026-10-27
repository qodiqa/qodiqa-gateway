'use strict';

/**
 * Swagger UI — OpenAPI Component #42
 *
 * Generates the HTML page that hosts the Swagger UI explorer.
 *
 *the swagger-ui-dist assets are SELF-HOSTED. They used to load
 * from unpkg with SRI, plus an inline initializer — and the gateway's own HTML CSP (`script-src 'self'`, PORTAL_CSP)
 * blocked every one of them, so /docs rendered an empty page in a real browser (verified in Chromium 2026-10-05: six CSP
 * violations, `SwaggerUIBundle` undefined). Now the three assets and the favicons are served by this process from
 * src/openapi/vendor/swagger-ui-dist-<version>/ (the npm-registry tarball's bytes, Apache-2.0, LICENSE + NOTICE kept
 * beside them; .gitattributes marks the directory -text so a clone cannot rewrite the bytes), each script/stylesheet
 * still carries its pinned sha384 integrity, and the initializer is a same-origin script configured through data-
 * attributes. The page therefore works under the unchanged CSP — no CSP was loosened, no external origin is contacted.
 *
 * The spec is loaded from the /openapi.json endpoint served by the same process,
 * so the UI always reflects the live generated spec.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SWAGGER_UI_VERSION = '5.17.14';
const VENDOR_DIR = path.join(__dirname, 'vendor', `swagger-ui-dist-${SWAGGER_UI_VERSION}`);

// Subresource Integrity for every script and stylesheet. Hashes are of swagger-ui-dist@5.17.14 as published
// on the npm registry — the vendored files must hash to exactly these
// (openapi.test.js checks the bytes on disk; a mismatch means the vendored copy was altered). Changing
// SWAGGER_UI_VERSION requires re-vendoring and recomputing all three:
//   openssl dgst -sha384 -binary <file> | openssl base64 -A
const SRI = Object.freeze({
  'swagger-ui.css':                  'sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn',
  'swagger-ui-bundle.js':            'sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep',
  'swagger-ui-standalone-preset.js': 'sha384-2YH8WDRaj7V2OqU/trsmzSagmk/E2SutiCsGkdgoQwC9pNUJV1u/141DHB6jgs8t',
});

// The same-origin initializer (was an inline <script>, which `script-src 'self'` refuses). Configuration travels in
// data- attributes on #swagger-ui, so the script is static and gets its own pinned integrity hash.
const INITIALIZER_JS = `'use strict';
window.addEventListener('load', function () {
  var el = document.getElementById('swagger-ui');
  window.ui = SwaggerUIBundle({
    url:          el.getAttribute('data-spec-url'),
    dom_id:       '#swagger-ui',
    presets:      [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout:       'StandaloneLayout',
    deepLinking:  true,
    displayOperationId: false,
    defaultModelsExpandDepth: 1,
    defaultModelExpandDepth:  2,
    docExpansion:  'list',
    filter:        true,
    tryItOutEnabled: true,
    persistAuthorization: true,
    requestInterceptor: function (req) {
      // Attach x-request-id for traceability when using Try-It-Out
      req.headers['x-request-id'] = 'swagger-ui-' + Date.now().toString(36);
      return req;
    },
  });
});
`;
const sri = (buf) => `sha384-${crypto.createHash('sha384').update(buf).digest('base64')}`;
const INITIALIZER_SRI = sri(Buffer.from(INITIALIZER_JS, 'utf8'));

// Every file the docs page may load, by its public name. Nothing outside this allowlist is ever served from the
// vendor directory (the route resolves names only through getSwaggerAsset, never a path).
const ASSETS = Object.freeze({
  'swagger-ui.css':                  { type: 'text/css; charset=utf-8',               file: 'swagger-ui.css' },
  'swagger-ui-bundle.js':            { type: 'application/javascript; charset=utf-8', file: 'swagger-ui-bundle.js' },
  'swagger-ui-standalone-preset.js': { type: 'application/javascript; charset=utf-8', file: 'swagger-ui-standalone-preset.js' },
  'favicon-32x32.png':               { type: 'image/png',                             file: 'favicon-32x32.png' },
  'favicon-16x16.png':               { type: 'image/png',                             file: 'favicon-16x16.png' },
  'swagger-initializer.js':          { type: 'application/javascript; charset=utf-8', body: Buffer.from(INITIALIZER_JS, 'utf8') },
});
const _cache = new Map();
/** @returns {{ type: string, body: Buffer } | null} the allowlisted asset (read once), or null for any other name */
function getSwaggerAsset(name) {
  if (!Object.prototype.hasOwnProperty.call(ASSETS, name)) return null;
  if (!_cache.has(name)) {
    const a = ASSETS[name];
    _cache.set(name, { type: a.type, body: a.body || fs.readFileSync(path.join(VENDOR_DIR, a.file)) });
  }
  return _cache.get(name);
}

/**
 * Generate the full HTML document for the Swagger UI page.
 *
 * @param {object} [options]
 * @param {string} [options.specUrl]   — URL the UI fetches the spec from (default: /openapi.json)
 * @param {string} [options.title]     — HTML <title> (default: 'QODIQA API Docs')
 * @param {string} [options.basePath]  — base path prefix (default: '')
 * @param {string} [options.assetsPath] — where this process serves the assets (default: '/docs/assets')
 * @returns {string}  Complete HTML document
 */
function renderSwaggerUiHtml(options) {
  const specUrl  = (options && options.specUrl)  || '/openapi.json';
  const title    = (options && options.title)    || 'QODIQA API Reference';
  const basePath = (options && options.basePath) || '';
  const A        = basePath + ((options && options.assetsPath) || '/docs/assets');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${_esc(title)}</title>
  <link rel="icon" type="image/png" href="${_esc(A)}/favicon-32x32.png" sizes="32x32" />
  <link rel="icon" type="image/png" href="${_esc(A)}/favicon-16x16.png" sizes="16x16" />
  <link rel="stylesheet" type="text/css" href="${_esc(A)}/swagger-ui.css" integrity="${SRI['swagger-ui.css']}" crossorigin="anonymous" />
  <style>
    /* ── Brand overrides ───────────────────────────────────────────────── */
    :root {
      --qodiqa-bg:       #0f1117;
      --qodiqa-surface:  #1a1d27;
      --qodiqa-accent:   #7c6af7;
      --qodiqa-text:     #e2e8f0;
      --qodiqa-muted:    #64748b;
      --qodiqa-border:   #2d3748;
    }

    html { box-sizing: border-box; }
    *, *::before, *::after { box-sizing: inherit; }

    body {
      margin: 0;
      background: var(--qodiqa-bg);
      color: var(--qodiqa-text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }

    /* Top banner */
    #qodiqa-header {
      background: var(--qodiqa-surface);
      border-bottom: 1px solid var(--qodiqa-border);
      padding: 14px 24px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    #qodiqa-header .logo {
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.5px;
      color: var(--qodiqa-accent);
    }
    #qodiqa-header .subtitle {
      font-size: 0.8rem;
      color: var(--qodiqa-muted);
    }
    #qodiqa-header .badge {
      margin-left: auto;
      background: rgba(124,106,247,0.15);
      color: var(--qodiqa-accent);
      border: 1px solid rgba(124,106,247,0.3);
      border-radius: 4px;
      padding: 2px 8px;
      font-size: 0.75rem;
      font-family: monospace;
    }

    /* Swagger UI container */
    #swagger-ui {
      max-width: 1280px;
      margin: 0 auto;
      padding: 0 16px 48px;
    }

    /* Dark theme overrides for swagger-ui elements */
    .swagger-ui .topbar           { display: none; }
    .swagger-ui .info             { margin: 24px 0 16px; }
    .swagger-ui .info .title      { color: var(--qodiqa-text); }
    .swagger-ui .info .description,
    .swagger-ui .info .base-url   { color: var(--qodiqa-muted); }
    .swagger-ui .scheme-container { background: var(--qodiqa-surface); box-shadow: none; border: 1px solid var(--qodiqa-border); border-radius: 6px; padding: 12px 16px; }
    .swagger-ui select            { background: var(--qodiqa-bg); color: var(--qodiqa-text); border-color: var(--qodiqa-border); }
    .swagger-ui .opblock-tag      { border-color: var(--qodiqa-border); color: var(--qodiqa-text); }
    .swagger-ui .opblock           { border-color: var(--qodiqa-border); border-radius: 6px; margin-bottom: 8px; }
    .swagger-ui .opblock .opblock-summary { background: var(--qodiqa-surface); }
    .swagger-ui .opblock.opblock-get    .opblock-summary { border-color: #38bdf8; }
    .swagger-ui .opblock.opblock-post   .opblock-summary { border-color: #4ade80; }
    .swagger-ui .opblock.opblock-put    .opblock-summary { border-color: #fb923c; }
    .swagger-ui .opblock.opblock-patch  .opblock-summary { border-color: #a78bfa; }
    .swagger-ui .opblock.opblock-delete .opblock-summary { border-color: #f87171; }
    .swagger-ui .btn.authorize      { background: var(--qodiqa-accent); border-color: var(--qodiqa-accent); color: #fff; }
    .swagger-ui .btn.authorize svg  { fill: #fff; }
  </style>
</head>
<body>

<div id="qodiqa-header">
  <span class="logo">QODIQA</span>
  <span class="subtitle">AI Authorization &amp; Consent Enforcement Platform</span>
  <span class="badge">OpenAPI 3.1.0</span>
</div>

<div id="swagger-ui" data-spec-url="${_esc(basePath + specUrl)}"></div>

<script src="${_esc(A)}/swagger-ui-bundle.js" integrity="${SRI['swagger-ui-bundle.js']}" crossorigin="anonymous"></script>
<script src="${_esc(A)}/swagger-ui-standalone-preset.js" integrity="${SRI['swagger-ui-standalone-preset.js']}" crossorigin="anonymous"></script>
<script src="${_esc(A)}/swagger-initializer.js" integrity="${INITIALIZER_SRI}" crossorigin="anonymous"></script>
</body>
</html>`;
}

// Minimal HTML entity escaping for values interpolated into the HTML template.
function _esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = { renderSwaggerUiHtml, getSwaggerAsset, SWAGGER_UI_VERSION, SRI, INITIALIZER_SRI, VENDOR_DIR, ASSET_NAMES: Object.keys(ASSETS) };
