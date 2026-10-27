'use strict';

const fs = require('fs');
const path = require('path');

/**
 * EXAMPLE-1 / regression guard.
 *
 * Root cause (see src/api/routes/__tests__/signProviderResolution.test.js and
 * src/api/routes/__tests__/quickstartFlow.test.js): POST /sign requires
 * payload.provider for any /ai/chat-bound request whenever zero or more than
 * one AI provider is enabled server-side, auto-resolving it only when
 * exactly one provider is enabled. Every bundled example and documentation
 * snippet that signs an /ai/chat request used to omit this fact silently
 * — a reader who copied one verbatim into a
 * multi-provider deployment hit an unexplained 400 PROVIDER_REQUIRED with no
 * clue why, and no test anywhere caught the omission (TEST-15).
 *
 * This test statically scans every shipped example/doc file that signs an
 * /ai/chat request and fails CI if the surrounding text doesn't explain the
 * conditional requirement. It intentionally does not require every example
 * to *set* payload.provider (omitting it is correct and idiomatic in a
 * single-provider deployment — see docs/guides/quickstart.md) — only that the file
 * explains the behavior so a reader isn't left debugging blind.
 *
 * Extend FILES_WITH_AI_CHAT_SIGN_EXAMPLES whenever a new example or doc page
 * ships a /sign call bound to /ai/chat.
 */

const ROOT = path.resolve(__dirname, '..', '..');

// Only files that hardcode a literal, quoted '/ai/chat' path in a /sign
// call belong here — express/middleware.js, fastify/middleware.js,
// sdk/python/examples/cli.py, fastapi_integration.py, and
// flask_integration.py deliberately sign a *caller-supplied* path (generic
// proxy/middleware examples, not /ai/chat-specific), so they're out of
// scope for this literal check even though they also carry a provider
// explanation comment.
const FILES_WITH_AI_CHAT_SIGN_EXAMPLES = [
  'docs/guides/quickstart.md',
  'examples/quickstart.js',
  'sdk/javascript/README.md',
  'sdk/javascript/examples/node/basic.js',
  'sdk/javascript/examples/node/cli.js',
  'sdk/javascript/examples/typescript/basic.ts',
  'sdk/javascript/examples/nextjs/route.ts',
  'sdk/python/README.md',
  'sdk/python/examples/basic_client.py',
  'sdk/python/examples/async_client.py',
  'docs/sdk/javascript/README.md',
  'docs/sdk/javascript/api.md',
  'docs/sdk/python/README.md',
  'docs/sdk/python/api.md',
];

// Any of these substrings (case-insensitive), found anywhere in the file, is
// accepted as evidence that the file explains /sign's conditional
// provider-resolution behavior. Multiple phrasings are accepted because
// prose style legitimately varies between a curl walkthrough (docs/guides/quickstart.md),
// a terse inline code comment (examples/quickstart.js), and a parameter reference table
// (docs/sdk/*/api.md) — the point is that *some* explanation is present, not
// that the wording is identical everywhere.
const EXPLANATION_MARKERS = [
  /provider_required/i,
  /auto-resolv/i,
  /only needed if more than one/i,
  /only meaningful when/i,
  /conditional/i,
];

// A request bound to /ai/chat, quoted either JS/TS-object-literal style or
// Python-dict-literal style, alongside a call that signs it.
function hasAiChatSignExample(content) {
  return /['"`]\/ai\/chat['"`]/.test(content) && /\.sign\.sign\(|\bsign\.sign\(|POST \/sign|#### `POST \/sign/i.test(content);
}

describe('EXAMPLE-1/DOC-1 regression: shipped examples explain conditional payload.provider', () => {
  test.each(FILES_WITH_AI_CHAT_SIGN_EXAMPLES)('%s exists and still ships an /ai/chat sign example', (relPath) => {
    const fullPath = path.join(ROOT, relPath);
    expect(fs.existsSync(fullPath)).toBe(true);
  });

  test.each(FILES_WITH_AI_CHAT_SIGN_EXAMPLES)(
    '%s explains provider auto-resolution near its /ai/chat sign example',
    (relPath) => {
      const fullPath = path.join(ROOT, relPath);
      const content = fs.readFileSync(fullPath, 'utf8');

      // Guard the guard: if a file stops shipping an /ai/chat sign example
      // entirely, that's a deliberate content change, not a drift this test
      // should silently pass on — fail loudly so it gets reviewed and
      // removed from FILES_WITH_AI_CHAT_SIGN_EXAMPLES deliberately.
      expect(hasAiChatSignExample(content)).toBe(true);

      const explained = EXPLANATION_MARKERS.some((re) => re.test(content));
      expect(explained).toBe(true);
    },
  );
});
