'use strict';

/**
 * Regression test for (hidden PostgreSQL consent dependency).
 *
 * Covers the contract scripts/lib/devConsent.js documents: with
 * QODIQA_PG_ENABLED unset (the default), provisioning must be a complete,
 * side-effect-free no-op — it must never attempt a PostgreSQL connection.
 * This is what makes it safe for `npm run dev` to call unconditionally on
 * every invocation.
 */

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  jest.resetModules();
});

describe('scripts/lib/devConsent — opt-in gate', () => {
  test('is a no-op and never touches PostgreSQL when QODIQA_PG_ENABLED is unset', async () => {
    delete process.env.QODIQA_PG_ENABLED;
    jest.resetModules();

    // If provisionDevConsent attempted a connection with no PG reachable, this
    // would reject/hang; the opt-in gate must return before any `pg` call.
    const { provisionDevConsent } = require('../scripts/lib/devConsent');
    const logs = [];
    const result = await provisionDevConsent({
      clientId: 'test-client',
      log: (m) => logs.push(m),
      warn: (m) => logs.push(m),
    });

    expect(result).toEqual({ attempted: false });
    expect(logs.some((l) => l.includes('QODIQA_PG_ENABLED is not "true"'))).toBe(true);
  });

  test('is a no-op when QODIQA_PG_ENABLED is set to any value other than "true"', async () => {
    process.env.QODIQA_PG_ENABLED = 'false';
    jest.resetModules();

    const { provisionDevConsent } = require('../scripts/lib/devConsent');
    const result = await provisionDevConsent({ clientId: 'test-client' });

    expect(result).toEqual({ attempted: false });
  });

  test('configuredProviders() reflects only providers with an env var actually set', () => {
    delete process.env.OPENAI_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.GEMINI_API_KEY;
    delete process.env.MISTRAL_API_KEY;
    delete process.env.LLAMA_BASE_URL;
    delete process.env.LOCAL_BASE_URL;
    process.env.OPENAI_API_KEY = 'sk-test';
    jest.resetModules();

    const { configuredProviders } = require('../scripts/lib/devConsent');
    expect(configuredProviders()).toEqual(['openai']);
  });
});
