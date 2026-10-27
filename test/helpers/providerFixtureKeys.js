'use strict';

// (BOOT-RULES.md section 3, decision D-E): a provider is enabled only by a key
// that passes the shared credential rules (prefix/charset/length, not a
// placeholder). Tests that need an ENABLED provider use these format-valid,
// deliberately low-entropy, obviously-fake keys — values like 'sk-test' are now
// (correctly) treated as placeholders and leave the provider disabled.
// Never real keys; never used outside tests.

const PROVIDER_FIXTURE_KEYS = Object.freeze({
  openai:    'sk-w2-fixture-openai-' + 'a'.repeat(24),
  anthropic: 'sk-ant-w2-fixture-anthropic-' + 'a'.repeat(20),
  gemini:    'w2-fixture-gemini-' + 'a'.repeat(20),
  mistral:   'w2fixturemistral' + 'a'.repeat(20),
});

module.exports = { PROVIDER_FIXTURE_KEYS };
