'use strict';

/**
 * Minimisation profiles: ready-made DLP rule sets for "send the provider only what it needs". A profile is a list of DLP policy rules (the same shape as any other
 * rule in the policy set); the operator copies the ones they want into the tenant's policy set, where they are governed, hashed and published like every other rule.
 *
 *   light     personal data is detected and recorded, credentials and key material are redacted before they reach a provider
 *   standard  + personal data, financial and national-id data are redacted in requests; credentials never leave in an answer
 *   strict    + answers are redacted too, and tool arguments / results are screened; anything classified RESTRICTED is refused
 */

const rule = (id, priority, config) => ({ id, type: 'DLP', priority, enabled: true, config: { dlpFormat: 1, minConfidence: 0.6, ...config } });

const PROFILES = Object.freeze({
  light: [
    rule('MIN_LIGHT_SECRETS_IN', 40, { direction: 'input', action: 'REDACT', rules: ['CREDENTIAL', 'CRYPTO'] }),
    rule('MIN_LIGHT_PII_DETECT', 60, { direction: 'input', action: 'DETECT', rules: ['PII', 'FINANCIAL', 'NATIONAL_ID'] }),
  ],
  standard: [
    rule('MIN_STD_REDACT_IN', 40, { direction: 'input', action: 'REDACT', rules: ['PII', 'FINANCIAL', 'NATIONAL_ID', 'CREDENTIAL', 'CRYPTO'] }),
    rule('MIN_STD_SECRETS_OUT', 50, { direction: 'output', action: 'REDACT', rules: ['CREDENTIAL', 'CRYPTO'] }),
  ],
  strict: [
    rule('MIN_STRICT_REDACT_IN', 40, { direction: 'input', action: 'REDACT', rules: ['PII', 'FINANCIAL', 'NATIONAL_ID', 'CREDENTIAL', 'CRYPTO'], classification: { minLevel: 'RESTRICTED', action: 'BLOCK' } }),
    rule('MIN_STRICT_REDACT_OUT', 50, { direction: 'output', action: 'REDACT', rules: ['PII', 'FINANCIAL', 'NATIONAL_ID', 'CREDENTIAL', 'CRYPTO'], exfiltration: { action: 'BLOCK' } }),
    rule('MIN_STRICT_TOOL_ARGS', 60, { direction: 'tool_input', action: 'BLOCK', rules: ['FINANCIAL', 'NATIONAL_ID', 'CREDENTIAL', 'CRYPTO'] }),
    rule('MIN_STRICT_TOOL_RESULT', 70, { direction: 'tool_output', action: 'REDACT', rules: ['PII', 'FINANCIAL', 'NATIONAL_ID', 'CREDENTIAL', 'CRYPTO'] }),
  ],
});

/** A deep copy of the rules of a profile (callers edit them freely). */
function profile(name) {
  if (!Object.prototype.hasOwnProperty.call(PROFILES, name)) throw new Error(`unknown minimisation profile: ${String(name).slice(0, 40)} (light, standard, strict)`);
  return JSON.parse(JSON.stringify(PROFILES[name]));
}

module.exports = { PROFILES, profile, names: () => Object.keys(PROFILES) };
