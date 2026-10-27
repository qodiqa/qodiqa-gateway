'use strict';

// step 6: deploy/env/production.env.example must be a VALID production configuration
// once its <REPLACE_…> placeholders are filled — and must be REFUSED while they
// are not, so an operator who copies it unchanged cannot start a production
// process. Both directions are checked with the real boot validator.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const dotenv = require('dotenv');

const { validateBoot, PROJECT_ROOT } = require('./bootValidator');
const { PROVIDER_FIXTURE_KEYS } = require('../../../test/helpers/providerFixtureKeys');

const EXAMPLE = dotenv.parse(fs.readFileSync(path.join(PROJECT_ROOT, 'deploy/env/production.env.example')));
const isPlaceholderValue = (v) => /<REPLACE[A-Z0-9_+]*>/.test(v);

function fill(name, value) {
  if (name === 'OPENAI_API_KEY') return PROVIDER_FIXTURE_KEYS.openai;
  if (name === 'QODIQA_CLIENT_ID') return 'acme-payments-prod';
  if (name === 'QODIQA_KEYS_PATH') return path.join(os.tmpdir(), 'qodiqa-w2-example', 'keys.json');
  // production refuses an unset or in-repository transparency key path, like QODIQA_KEYS_PATH.
  if (name === 'QODIQA_TRANSPARENCY_KEYS_PATH') return path.join(os.tmpdir(), 'qodiqa-w2-example', 'transparency-keys.json');
  if (name === 'QODIQA_PRQ_JOURNAL_DIR') return path.join(os.tmpdir(), 'qodiqa-w2-example', 'prq-journal');   // a persistent volume outside the application directory
  if (name === 'QODIQA_MAC_KEYS_PATH') { // the validator checks only that the provisioned file exists
    const p = path.join(os.tmpdir(), 'qodiqa-w2-example', 'mac-keys.json');
    fs.mkdirSync(path.dirname(p), { recursive: true });
    if (!fs.existsSync(p)) fs.writeFileSync(p, '{}');
    return p;
  }
  // production requires anchoring — the validator checks the witness public-key file exists.
  if (name === 'QODIQA_WITNESS_PUBLIC_KEYS') {
    const p = path.join(os.tmpdir(), 'qodiqa-w2-example-witness', 'witness-public-keys.json');
    fs.mkdirSync(path.dirname(p), { recursive: true });
    if (!fs.existsSync(p)) fs.writeFileSync(p, '[]');
    return p;
  }
  if (name === 'QODIQA_WITNESS_EXEC') return '/opt/customer/bin/qodiqa-witness';
  if (name === 'QODIQA_ANCHOR_EXPORT_PATH') return path.join(os.tmpdir(), 'qodiqa-w2-example-witness', 'anchors.jsonl');
  if (/HOSTNAME/.test(value)) return value.replace(/<REPLACE[A-Z0-9_+]*>/, 'svc.internal');
  if (/USERNAME/.test(value)) return 'svc_qodiqa';
  if (/(SECRET|KEY|PEPPER|PASSWORD|TOKEN|KEK)/.test(value)) return crypto.randomBytes(32).toString('hex');
  throw new Error(`productionEnvExample.test: no fill rule for ${name}=${value} — add one`);
}

test('the example contains the W2-required production variables', () => {
  for (const n of ['NODE_ENV', 'QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_EXECUTION_INVARIANT_SECRET', 'QODIQA_CLIENT_ID',
    'QODIQA_KEYS_PATH', 'POLICY_FILE', 'QODIQA_DSR_PSEUDONYM_PEPPER', 'QODIQA_MAC_KEYS_PATH',
    'RL_ENABLED', 'REDIS_URL', 'QODIQA_PG_SSL']) {
    expect({ n, present: n in EXAMPLE }).toEqual({ n, present: true });
  }
  expect(EXAMPLE.NODE_ENV).toBe('production');
  expect(EXAMPLE.RL_ENABLED).toBe('true');
});

test('filled in, the example passes production boot validation (only the local-KMS advisory remains)', () => {
  const env = Object.fromEntries(Object.entries(EXAMPLE).map(([k, v]) => [k, isPlaceholderValue(v) ? fill(k, v) : v]));
  const r = validateBoot(env);
  expect(r.profile).toBe('prod');
  expect(r.fatal).toEqual([]);
  expect(r.warnings.map((w) => w.variable)).toEqual(['QODIQA_KMS_PROVIDER']);
});

test('copied unchanged, the example is refused — every validated placeholder is named', () => {
  const r = validateBoot({ ...EXAMPLE });
  const fatalVars = new Set(r.fatal.map((f) => f.variable));
  const placeholders = Object.entries(EXAMPLE).filter(([, v]) => isPlaceholderValue(v)).map(([k]) => k);
  // Connection identities (host/user names) are not secrets and are not
  // boot-validated; a wrong one fails at connect time instead.
  // QODIQA_BACKUP_HMAC_KEY is read only by the backup shell scripts
  // (scripts/pg-backup.sh et al.), never by the gateway process —
  // src/infra/configSecrets/managedSecrets.js lists it as
  // UNREACHABLE_FROM_NODE_PROCESS — so the gateway's boot validator does not own it.
  const notValidated = new Set(['QODIQA_PG_HOST', 'QODIQA_PG_USER', 'REDIS_USERNAME', 'QODIQA_BACKUP_HMAC_KEY']);
  const expected = placeholders.filter((k) => !notValidated.has(k)).sort();
  expect(expected.length).toBeGreaterThanOrEqual(10);
  expect(expected.filter((k) => !fatalVars.has(k))).toEqual([]);
});
