'use strict';
// minimal lint configuration for the gateway. Correctness rules (errors) from eslint:recommended;
// style and noise rules are disabled explicitly. It does not cover sdk/ (own configuration), eval/, evidence/, quarantine/.
const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  { ignores: [
    'node_modules/**', 'sdk/**', 
    'coverage/**', 'logs/**', 'backups/**', 'public/**', 'tls/**',
    '.*-venv/**', 'scripts/spikes/**', 'src/openapi/vendor/**', '.stryker-*/**', 'stryker-report/**', '.claude/**', '.scratch-*/**',
    '**/*.snapshot.js', '**/*.mjs', '**/*.cjs',
  ] },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'commonjs', globals: { ...globals.node, ...globals.jest } },
    linterOptions: { reportUnusedDisableDirectives: 'off' },
    rules: {
      'no-unused-vars': 'off', 'no-empty': 'off', 'no-useless-escape': 'off', 'no-control-regex': 'off',
      'no-prototype-builtins': 'off', 'no-inner-declarations': 'off', 'no-case-declarations': 'off', 'no-fallthrough': 'off',
      'no-async-promise-executor': 'off', 'no-misleading-character-class': 'off', 'no-constant-condition': 'off',
      'no-cond-assign': 'off', 'no-regex-spaces': 'off', 'no-sparse-arrays': 'off', 'no-useless-catch': 'off',
      'no-extra-boolean-cast': 'off', 'no-self-assign': 'off', 'no-empty-pattern': 'off', 'getter-return': 'off',
    },
  },
  // Explicit exceptions (item 1.4): literals/constructs that are intentional in tests; frozen semantic files (not edited).
  { files: ['**/*.test.js', 'test/**/*.js'], rules: { 'no-loss-of-precision': 'off', 'require-yield': 'off', 'no-unsafe-finally': 'off', 'no-irregular-whitespace': 'off' } },
  { files: ['src/core/semantic/embeddingSimilarity/inputNormalization.js', 'src/core/semantic/textSignals.js'], rules: { 'no-irregular-whitespace': 'off' } },
];
