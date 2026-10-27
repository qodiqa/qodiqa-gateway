'use strict';
// Flat configuration (ESLint 8.57 and later). It replaces .eslintrc.cjs, which a flat-config file in a parent directory made unusable.
// Same rule sets as before: eslint:recommended plus the TypeScript recommended set; no rule was relaxed.
const js = require('@eslint/js');
const tseslint = require('@typescript-eslint/eslint-plugin');

module.exports = [
  { ignores: ['dist/', 'node_modules/'] },
  js.configs.recommended,
  ...tseslint.configs['flat/recommended'],
  { files: ['**/*.ts'], languageOptions: { ecmaVersion: 2022, sourceType: 'module' } },
];
