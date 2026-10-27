// Gate A #28 / owner C-1 + C-7: ESLint declared reproducibly (package.json + package-lock.json) so that
// `npm ci && npm run lint` works in hosted CI. Minimal, evidence-preserving config: the TypeScript parser plus the
// recommended rule sets; no rule was relaxed to make the existing source pass.
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
  plugins: ['@typescript-eslint'],
  extends: ['eslint:recommended', 'plugin:@typescript-eslint/recommended'],
  env: { node: true, es2022: true },
  ignorePatterns: ['dist/', 'node_modules/'],
};
