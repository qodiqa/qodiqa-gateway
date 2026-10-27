import { defineConfig } from 'tsup';
import pkg from './package.json';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  outDir: 'dist',
  target: 'es2020',
  platform: 'node',
  minify: false,
  banner: {
    js: `/* @qodiqa/sdk v${pkg.version} — Official QODIQA JavaScript/TypeScript SDK */`,
  },
});
