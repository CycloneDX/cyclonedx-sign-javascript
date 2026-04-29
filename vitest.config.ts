import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    globals: false,
    coverage: {
      // v8 is Node's own coverage engine. Fast, no instrumentation
      // step; it works cleanly with vitest and with TypeScript source
      // without source-map gymnastics.
      provider: 'v8',
      reportsDirectory: 'coverage',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: [
        // Pure type declarations and barrel re-exports — no runtime
        // branches to cover. v8 reports these as 0% despite being
        // imported transitively, which skews the overall number.
        'src/**/types.ts',
        'src/**/internal-types.ts',
        'src/**/internal-binding.ts',
        'src/**/index.ts',
      ],
      // Coverage is uploaded to Codacy but we do not fail the build
      // on thresholds; keep the number visible and let the Codacy
      // gate enforce it.
      thresholds: undefined,
    },
  },
});
