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
        // JSS is a stub that only throws; coverage for it is not a
        // meaningful signal until the implementation lands.
        'src/jss/**',
        // Pure type declarations.
        'src/**/types.ts',
      ],
      // Coverage is uploaded to Codacy but we do not fail the build
      // on thresholds; keep the number visible and let the Codacy
      // gate enforce it.
      thresholds: undefined,
    },
  },
});
