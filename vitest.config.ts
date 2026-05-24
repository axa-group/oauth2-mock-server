import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    setupFiles: ['test/lib/_vitest-setup.ts'],
    coverage: {
      exclude: ['test/**'],
    },
  },
});
