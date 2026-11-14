import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@wolin-id/client': fileURLToPath(
        new URL('./packages/client/src/index.ts', import.meta.url),
      ),
      '@wolin-id/react': fileURLToPath(
        new URL('./packages/react/src/index.ts', import.meta.url),
      ),
    },
  },
  test: {
    include: ['packages/*/tests/**/*.test.{ts,tsx}'],
    passWithNoTests: false,
  },
});
