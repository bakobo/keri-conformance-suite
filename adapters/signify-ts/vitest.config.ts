import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: ['tests/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            include: ['src/**/*.ts'],
            // main.ts is only the process entry point. tests/stdio.test.ts runs it as a child
            // process, which this process's coverage cannot see.
            exclude: ['src/main.ts'],
            thresholds: { branches: 100, functions: 100, lines: 100, statements: 100 },
        },
    },
});
