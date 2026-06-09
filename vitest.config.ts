import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    // 使用 node 环境：Node.js v18+ 内置 globalThis.crypto.subtle，与 Workers 运行时行为一致。
    // @cloudflare/vitest-pool-workers 在 Windows 上额外依赖较重，保持最简配置。
    environment: 'node',
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts', 'webapp/**/*.test.ts'],
    globals: false,
  },
  resolve: {
    // 对齐 tsconfig 的 bundler moduleResolution
    conditions: ['import', 'module', 'browser', 'default'],
    alias: {
      // 支持 webapp 单测使用 @/ 路径别名（与 vite.config.ts 对齐）
      '@': path.resolve(__dirname, 'webapp/src'),
    },
  },
});
