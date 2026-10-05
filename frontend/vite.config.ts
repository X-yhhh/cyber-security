import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: {
      // v1 为既有页面，v2 为 host-guard v5 控制面（09—11 模块）；两者都代理到同一后端。
      '/api/v1': {
        target: 'http://127.0.0.1:18080',
        changeOrigin: true
      },
      '/api/v2': {
        target: 'http://127.0.0.1:18080',
        changeOrigin: true
      }
    }
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      thresholds: { lines: 40, functions: 40, statements: 40, branches: 30 }
    }
  }
})
