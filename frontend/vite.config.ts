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
      // 浏览器只使用 v2 控制面与公共健康探针。
      '/health': {
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
