import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import path from 'path'
import fs from 'node:fs'
import os from 'node:os'
import https from 'node:https'

// 已登记实时传感器的本机后端使用私有 CA TLS；未接入的开发环境仍沿用普通本机 HTTP。
const serviceConfig = path.join(os.homedir(), 'Workspace/development/services/security/cyber-security/config')
const sensorEnabled = fs.existsSync(process.env.CYBER_LOCAL_SENSOR_CONFIG ?? path.join(serviceConfig, 'local-sensor.properties'))
const backendTarget = process.env.VITE_BACKEND_URL ?? `${sensorEnabled ? 'https' : 'http'}://127.0.0.1:18080`
const backendAgent = backendTarget.startsWith('https:')
  ? new https.Agent({ ca: fs.readFileSync(process.env.CYBER_BACKEND_CA ?? path.join(serviceConfig, 'tls/ca.pem')) })
  : undefined

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  server: {
    // 日常开发入口固定；重复启动时明确报占用，避免自动递增端口导致浏览器连错实例。
    port: 5173,
    strictPort: true,
    host: '127.0.0.1',
    proxy: {
      // 浏览器只使用 v2 控制面与公共健康探针。
      '/health': {
        target: backendTarget,
        agent: backendAgent,
        changeOrigin: true
      },
      '/api/v2': {
        target: backendTarget,
        agent: backendAgent,
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
