import { defineConfig } from 'vite'
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
      '/api/v1': {
        target: 'http://127.0.0.1:18080',
        changeOrigin: true
      }
    }
  }
})
