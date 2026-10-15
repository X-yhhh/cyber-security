/** T1 使用 runner 启动的真实隔离环境；失败保留脱敏 trace，不记录凭据截图。 */
import { defineConfig } from '@playwright/test'
import path from 'node:path'

const work = process.env.E2E_WORK
if (!work || !process.env.E2E_BASE_URL) throw new Error('请通过 npm run test:e2e 启动隔离环境')

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  outputDir: path.join(work, 'test-results'),
  reporter: [['list'], ['json', { outputFile: path.join(work, 'results.json') }]],
  use: {
    baseURL: process.env.E2E_BASE_URL,
    browserName: 'chromium',
    channel: 'chromium',
    viewport: { width: 1440, height: 1000 },
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: { mode: 'retain-on-failure', screenshots: false, snapshots: true, sources: false },
    screenshot: 'off',
    video: 'off',
  },
})
