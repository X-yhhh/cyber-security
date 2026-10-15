/** 真实会话与合成制品的测试适配；禁止拦截业务 API。秘密只登记到 runner 的私有目录。 */
import { test as base, expect, type Page, type Response, type Locator } from '@playwright/test'
import { appendFileSync, readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import path from 'node:path'
import { randomUUID, randomBytes } from 'node:crypto'

export type Role = 'admin' | 'analyst' | 'reviewer' | 'operator' | 'evidence' | 'auditor'
export const state = JSON.parse(readFileSync(process.env.E2E_STATE_FILE!, 'utf8'))
export const ids: Record<string, any> = {}
export const unique = () => randomUUID()
export const reason = 'T1 合成回归，不执行防火墙动作'
export function registerSecret(value: string) {
  if (value && value.length >= 6) appendFileSync(path.join(process.env.E2E_ARTIFACT_ROOT!, 'browser-secrets.jsonl'), JSON.stringify(value) + '\n', { mode: 0o600 })
}
export function password() { const value = randomBytes(24).toString('base64url'); registerSecret(value); return value }
function secretsIn(value: any) {
  if (!value || typeof value !== 'object') return
  for (const [key, item] of Object.entries(value)) {
    if (/^(password|credential|token|cookie|set-cookie|authorization|x-csrf-token)$/i.test(key) && typeof item === 'string') registerSecret(item)
    else secretsIn(item)
  }
}
export const test = base.extend({
  page: async ({ page }, use) => {
    page.on('request', req => {
      secretsIn(req.headers())
      try { secretsIn(req.postDataJSON()) } catch { /* 非 JSON 请求 */ }
    })
    page.on('response', async res => {
      secretsIn(res.headers())
      if (res.url().includes('/api/')) {
        try { secretsIn(await res.json()) } catch { /* 空响应 */ }
      }
    })
    await use(page)
  },
})
export { expect }
export async function login(page: Page, role: Role) {
  await page.context().clearCookies()
  await page.goto('/login')
  await page.getByLabel('用户名', { exact: true }).fill(state.accounts[role].username)
  await page.getByLabel('密码', { exact: true }).fill(state.accounts[role].password)
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page).toHaveURL(new RegExp(role === 'operator' ? '/console/workbench$' : '/console/overview/live$'))
}
export const dialog = (page: Page, name?: string | RegExp) => page.getByRole('dialog', name ? { name } : {})
export async function mutation(page: Page, suffix: string, action: () => Promise<unknown>, method = 'POST', expected?: number) {
  // 按已登记的 HTTP 契约检查精确状态：创建 201、异步受理 202、状态/资料变更 200。
  const operation = suffix.split('/').at(-1)!
  expected ??= method !== 'POST' ? 200 : ['activations', 'revocations', 'automation-stops'].includes(operation) ? 202
    : suffix.split('/').length === 2 || ['authorizations', 'configs', 'imports', 'sealings', 'notes', 'role-bindings'].includes(operation) ? 201 : 200
  const pending = page.waitForResponse(r => new URL(r.url()).pathname === '/api/v2' + suffix && r.request().method() === method)
  await action()
  const response: Response = await pending
  expect(response.status(), `真实 ${method} ${suffix} 状态`).toBe(expected)
  const json = await response.json()
  secretsIn(json)
  expect(Boolean(json.data), '响应包含 data').toBeTruthy()
  return json.data
}
export async function api(page: Page, suffix: string, body?: unknown, method = body === undefined ? 'GET' : 'POST', revision?: number) {
  const csrf = await page.request.get('/api/v2/auth/csrf')
  const token = (await csrf.json()).data.token
  registerSecret(token)
  const response = await page.request.fetch('/api/v2' + suffix, {
    method, data: body, headers: { 'X-CSRF-TOKEN': token, 'Idempotency-Key': unique(), ...(revision === undefined ? {} : { 'If-Match': String(revision) }) },
  })
  return response
}
export async function read(page: Page, suffix: string) {
  const response = await api(page, suffix)
  expect(response.status(), `读取 ${suffix}`).toBe(200)
  return (await response.json()).data
}
export function fixture(op: string, input: Record<string, unknown> = {}) {
  try {
    return JSON.parse(execFileSync('sh', ['executor/python.sh', 'scripts/p8/e2e_fixtures.py'], {
      cwd: path.resolve(process.cwd(), '..'), input: JSON.stringify({ op, ...input }), encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 45_000,
    }))
  } catch (error: any) {
    throw new Error(String(error.stderr || 'E2E_FIXTURE_FAILED').replace(/[^A-Z0-9_\n -]/g, '').slice(0, 200))
  }
}
export async function fill(d: Locator, label: string, value: string) { await d.getByLabel(label, { exact: false }).fill(value) }
export async function close(page: Page) { await dialog(page).getByRole('button', { name: '关闭', exact: true }).click() }
