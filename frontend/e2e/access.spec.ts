/** 以权限设计的六角色矩阵独立断言真实会话、路由守卫和服务器授权；不读取菜单实现。 */
import { test, expect, login, api, type Role } from './helpers'

const all = ['实时态势', '待办中心', '事件研判', '检测记录', '误报反馈', '处置记录', '模型与数据集', '发布管理', '资产', '传感器与执行器', '用户管理', '角色管理', '审计日志']
const matrix: Record<Role, { menus: string[]; denied: string; endpoint: string }> = {
  admin: { menus: ['实时态势', '待办中心', '资产', '传感器与执行器', '用户管理', '角色管理', '审计日志'], denied: '/console/detect/events', endpoint: '/events' },
  analyst: { menus: all.slice(0, 6), denied: '/console/system/users', endpoint: '/users' },
  reviewer: { menus: all.filter(n => !['误报反馈', '用户管理', '角色管理', '审计日志'].includes(n)), denied: '/console/system/users', endpoint: '/users' },
  operator: { menus: ['待办中心', '模型与数据集', '发布管理'], denied: '/console/assets/list', endpoint: '/users' },
  evidence: { menus: ['实时态势', '待办中心', '事件研判', '检测记录', '误报反馈', '模型与数据集', '发布管理'], denied: '/console/system/users', endpoint: '/users' },
  auditor: { menus: all.filter(n => !['误报反馈', '用户管理'].includes(n)), denied: '/console/system/users', endpoint: '/users' },
}

for (const role of Object.keys(matrix) as Role[]) {
  test(`${role}：菜单、落地页、前后端 403 与 390px 导航`, async ({ page }) => {
    await login(page, role)
    await expect(page.getByText('控制面正常', { exact: true })).toBeVisible()
    const nav = page.getByRole('navigation', { name: '功能菜单', exact: true })
    await expect(nav.getByRole('link')).toHaveText(matrix[role].menus)
    await page.goto(matrix[role].denied)
    await expect(page.getByRole('heading', { name: '无权访问此页面' })).toBeVisible()
    await expect(page).toHaveURL(new RegExp(matrix[role].denied + '$'))
    expect((await api(page, matrix[role].endpoint)).status()).toBe(403)
    await page.setViewportSize({ width: 390, height: 844 })
    const toggle = page.getByRole('button', { name: '打开菜单', exact: true })
    await toggle.click()
    const menu = page.getByRole('dialog', { name: '功能菜单', exact: true })
    await expect(menu.getByRole('navigation').getByRole('link')).toHaveText(matrix[role].menus)
    await page.keyboard.press('Escape')
    await expect(menu).toBeHidden()
    await expect(toggle).toBeFocused()
    await toggle.click()
    await menu.getByRole('link', { name: '待办中心', exact: true }).click()
    await expect(page).toHaveURL(/\/console\/workbench$/)
    await expect(menu).toBeHidden()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), '390px 无整页横向溢出').toBe(true)
  })
}

test('合并的旧地址保留既定重定向和查询参数', async ({ page }) => {
  await login(page, 'auditor')
  const routes = [
    ['observation', 'detect/records?tab=observations'],
    ['detect/observations', 'detect/records?tab=observations'],
    ['decisions', 'detect/records?tab=decisions'],
    ['detect/decisions', 'detect/records?tab=decisions'],
    ['release', 'release/bundles?tab=bundles'],
    ['release/evaluations', 'release/bundles?tab=validation&record=evaluations'],
    ['release/policies', 'release/bundles?tab=policies'],
    ['release/lab', 'release/bundles?tab=validation&record=lab'],
    ['lab', 'release/bundles?tab=validation&record=lab'],
    ['health', 'assets/agents?tab=health'], ['ops/health', 'assets/agents?tab=health'],
    ['assets/authorizations', 'assets/list'], ['response/budgets', 'response/actions'],
    ['execution', 'response/actions'], ['ops/audit', 'system/audit'],
  ]
  for (const [from, to] of routes) {
    await page.goto('/console/' + from)
    await expect(page).toHaveURL(new URL('/console/' + to, page.url()).href)
  }
  await page.goto('/console/detect/observations?assetId=fixture#anchor')
  await expect(page).toHaveURL(/\/console\/detect\/records\?assetId=fixture&tab=observations#anchor$/)
})
