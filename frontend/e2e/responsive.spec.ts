/** F6 留存的 390px 展示回归：真实统计响应加载后检查整页宽度与关键入口。 */
import { test, expect, login } from './helpers'

test('390px 实时态势数据表不会撑宽页面，筛选与检测入口可操作', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await login(page, 'analyst')
  await expect(page.getByRole('heading', { name: '实时态势', exact: true })).toBeVisible()
  await expect(page.locator('[data-stat]').filter({ hasText: '今日入站观察' }).locator('p.num')).toHaveText(/\d/)
  expect(await page.evaluate(() => ({ viewport: innerWidth, width: document.documentElement.scrollWidth }))).toEqual({ viewport: 390, width: 390 })
  await page.getByRole('button', { name: '打开菜单', exact: true }).click()
  await page.getByRole('dialog', { name: '功能菜单', exact: true }).getByRole('link', { name: '检测记录', exact: true }).click()
  await expect(page.getByRole('heading', { name: '检测记录', exact: true })).toBeVisible()
  await page.getByLabel('时间范围').selectOption('1h')
  await expect(page.getByLabel('时间范围')).toHaveValue('1h')
})
