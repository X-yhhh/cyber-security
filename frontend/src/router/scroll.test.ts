/** F0R.2：查询串变化保持滚动，历史导航恢复位置，跨路径（含详情 ID）回顶。 */
import { describe, expect, it } from 'vitest'
import { createMemoryHistory, type RouteLocationNormalized } from 'vue-router'
import { createAppRouter } from '.'

describe('控制台滚动行为', () => {
  const router = createAppRouter(createMemoryHistory())
  const scroll = router.options.scrollBehavior!
  const resolve = (path: string): RouteLocationNormalized => {
    const route = router.resolve(path)
    return { ...route, name: route.name ?? undefined }
  }

  it('同一路径改变筛选或 hash 保持原位置', () => {
    expect(scroll(resolve('/console/detect/events?status=open#row'), resolve('/console/detect/events?status=closed'), null)).toBe(false)
  })
  it('saved 优先于同页保持和跨页回顶', () => {
    const saved = { left: 0, top: 420 }
    expect(scroll(resolve('/console/detect/events?status=open'), resolve('/console/detect/events'), saved)).toBe(saved)
    expect(scroll(resolve('/console/detect/records'), resolve('/console/detect/events'), saved)).toBe(saved)
  })
  it('不同菜单页和不同详情 ID 都回到顶部', () => {
    expect(scroll(resolve('/console/detect/records'), resolve('/console/detect/events'), null)).toEqual({ top: 0 })
    expect(scroll(resolve('/console/detect/events/b'), resolve('/console/detect/events/a'), null)).toEqual({ top: 0 })
  })
})
