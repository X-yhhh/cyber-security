/** F0R.3：验证外部导航回填、自己写入不回填、缺省省略与导航竞态，防止丢失页内状态或循环请求。 */
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { defineComponent, h, nextTick, ref, watch, type Ref } from 'vue'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { queryString, useQueryState } from './query'

let wrapper: VueWrapper | undefined
let state: { tab: Ref<'summary' | 'list'>; status: Ref<string>; q: Ref<string>; draft: Ref<string> }
let hydrations: number
let changes: number
const Page = defineComponent({
  setup() {
    state = { tab: ref<'summary' | 'list'>('summary'), status: ref(''), q: ref(''), draft: ref('') }
    useQueryState({
      tab: { state: state.tab, default: 'summary', parse: (v) => v === 'list' ? 'list' : 'summary' },
      status: { state: state.status, default: '', parse: (v) => v === 'open' || v === 'closed' ? v : '' },
      q: { state: state.q, default: '', parse: queryString, serialize: (v) => state.tab.value === 'list' ? v : undefined },
    }, () => { hydrations++; state.draft.value = state.q.value })
    watch([state.tab, state.status, state.q], () => { changes++ })
    return () => h('p', `${state.tab.value}/${state.status.value}/${state.q.value}`)
  },
})
async function settle() {
  await nextTick()
  await flushPromises()
  await nextTick()
}
async function open(path: string) {
  hydrations = changes = 0
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/items', component: Page },
    { path: '/other', component: defineComponent({ render: () => h('p', 'other') }) },
  ] })
  await router.push(path)
  wrapper = mount(defineComponent({ render: () => h(RouterView) }), { global: { plugins: [router] } })
  await settle()
  return router
}
afterEach(() => { wrapper?.unmount() })

describe('useQueryState', () => {
  it('初始查询先解析回填，重复参数、裸参数与无效枚举按缺省处理', async () => {
    await open('/items?tab=list&status=open&q=needle')
    expect(wrapper!.text()).toBe('list/open/needle')
    expect(state.draft.value).toBe('needle')
    expect(hydrations).toBe(1)
    wrapper!.unmount()
    await open('/items?tab=list&tab=summary&status=invalid&q')
    expect(wrapper!.text()).toBe('summary//')
  })

  it('本地批量改筛选只 replace 一次，保留未托管参数与 hash，自己写入不重置输入草稿', async () => {
    const router = await open('/items?keep=1#row')
    let navigations = 0
    router.afterEach(() => { navigations++ })
    state.draft.value = '未提交输入'
    state.tab.value = 'list'
    state.status.value = 'open'
    state.q.value = 'needle'
    await settle()
    expect(router.currentRoute.value.query).toEqual({ keep: '1', tab: 'list', status: 'open', q: 'needle' })
    expect(router.currentRoute.value.hash).toBe('#row')
    expect(navigations).toBe(1)
    expect(changes).toBe(1)
    expect(hydrations).toBe(1)
    expect(state.draft.value).toBe('未提交输入')
  })

  it('恢复缺省筛选时删除托管参数', async () => {
    const router = await open('/items?tab=list&status=open&q=needle&keep=1')
    state.tab.value = 'summary'
    state.status.value = ''
    state.q.value = ''
    await settle()
    expect(router.currentRoute.value.query).toEqual({ keep: '1' })
  })

  it('当前分段不适用的字段从 URL 省略，但来回切分段时保留其页内值', async () => {
    const router = await open('/items?tab=list&q=needle')
    state.tab.value = 'summary'
    await settle()
    expect(router.currentRoute.value.query).toEqual({})
    expect(state.q.value).toBe('needle')
    state.tab.value = 'list'
    await settle()
    expect(router.currentRoute.value.query).toEqual({ tab: 'list', q: 'needle' })
  })

  it('外部同页链接一次回填全部字段，点击当前菜单地址回到缺省且没有反向导航', async () => {
    const router = await open('/items?tab=list&status=open&q=needle')
    state.draft.value = '尚未提交'
    let navigations = 0
    router.afterEach(() => { navigations++ })
    await router.push('/items?status=closed')
    await settle()
    expect(wrapper!.text()).toBe('summary/closed/')
    expect(state.draft.value).toBe('')
    expect(changes).toBe(1)
    expect(navigations).toBe(1)
    await router.push('/items')
    await settle()
    expect(wrapper!.text()).toBe('summary//')
    expect(navigations).toBe(2)
  })

  it('前进后退回填筛选且不改写历史项', async () => {
    const router = await open('/items')
    await router.push('/items?status=open')
    await router.push('/items?status=closed')
    router.back()
    await settle()
    expect(state.status.value).toBe('open')
    expect(router.currentRoute.value.query).toEqual({ status: 'open' })
    router.forward()
    await settle()
    expect(state.status.value).toBe('closed')
  })

  it('快速改筛选时，较慢的旧 replace 不覆盖最新筛选', async () => {
    const router = await open('/items')
    let release!: () => void
    const gate = new Promise<void>((resolve) => { release = resolve })
    router.beforeEach((to) => to.query.status === 'open' ? gate : true)
    state.status.value = 'open'
    await settle()
    state.status.value = 'closed'
    await settle()
    release()
    await settle()
    expect(state.status.value).toBe('closed')
    expect(router.currentRoute.value.query).toEqual({ status: 'closed' })
    expect(hydrations).toBe(1)
  })

  it('离开页面后旧 ref 变化不修改下一页的地址', async () => {
    const router = await open('/items?status=open')
    await router.push('/other?keep=1')
    state.status.value = 'closed'
    await settle()
    expect(router.currentRoute.value.fullPath).toBe('/other?keep=1')
  })
})
