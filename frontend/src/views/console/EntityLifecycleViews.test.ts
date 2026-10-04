import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { load } = vi.hoisted(() => ({ load: vi.fn() }))
vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn() } }))
vi.mock('@/api/session', () => ({ can: () => true, session: { user: { id: 99 } } }))
vi.mock('@/composables/load', () => ({ useLoad: load, errText: (e: unknown) => String(e), optional: (p: Promise<unknown>) => p }))
vi.mock('@/composables/toast', () => ({ toast: vi.fn() }))
import { api } from '@/api/client'
import IamView from './IamView.vue'
import AssetsView from './AssetsView.vue'
import SourcesView from './SourcesView.vue'

const global = { stubs: {
  PageHead: true, Segmented: true, Tag: true, SourcesShadowPanel: true,
  LoadState: { template: '<div><slot /></div>' },
  Drawer: { props: ['open', 'title'], template: '<section v-if="open" class="drawer"><h2>{{ title }}</h2><slot /><slot name="foot" /></section>' },
} }
function deferred() {
  let resolve!: (v: unknown) => void
  const promise = new Promise<unknown>((r) => { resolve = r })
  return { promise, resolve }
}
function seed(data: unknown) {
  load.mockReturnValue({ data: ref(data), loading: ref(false), error: ref(''), reload: vi.fn() })
}

beforeEach(() => vi.clearAllMocks())
describe('实体详情请求隔离', () => {
  it('切换用户后丢弃迟到详情，保存只作用于当前用户', async () => {
    seed({ users: [1, 2].map((id) => ({ id, username: `user${id}`, displayName: `用户${id}`, status: 'active' })), roles: [], clients: [] })
    const old = deferred()
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.endsWith('/roles')) return Promise.resolve([])
      if (url === '/users/1') return old.promise
      return Promise.resolve({ id: 2, username: 'user2', displayName: '用户2', status: 'active' })
    })
    const w = mount(IamView, { global })
    await w.findAll('tr.row-link')[0]!.trigger('click')
    await w.findAll('tr.row-link')[1]!.trigger('click')
    await flushPromises()
    old.resolve({ id: 1, username: 'user1', displayName: '用户1', status: 'active' })
    await flushPromises()
    expect(w.get('.drawer h2').text()).toBe('用户2')
    await w.get('.drawer input[maxlength="128"]').setValue('新名称')
    const save = w.findAll('button').find((b) => b.text() === '保存显示名称')!
    await save.trigger('click')
    expect(api.put).toHaveBeenCalledWith('/users/2', { displayName: '新名称' })
    w.unmount()
  })

  it.each([
    [AssetsView, 'assets', 'authorizations', { sensors: [] }],
    [SourcesView, 'data-sources', 'mappings', { summary: [], replay: [] }],
  ] as const)('切换资源后不显示前一个资源的授权或映射', async (component, route, child, extra) => {
    const rows = [1, 2].map((id) => ({ id, assetKey: `asset${id}`, sourceKey: `source${id}`, status: 'active' }))
    seed({ [route === 'assets' ? 'assets' : 'sources']: rows, ...extra })
    const old = deferred()
    vi.mocked(api.get).mockImplementation((url: string) => url === `/${route}/1/${child}` ? old.promise : Promise.resolve([]))
    const w = mount(component, { global })
    await w.findAll('tr.row-link')[0]!.trigger('click')
    await w.findAll('tr.row-link')[1]!.trigger('click')
    await flushPromises()
    old.resolve([{ id: 10, assetId: 1, authorizationRef: '旧资源记录', mappingVersion: '旧资源记录', status: 'active' }])
    await flushPromises()
    expect(w.get('.drawer').text()).not.toContain('旧资源记录')
    w.unmount()
  })

  it.each([403, 500])('用户详情 %s 显式展示错误且不开放旧对象操作', async (code) => {
    seed({ users: [{ id: 1, username: 'one', displayName: '一', status: 'active' }], roles: [], clients: [] })
    vi.mocked(api.get).mockRejectedValue(new Error(`HTTP ${code} request-id test-${code}`))
    const w = mount(IamView, { global })
    await w.get('tr.row-link').trigger('click')
    await flushPromises()
    expect(w.get('.drawer').text()).toContain(`request-id test-${code}`)
    expect(w.get('.drawer').text()).not.toContain('重置口令')
    expect(api.post).not.toHaveBeenCalled()
    w.unmount()
  })
})
