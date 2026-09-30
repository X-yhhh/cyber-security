import { mount } from '@vue/test-utils'
import { ref } from 'vue'
import { describe, expect, it, vi } from 'vitest'

const { useLoadMock } = vi.hoisted(() => ({ useLoadMock: vi.fn() }))

vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn() } }))
vi.mock('@/api/session', () => ({ can: vi.fn(() => false), session: { user: null } }))
vi.mock('@/composables/load', () => ({
  useLoad: useLoadMock,
  optional: (promise: Promise<unknown>, fallback: unknown) => promise.catch(() => fallback),
  errText: (error: unknown) => String(error),
}))
vi.mock('@/composables/reveal', () => ({ vReveal: { mounted: vi.fn() } }))
vi.mock('@/composables/toast', () => ({ toast: vi.fn() }))
vi.mock('vue-router', () => ({
  RouterLink: { template: '<a><slot /></a>' },
  useRoute: () => ({ params: { id: '1' } }),
  useRouter: () => ({ push: vi.fn() }),
}))

import AssetsView from './AssetsView.vue'
import AuditView from './AuditView.vue'
import EventDetailView from './EventDetailView.vue'
import EventsView from './EventsView.vue'
import IamView from './IamView.vue'
import ModelsView from './ModelsView.vue'
import OverviewView from './OverviewView.vue'
import ResponseView from './ResponseView.vue'
import SourcesView from './SourcesView.vue'
import { can } from '@/api/session'

const components = [AssetsView, AuditView, EventDetailView, EventsView, IamView, ModelsView, OverviewView, ResponseView, SourcesView]

describe('console view smoke coverage', () => {
  it.each(components)('mounts %s with empty authorized data', (component) => {
    useLoadMock.mockImplementation((_loader: unknown, initial: unknown) => ({
      data: ref(initial),
      loading: ref(false),
      error: ref(null),
      reload: vi.fn(),
    }))

    const wrapper = mount(component, {
      global: {
        stubs: ['PageHead', 'Segmented', 'Tag', 'Drawer', 'LoadState', 'Metric'],
        directives: { reveal: () => undefined },
      },
    })

    expect(wrapper.exists()).toBe(true)
    wrapper.unmount()
  })

  it('renders an authorized event row and keeps the trend chart accessible', () => {
    useLoadMock.mockImplementation(() => ({
      data: ref({
        events: [{ id: 1, eventKey: 'evt-1', title: '异常连接', category: 'network', severity: 'high', status: 'open', assetCount: 1, alertCount: 2, riskScore: 0.82, lastSeenAt: '2026-09-28T08:00:00Z' }],
        alerts: [], eventTotal: 1, alertTotal: 0,
      }),
      loading: ref(false), error: ref(null), reload: vi.fn(),
    }))

    const wrapper = mount(EventsView, {
      global: {
        stubs: ['PageHead', 'Segmented', 'Tag', 'Drawer'],
        directives: { reveal: () => undefined },
      },
    })

    expect(wrapper.text()).toContain('异常连接')
    expect(wrapper.find('input[aria-label="搜索"]').exists()).toBe(true)
    expect(wrapper.get('tr[tabindex="0"]').attributes('tabindex')).toBe('0')
    wrapper.unmount()
  })

  it('offers the shadow validation tab on the sources page only with shadow.report.read', () => {
    useLoadMock.mockImplementation((_loader: unknown, initial: unknown) => ({ data: ref(initial), loading: ref(false), error: ref(''), reload: vi.fn() }))
    const options = () => {
      const wrapper = mount(SourcesView, { global: { stubs: ['PageHead', 'Segmented', 'Tag', 'LoadState'] } })
      const values = (wrapper.findComponent({ name: 'Segmented' }).props('options') as { value: string }[]).map((o) => o.value)
      wrapper.unmount()
      return values
    }
    expect(options()).toEqual(['sources', 'replay'])
    vi.mocked(can).mockImplementation((p: string) => p === 'shadow.report.read')
    expect(options()).toEqual(['sources', 'replay', 'shadow'])
    vi.mocked(can).mockImplementation(() => false)
  })

  it('surfaces a backend error through the shared alert state', () => {
    useLoadMock.mockImplementation(() => ({
      data: ref({ totalElements: 0, page: 0, size: 50, items: [] }),
      loading: ref(false), error: ref('服务暂时无法处理请求（request-id req-500）'), reload: vi.fn(),
    }))

    const wrapper = mount(AuditView, {
      global: {
        stubs: ['PageHead', 'Tag'],
        directives: { reveal: () => undefined },
      },
    })

    expect(wrapper.get('[role="alert"]').text()).toContain('request-id req-500')
    wrapper.unmount()
  })
})
