import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { getMock, putMock, toastMock, canMock, fixture } = vi.hoisted(() => ({ getMock: vi.fn(), putMock: vi.fn(), toastMock: vi.fn(), canMock: vi.fn(), fixture: { alerts: null as unknown, timeline: null as unknown } }))

vi.mock('@/api/client', () => ({ api: { get: getMock, post: vi.fn(), put: putMock }, ApiError: class extends Error {} }))
vi.mock('@/api/session', () => ({ can: canMock, session: { user: { id: 8 } } }))
vi.mock('@/composables/reveal', () => ({ vReveal: { mounted: vi.fn() } }))
vi.mock('@/composables/toast', () => ({ toast: toastMock }))
vi.mock('@/composables/load', () => ({
  useLoad: () => ({ data: ref(detail()), loading: ref(false), error: ref(''), reload: vi.fn() }),
  optional: (p: Promise<unknown>) => p,
  errText: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}))
vi.mock('vue-router', () => ({ RouterLink: { template: '<a><slot /></a>' }, useRoute: () => ({ params: { id: '7' } }) }))

import EventDetailView from './EventDetailView.vue'

const entry = (n: number) => ({ id: n, occurredAt: '2026-09-29T15:00:00', entryType: 'alert_linked', actorType: 'system', actorId: null, summary: `entry-${n}`, evidenceRef: null, detailsJson: null })
const page = <T>(items: T[], total: number, p = 0) => ({ totalElements: total, page: p, size: 20, items })

function detail() {
  return {
    event: { id: 7, eventKey: 'evt-7', title: '批量告警', category: 'network', severity: 'critical', status: 'open', riskScore: 1, firstSeenAt: '2026-09-29T15:00:00', lastSeenAt: '2026-09-29T15:20:00', assigneeId: null, alertCount: 45, assetCount: 1, riskRuleVersion: 'risk-v1', riskBasisJson: null, correlationKey: null, correlationPolicyVersion: null },
    alerts: fixture.alerts ?? page([], 0),
    assets: [{ assetId: 1, assetKey: 'host-1', relationType: 'affected', evidenceCount: 45 }],
    timeline: fixture.timeline ?? page(Array.from({ length: 20 }, (_, i) => entry(45 - i)), 45),
  }
}

function mountView() {
  // LoadState 用真实组件：stub 不渲染插槽，详情主体会整块消失。
  return mount(EventDetailView, { global: { stubs: ['Tag', 'Drawer'], directives: { reveal: () => undefined } } })
}

describe('EventDetailView paging', () => {
  beforeEach(() => { getMock.mockReset(); toastMock.mockReset(); canMock.mockReset().mockReturnValue(false); fixture.alerts = null; fixture.timeline = null })

  it('renders only the embedded first page and requests the next page from the sub-resource', async () => {
    getMock.mockResolvedValue(page(Array.from({ length: 20 }, (_, i) => entry(25 - i)), 45, 1))
    const wrapper = mountView()
    expect(wrapper.findAll('ol > li')).toHaveLength(20)
    expect(wrapper.text()).toContain('共 45 条 · 第 1 / 3 页')

    const next = wrapper.get('nav[aria-label="证据时间线分页"]').findAll('button')[1]
    await next.trigger('click')
    await flushPromises()

    expect(getMock).toHaveBeenCalledWith('/events/7/timeline?page=1&size=20')
    expect(wrapper.text()).toContain('entry-25')
    expect(wrapper.text()).toContain('第 2 / 3 页')
    wrapper.unmount()
  })

  it('keeps the current page and reports the error when a page request fails', async () => {
    getMock.mockRejectedValue(new Error('服务暂时无法处理请求（request-id req-1）'))
    const wrapper = mountView()
    await wrapper.get('nav[aria-label="证据时间线分页"]').findAll('button')[1].trigger('click')
    await flushPromises()

    expect(toastMock).toHaveBeenCalledWith('服务暂时无法处理请求（request-id req-1）', 'threat')
    expect(wrapper.text()).toContain('entry-45')
    expect(wrapper.text()).toContain('第 1 / 3 页')
    wrapper.unmount()
  })

  it('ignores a slower stale response that returns after a newer page', async () => {
    let resolveSlow!: (v: unknown) => void
    getMock
      .mockImplementationOnce(() => new Promise((r) => { resolveSlow = r }))
      .mockResolvedValueOnce(page([entry(5)], 45, 2))
    const wrapper = mountView()
    const vm = wrapper.vm as unknown as { timeline: { go: (p: number) => Promise<void> } }
    const slow = vm.timeline.go(1)
    await vm.timeline.go(2)
    resolveSlow(page([entry(25)], 45, 1))
    await slow
    await flushPromises()

    expect(wrapper.text()).toContain('entry-5')
    expect(wrapper.text()).not.toContain('entry-25')
    wrapper.unmount()
  })

  it('opens the feedback drawer from an alert row and reloads the current alert page after a label', async () => {
    canMock.mockImplementation((p: string) => p === 'alert.read' || p === 'alert.feedback.label')
    const alert = { id: 31, alertKey: 'alt-31', alertType: 'model', severity: 'high', status: 'new', score: 0.9, detectedAt: '2026-09-29T15:00:00', dataSourceId: 1, assetId: 1, modelKey: 'unsw', modelVersion: 'v1', contractVersion: 'v4', ruleKey: null, ruleVersion: null, severityPolicyVersion: null }
    fixture.alerts = page([alert], 1)
    getMock.mockResolvedValue(page([{ ...alert, status: 'false_positive' }], 1))
    const wrapper = mount(EventDetailView, { global: { stubs: ['Tag', 'Drawer', 'AlertFeedbackDrawer'], directives: { reveal: () => undefined } } })

    const drawer = wrapper.findComponent({ name: 'AlertFeedbackDrawer' })
    expect(drawer.props('open')).toBe(false)
    await wrapper.get('button[aria-label="标注 alt-31"]').trigger('click')
    expect(drawer.props()).toMatchObject({ open: true, alertId: 31, alertKey: 'alt-31', status: 'new', alertType: 'model' })

    drawer.vm.$emit('changed')
    await flushPromises()
    expect(getMock).toHaveBeenCalledWith('/events/7/alerts?page=0&size=20')
    expect(wrapper.findComponent({ name: 'AlertFeedbackDrawer' }).props('status')).toBe('false_positive')
    expect(wrapper.find('button[aria-label="查看标注 alt-31"]').exists()).toBe(true)
    wrapper.unmount()
  })

  it('assigns a handler with a reason and shows assignee_changed before/after in the timeline', async () => {
    canMock.mockImplementation((p: string) => p === 'event.investigate')
    putMock.mockResolvedValue({})
    const drawerStub = { props: ['open', 'title'], template: '<section v-if="open" class="drawer"><slot /><slot name="foot" /></section>' }
    const wrapper = mount(EventDetailView, { global: { stubs: { Tag: true, Drawer: drawerStub }, directives: { reveal: () => undefined } } })
    await wrapper.findAll('button').find((b) => b.text() === '指派')!.trigger('click')
    await wrapper.get('.drawer input').setValue('12')
    const confirm = wrapper.findAll('.drawer button').find((b) => b.text() === '确认指派')!
    await confirm.trigger('click')
    expect(putMock).not.toHaveBeenCalled()
    expect(toastMock).toHaveBeenCalledWith('请填写指派理由。', 'warn')
    await wrapper.get('.drawer textarea').setValue('值班交接')
    await confirm.trigger('click')
    await flushPromises()
    expect(putMock).toHaveBeenCalledWith('/events/7/assignee', { assigneeId: 12, reason: '值班交接' })
    wrapper.unmount()
  })

  it('renders assignee_changed before/after from detailsJson', () => {
    // 本人 id 来自 session mock（8）
    fixture.timeline = page([{ ...entry(1), entryType: 'assignee_changed', detailsJson: '{"from":"unassigned","to":"8"}' }], 1)
    const wrapper = mountView()
    expect(wrapper.text()).toContain('处理人 未指派 → #8（我）')
    wrapper.unmount()
  })

  it('hides the pager for a section that fits on one page', () => {
    const wrapper = mountView()
    expect(wrapper.find('nav[aria-label="关联告警分页"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('无可见关联告警。')
    wrapper.unmount()
  })
})
