/**
 * 阶段 2 前端对接：告警分层、本人申请撤回、模型退役与回退的交互（以 mock API 验证请求与可见性）。
 */
import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { useLoadMock, perms, user } = vi.hoisted(() => ({ useLoadMock: vi.fn(), perms: { value: new Set<string>() }, user: { value: { id: 8, username: 'analyst' } } }))

vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn() } }))
vi.mock('@/api/session', () => ({ can: (p: string) => perms.value.has(p), session: { get user() { return user.value } } }))
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

import { api } from '@/api/client'
import { toast } from '@/composables/toast'
import EventsView from './EventsView.vue'
import ResponseView from './ResponseView.vue'
import ModelsView from './ModelsView.vue'

const global = {
  stubs: {
    PageHead: true, DetectionRulesPanel: true, DetectionPoliciesPanel: true,
    Tag: { props: ['label'], template: '<span>{{ label }}</span>' },
    Drawer: { props: ['open', 'title'], template: '<section v-if="open" class="drawer"><slot /><slot name="foot" /></section>' },
  },
  directives: { reveal: () => undefined },
}
const button = (w: ReturnType<typeof mount>, text: string) => w.findAll('button').find((b) => b.text().trim() === text)
function seed(data: unknown) {
  useLoadMock.mockReturnValue({ data: ref(data), loading: ref(false), error: ref(''), reload: vi.fn() })
}

beforeEach(() => { vi.clearAllMocks(); perms.value = new Set() })

const alert = (id: number, over: Record<string, unknown> = {}) => ({
  id, alertKey: `alert-${id}`, alertType: 'model', severity: 'low', status: 'open', score: 0.6, detectedAt: '2026-10-01T08:00:00',
  dataSourceId: 1, assetId: 2, modelVersionId: 3, modelKey: 'm', modelVersion: '1', contractVersion: null, contractSha256: null,
  detectionRuleId: null, ruleKey: null, ruleVersion: null, severityPolicyVersion: 'severity-v2', thresholdVersion: null, basisJson: null,
  alertLayer: 'alert', correlationPolicyVersion: null, promotedAt: null, ...over,
})

describe('告警分层', () => {
  it('切到模型信号时读 ?layer=signal，并标注未进人工队列', async () => {
    perms.value = new Set(['alert.read'])
    seed({ events: [], alerts: [alert(1)], eventTotal: 0, alertTotal: 1 })
    vi.mocked(api.get).mockResolvedValue({ items: [alert(9, { alertLayer: 'signal' })], totalElements: 1, page: 0, size: 100 })
    const w = mount(EventsView, { global })
    ;(w.vm as unknown as { view: string }).view = 'alerts'
    await flushPromises()
    await button(w, '模型信号')!.trigger('click')
    await flushPromises()
    expect(api.get).toHaveBeenCalledWith('/api/v1/alerts?layer=signal&size=100')
    expect(w.text()).toContain('alert-9')
    expect(w.text()).toContain('模型信号，未进人工队列')
    expect(w.text()).not.toContain('alert-1')
    w.unmount()
  })
})

const ledger = (id: number, over: Record<string, unknown> = {}) => ({
  id, eventId: 1, eventKey: 'evt-1', assetId: 2, assetKey: 'host-2', actionRequest: { parameters: { targetAddress: '10.0.0.9', ttlSeconds: 600 } },
  status: 'pending', requester: 'analyst', reviewer: null, decisionReason: null, expiresAt: '2026-10-02T08:00:00', createdAt: '2026-10-01T08:00:00',
  reviewedAt: null, executionStatus: null, withdrawReason: null, withdrawnAt: null, ...over,
})

describe('本人申请撤回', () => {
  it('pending 本人申请可撤回，理由必填；已撤回显示原因', async () => {
    perms.value = new Set(['action.request'])
    seed({ ledger: [], mine: [ledger(1), ledger(2, { status: 'cancelled', withdrawReason: '误报', withdrawnAt: '2026-10-01T09:00:00' })], policies: [] })
    vi.mocked(api.post).mockResolvedValue({})
    const w = mount(ResponseView, { global })
    expect(w.text()).toContain('已撤回')
    expect(w.text()).toContain('误报')
    const withdraws = w.findAll('button').filter((b) => b.text() === '撤回')
    expect(withdraws).toHaveLength(1)
    await withdraws[0]!.trigger('click')
    await button(w, '确认撤回')!.trigger('click')
    expect(api.post).not.toHaveBeenCalled()
    expect(toast).toHaveBeenCalledWith('请填写撤回理由。', 'warn')
    await w.get('.drawer textarea').setValue('不再需要')
    await button(w, '确认撤回')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/api/v1/actions/1/withdraw', { reason: '不再需要' })
    w.unmount()
  })
})

const model = (id: number, approvalStatus: string) => ({
  id, modelKey: 'flow-model', version: `v${id}`, taskType: 'binary', manifestVersion: '1', manifest: {}, artifactRef: 'a', artifactSha256: 'x',
  featureContractVersion: 'unsw-nb15-flow-v4', approvalStatus, createdAt: '2026-10-01T08:00:00',
})
const deployment = (modelVersionId: number) => ({
  id: 1, environment: 'local', mode: 'detect', modelVersionId, modelKey: 'flow-model', version: `v${modelVersionId}`, runtimeType: 'onnx', status: 'active', activatedAt: '2026-10-01T08:00:00',
})

// 列表选中由 watch(models) 驱动；mock 的 data 不变化，测试中点击第一行选中。
async function selectFirstModel(w: ReturnType<typeof mount>) {
  await flushPromises()
  await w.get('ul li button').trigger('click')
  await flushPromises()
}

describe('模型退役与回退', () => {
  beforeEach(() => { vi.mocked(api.get).mockResolvedValue([]); vi.mocked(api.post).mockResolvedValue({}) })

  it('活动部署回退需二次确认，并带 expectedCurrentModelId；活动版本不提供退役', async () => {
    perms.value = new Set(['model.validation.read', 'model.deployment.activate', 'model.candidate.manage'])
    seed({ models: [model(5, 'approved')], deployments: [deployment(5)], drift: [], feedback: [], jobs: [] })
    const w = mount(ModelsView, { global })
    await selectFirstModel(w)
    expect(button(w, '退役此版本')).toBeUndefined()
    await w.get('textarea').setValue('新版本误报')
    await button(w, '回退到上一已批准版本')!.trigger('click')
    expect(api.post).not.toHaveBeenCalled()
    await button(w, '确认回退')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/api/v1/model-deployments/rollback', { expectedCurrentModelId: 5, reason: '新版本误报' })
    w.unmount()
  })

  it('非活动版本可退役，理由必填', async () => {
    perms.value = new Set(['model.validation.read', 'model.candidate.manage'])
    seed({ models: [model(4, 'approved')], deployments: [], drift: [], feedback: [], jobs: [] })
    const w = mount(ModelsView, { global })
    await selectFirstModel(w)
    await button(w, '退役此版本')!.trigger('click')
    expect(api.post).not.toHaveBeenCalled()
    await w.get('textarea').setValue('已被新版本替代')
    await button(w, '退役此版本')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/api/v1/models/4/retire', { reason: '已被新版本替代' })
    w.unmount()
  })
})
