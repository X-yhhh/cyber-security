import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { load, perms } = vi.hoisted(() => ({ load: vi.fn(), perms: { value: new Set<string>() } }))
vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn() } }))
vi.mock('@/api/session', () => ({ can: (p: string) => perms.value.has(p), session: { user: { id: 8 } } }))
vi.mock('@/composables/load', () => ({ useLoad: load, errText: (e: unknown) => String(e) }))
vi.mock('@/composables/toast', () => ({ toast: vi.fn() }))
import { api } from '@/api/client'
import { toast } from '@/composables/toast'
import DetectionPoliciesPanel from './DetectionPoliciesPanel.vue'
import type { DetectionPolicyView } from '@/api/types'

const reload = vi.fn()
const global = { stubs: {
  Tag: { props: ['label'], template: '<span>{{ label }}</span>' },
  Drawer: { props: ['open', 'title'], template: '<section v-if="open" class="drawer"><h2>{{ title }}</h2><slot /><slot name="foot" /></section>' },
} }
const SEVERITY = { model: [{ minScore: 0.9, severity: 'critical' }, { minScore: 0, severity: 'medium' }], modelSignal: { enabled: true, countThreshold: 3, highScore: 0.99 } }

function policy(id: number, policyType: string, over: Partial<DetectionPolicyView> = {}): DetectionPolicyView {
  return {
    id, policyType, version: `${policyType}-v${id}`, configJson: JSON.stringify(policyType === 'severity_mapping' ? SEVERITY : { windowSeconds: 900, dimensions: ['asset'] }),
    status: 'draft', createdBy: 8, basedOnPolicyId: null, changeReason: '调整', contentSha256: 'a'.repeat(64), submittedAt: null,
    reviewedBy: null, reviewedAt: null, decisionReason: null, retiredBy: null, retiredAt: null, createdAt: '2026-10-01T08:00:00', ...over,
  }
}
function seed(data: DetectionPolicyView[]) {
  load.mockReturnValue({ data: ref(data), loading: ref(false), error: ref(''), reload })
}
const button = (w: ReturnType<typeof mount>, text: string) => w.findAll('button').find((b) => b.text() === text)

beforeEach(() => { vi.clearAllMocks(); perms.value = new Set() })

describe('检测策略页签', () => {
  it('按类型分组，详情展示解析后的参数', async () => {
    seed([policy(1, 'severity_mapping', { status: 'active', createdBy: null }), policy(2, 'correlation', { status: 'active', createdBy: null })])
    const w = mount(DetectionPoliciesPanel, { global })
    expect(w.text()).toContain('分级映射')
    expect(w.text()).toContain('事件关联')
    await w.findAll('tr.row-link')[0]!.trigger('click')
    const drawer = w.get('.drawer').text()
    expect(drawer).toContain('modelSignal')
    expect(drawer).toContain('"countThreshold":3')
    expect(drawer).toContain('预置')
    w.unmount()
  })

  it('起草人可提交本人草稿，提交不带请求体', async () => {
    perms.value = new Set(['detection.policy.manage'])
    seed([policy(3, 'severity_mapping')])
    const w = mount(DetectionPoliciesPanel, { global })
    await w.get('tr.row-link').trigger('click')
    expect(button(w, '批准生效')).toBeUndefined()
    await button(w, '提交审批')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/detection-policies/3/submit', undefined)
    expect(reload).toHaveBeenCalled()
    w.unmount()
  })

  it('撤回须填理由', async () => {
    perms.value = new Set(['detection.policy.manage'])
    seed([policy(3, 'severity_mapping', { status: 'pending' })])
    const w = mount(DetectionPoliciesPanel, { global })
    await w.get('tr.row-link').trigger('click')
    await button(w, '撤回')!.trigger('click')
    expect(api.post).not.toHaveBeenCalled()
    expect(toast).toHaveBeenCalledWith('请填写理由。', 'warn')
    await w.get('.drawer textarea').setValue('不再需要')
    await button(w, '撤回')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/detection-policies/3/withdraw', { reason: '不再需要' })
    w.unmount()
  })

  it('审批人只能决定他人待审版本；本人起草不显示批准', async () => {
    perms.value = new Set(['detection.policy.approve'])
    seed([policy(4, 'severity_mapping', { status: 'pending', createdBy: 12 }), policy(5, 'correlation', { status: 'pending', createdBy: 8 })])
    const w = mount(DetectionPoliciesPanel, { global })
    await w.findAll('tr.row-link')[0]!.trigger('click')
    await w.get('.drawer textarea').setValue('复核通过')
    await button(w, '批准生效')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/detection-policies/4/decision', { decision: 'approve', reason: '复核通过' })
    await w.findAll('tr.row-link')[1]!.trigger('click')
    expect(button(w, '批准生效')).toBeUndefined()
    expect(w.get('.drawer').text()).toContain('须由其他审批人决定')
    w.unmount()
  })

  it('审批人可退役生效版本', async () => {
    perms.value = new Set(['detection.policy.approve'])
    seed([policy(6, 'risk_score', { status: 'active', createdBy: null, configJson: '{"repeatStep":0.05}' })])
    const w = mount(DetectionPoliciesPanel, { global })
    await w.get('tr.row-link').trigger('click')
    await w.get('.drawer textarea').setValue('停用')
    await button(w, '退役')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/detection-policies/6/retire', { reason: '停用' })
    w.unmount()
  })

  it('基于旧版本复制只提交 config 与理由；modelSignal 越界被前端拦截', async () => {
    perms.value = new Set(['detection.policy.manage'])
    seed([policy(1, 'severity_mapping', { status: 'active', createdBy: null })])
    const w = mount(DetectionPoliciesPanel, { global })
    await button(w, '基于此版本起草')!.trigger('click')
    const count = w.findAll('.drawer input[type="number"]')[0]!
    await count.setValue('1')
    await w.findAll('.drawer textarea')[1]!.setValue('收紧阈值')
    await button(w, '登记草稿')!.trigger('click')
    expect(api.post).not.toHaveBeenCalled()
    expect(toast).toHaveBeenCalledWith('信号提升计数须为 2～10000 的整数。', 'warn')
    await count.setValue('5')
    await button(w, '登记草稿')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/detection-policies/1/versions', {
      config: { ...SEVERITY, modelSignal: { enabled: true, countThreshold: 5, highScore: 0.99 } }, reason: '收紧阈值',
    })
    w.unmount()
  })

  it('同类型已有未决版本时不提供复制', () => {
    perms.value = new Set(['detection.policy.manage'])
    seed([policy(1, 'severity_mapping', { status: 'active', createdBy: null }), policy(2, 'severity_mapping', { status: 'pending', createdBy: 12 })])
    const w = mount(DetectionPoliciesPanel, { global })
    expect(button(w, '基于此版本起草')).toBeUndefined()
    w.unmount()
  })
})
