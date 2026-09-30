import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { load, perms } = vi.hoisted(() => ({ load: vi.fn(), perms: { value: new Set<string>() } }))
vi.mock('@/api/client', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn() } }))
vi.mock('@/api/session', () => ({ can: (p: string) => perms.value.has(p), session: { user: { id: 8 } } }))
vi.mock('@/composables/load', () => ({ useLoad: load, errText: (e: unknown) => String(e) }))
vi.mock('@/composables/toast', () => ({ toast: vi.fn() }))
import { api } from '@/api/client'
import { toast } from '@/composables/toast'
import DetectionRulesPanel from './DetectionRulesPanel.vue'
import IamView from './IamView.vue'

const global = { stubs: {
  Tag: { props: ['label'], template: '<span>{{ label }}</span>' }, PageHead: true, Segmented: { name: 'Segmented', template: '<div />' },
  LoadState: { template: '<div><slot /></div>' },
  Drawer: { props: ['open', 'title'], template: '<section v-if="open" class="drawer"><h2>{{ title }}</h2><slot /><slot name="foot" /></section>' },
} }
const windowed = JSON.stringify({
  all: [{ field: 'features.proto', op: 'eq', value: 'tcp' }, { field: 'features.synack', op: 'eq', value: 0 }],
  window: { seconds: 60, aggregate: 'count', threshold: 30, groupBy: 'asset' },
})
const rule = (id: number, over: Record<string, unknown> = {}) => ({
  id, ruleKey: 'tcp-port-scan', version: String(id), scopeJson: '{"featureContractVersion":"unsw-nb15-flow-v4"}', conditionJson: windowed,
  severity: 'high', status: 'pending', requestedBy: 12, approvedBy: null, createdAt: '2026-10-01T00:00:00', updatedAt: '2026-10-01T00:00:00', ...over,
})
const reload = vi.fn()
function seed(data: unknown) {
  load.mockReturnValue({ data: ref(data), loading: ref(false), error: ref(''), reload })
}
const button = (w: ReturnType<typeof mount>, text: string) => w.findAll('button').find((b) => b.text() === text)

beforeEach(() => { vi.clearAllMocks(); perms.value = new Set() })

describe('检测规则页签', () => {
  it('按规则键分组并展示窗口条件摘要与详情', async () => {
    seed([rule(2), rule(1, { status: 'active', approvedBy: 13 })])
    const w = mount(DetectionRulesPanel, { global })
    const rows = w.findAll('tr.row-link')
    expect(rows).toHaveLength(2)
    expect(rows[0]!.text()).toContain('tcp-port-scan')
    expect(rows[1]!.text()).not.toContain('tcp-port-scan')
    expect(rows[0]!.text()).toContain('60 秒 计数 ≥ 30 · 2 项过滤')
    await rows[1]!.trigger('click')
    const drawer = w.get('.drawer').text()
    expect(drawer).toContain('features.synack = 0')
    expect(drawer).toContain('60 秒（同时为抑制期）')
    expect(drawer).toContain('unsw-nb15-flow-v4')
    expect(drawer).toContain('#13')
    w.unmount()
  })

  it('审批人可对他人登记的待审规则作决定，理由必填', async () => {
    perms.value = new Set(['detection.rule.approve'])
    seed([rule(5)])
    vi.mocked(api.post).mockResolvedValue({})
    const w = mount(DetectionRulesPanel, { global })
    await w.get('tr.row-link').trigger('click')
    await button(w, '批准启用')!.trigger('click')
    expect(api.post).not.toHaveBeenCalled()
    expect(toast).toHaveBeenCalledWith('请填写审批理由。', 'warn')
    await w.get('.drawer textarea').setValue('阈值与离线检出已复核')
    await button(w, '批准启用')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/detection-rules/5/decision', { decision: 'approve', reason: '阈值与离线检出已复核' })
    expect(reload).toHaveBeenCalled()
    w.unmount()
  })

  it('本人登记的规则不显示审批按钮', async () => {
    perms.value = new Set(['detection.rule.approve'])
    seed([rule(5, { requestedBy: 8 })])
    const w = mount(DetectionRulesPanel, { global })
    await w.get('tr.row-link').trigger('click')
    expect(button(w, '批准启用')).toBeUndefined()
    expect(button(w, '驳回')).toBeUndefined()
    expect(w.get('.drawer').text()).toContain('须由其他审批人决定')
    w.unmount()
  })

  it('无管理权限不显示登记入口；有权限时提交规范化请求体', async () => {
    seed([])
    let w = mount(DetectionRulesPanel, { global })
    expect(button(w, '登记规则版本')).toBeUndefined()
    w.unmount()

    perms.value = new Set(['detection.rule.manage'])
    vi.mocked(api.post).mockResolvedValue({})
    w = mount(DetectionRulesPanel, { global })
    await button(w, '登记规则版本')!.trigger('click')
    await w.get('input[placeholder="小写字母、数字、. _ -"]').setValue(' udp-burst ')
    const [condition, reason] = w.findAll('.drawer textarea')
    await condition!.setValue('{"all":[{"field":"features.proto","op":"eq","value":"udp"}]}')
    await reason!.setValue('离线回放检出 9/9')
    await button(w, '登记')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/detection-rules', {
      ruleKey: 'udp-burst', version: '1', severity: 'medium', condition: { all: [{ field: 'features.proto', op: 'eq', value: 'udp' }] },
      scope: { featureContractVersion: 'unsw-nb15-flow-v4' }, reason: '离线回放检出 9/9',
    })
    w.unmount()
  })

  it('条件不是 JSON 对象时不发请求', async () => {
    perms.value = new Set(['detection.rule.manage'])
    seed([])
    const w = mount(DetectionRulesPanel, { global })
    await button(w, '登记规则版本')!.trigger('click')
    await w.get('input[placeholder="小写字母、数字、. _ -"]').setValue('bad-rule')
    await w.findAll('.drawer textarea')[0]!.setValue('[1, 2]')
    await button(w, '登记')!.trigger('click')
    expect(api.post).not.toHaveBeenCalled()
    expect(toast).toHaveBeenCalledWith('条件须为 JSON 对象。', 'warn')
    w.unmount()
  })
})

describe('机器客户端登记', () => {
  it('按配对推导资源范围，凭据只显示一次且关闭后清除', async () => {
    perms.value = new Set(['iam.user.read', 'system.config.read', 'system.config.update'])
    seed({ users: [], roles: [], clients: [] })
    vi.mocked(api.get).mockImplementation((url: string) => Promise.resolve(url.startsWith('/data-sources')
      ? { items: [{ id: 3, sourceKey: 'lab-src', status: 'active' }, { id: 4, sourceKey: 'old-src', status: 'disabled' }] }
      : { items: [{ id: 7, assetKey: 'lab-host', status: 'active' }, { id: 9, assetKey: 'lab-host-2', status: 'active' }] }))
    vi.mocked(api.post).mockResolvedValue({
      id: 21, clientKey: 'lab-connector', clientType: 'connector', scopes: [], credential: 'mch_21.secret-value',
      sourceAssetBindings: [{ dataSourceId: 3, assetId: 7 }, { dataSourceId: 3, assetId: 9 }], issuedAt: '2026-10-01T00:00:00Z',
    })
    const w = mount(IamView, { global })
    await w.getComponent({ name: 'Segmented' }).vm.$emit('update:modelValue', 'clients')
    await flushPromises()
    await button(w, '登记连接器')!.trigger('click')
    await flushPromises()
    const sourceOptions = w.findAll('select[aria-label="数据源"] option').map((o) => o.text())
    expect(sourceOptions.some((t) => t.includes('old-src'))).toBe(false)
    await w.get('input[maxlength="96"]').setValue('lab-connector')
    await button(w, '添加一行')!.trigger('click')
    const sources = w.findAll('select[aria-label="数据源"]')
    const assets = w.findAll('select[aria-label="资产"]')
    await sources[0]!.setValue(3); await assets[0]!.setValue(7)
    await sources[1]!.setValue(3); await assets[1]!.setValue(9)
    await button(w, '登记并签发')!.trigger('click')
    await flushPromises()
    expect(api.post).toHaveBeenCalledWith('/machine-clients', {
      clientKey: 'lab-connector', clientType: 'connector',
      scopes: [{ scopeType: 'data_source', scopeId: '3' }, { scopeType: 'asset', scopeId: '7' }, { scopeType: 'asset', scopeId: '9' }],
      sourceAssetBindings: [{ dataSourceId: 3, assetId: 7 }, { dataSourceId: 3, assetId: 9 }],
    })
    expect(w.get('.drawer').text()).toContain('mch_21.secret-value')
    await button(w, '关闭')!.trigger('click')
    await button(w, '登记连接器')!.trigger('click')
    await flushPromises()
    expect(w.text()).not.toContain('mch_21.secret-value')
    w.unmount()
  })

  it('配对未选全时不发请求', async () => {
    perms.value = new Set(['iam.user.read', 'system.config.read', 'system.config.update'])
    seed({ users: [], roles: [], clients: [] })
    vi.mocked(api.get).mockResolvedValue({ items: [] })
    const w = mount(IamView, { global })
    await w.getComponent({ name: 'Segmented' }).vm.$emit('update:modelValue', 'clients')
    await flushPromises()
    await button(w, '登记连接器')!.trigger('click')
    await flushPromises()
    await w.get('input[maxlength="96"]').setValue('lab-connector')
    await button(w, '登记并签发')!.trigger('click')
    expect(api.post).not.toHaveBeenCalled()
    expect(toast).toHaveBeenCalledWith('每一行都须选择数据源与资产。', 'warn')
    w.unmount()
  })
})
