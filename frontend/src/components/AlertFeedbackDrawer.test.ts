import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { getMock, postMock, toastMock, canMock } = vi.hoisted(() => ({ getMock: vi.fn(), postMock: vi.fn(), toastMock: vi.fn(), canMock: vi.fn() }))

vi.mock('@/api/client', () => ({ api: { get: getMock, post: postMock }, ApiError: class extends Error {} }))
vi.mock('@/api/session', () => ({ can: canMock }))
vi.mock('@/composables/toast', () => ({ toast: toastMock }))

import AlertFeedbackDrawer from './AlertFeedbackDrawer.vue'

const fb = (over: Record<string, unknown> = {}) => ({
  id: 1, alertId: 9, alertKey: 'alt-9', alertType: 'model', label: 'false_positive', note: '本机当时在做系统更新', reviewedBy: 2, reviewerName: '研判员甲',
  reviewedAt: '2026-10-02T03:00:00', reviewStatus: 'rejected', secondReviewedBy: 3, secondReviewerName: '复核员乙', secondReviewedAt: '2026-10-02T04:00:00',
  secondReviewReason: '证据不足', trainingEligible: false, dataSourceId: 1, assetId: 1, ...over,
})

function mountDrawer(props: Record<string, unknown>) {
  // Teleport 置为内联渲染，便于在 wrapper 内查询抽屉内容
  return mount(AlertFeedbackDrawer, { props: { open: true, alertId: 9, alertKey: 'alt-9', alertType: 'model', ...props }, global: { stubs: { teleport: true } } })
}

describe('AlertFeedbackDrawer', () => {
  beforeEach(() => {
    getMock.mockReset(); postMock.mockReset(); toastMock.mockReset()
    canMock.mockReset().mockImplementation(() => true)
  })

  it('submits a label with a trimmed note, reloads history and emits changed', async () => {
    getMock.mockResolvedValueOnce([fb()]).mockResolvedValueOnce([fb({ id: 2, reviewStatus: 'pending', secondReviewedAt: null, secondReviewerName: null, secondReviewReason: null }), fb()])
    postMock.mockResolvedValue(fb({ id: 2, reviewStatus: 'pending' }))
    const wrapper = mountDrawer({ status: 'acknowledged' })
    await flushPromises()

    expect(getMock).toHaveBeenCalledWith('/api/v1/alerts/9/feedback')
    expect(wrapper.text()).toContain('复核员乙')
    expect(wrapper.text()).toContain('证据不足')
    const submit = wrapper.get('button[type="submit"]')
    expect(submit.attributes('disabled')).toBeDefined()

    await wrapper.get('input[value="false_positive"]').setValue(true)
    await wrapper.get('textarea').setValue('  10:00 本机在执行系统更新，HTTPS 下载  ')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(postMock).toHaveBeenCalledWith('/api/v1/alerts/9/feedback', { label: 'false_positive', note: '10:00 本机在执行系统更新，HTTPS 下载' })
    expect(getMock).toHaveBeenCalledTimes(2)
    expect(wrapper.emitted('changed')).toHaveLength(1)
    expect(toastMock).toHaveBeenCalledWith(expect.stringContaining('误报'))
    // 已有待复核标注，表单隐藏
    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.text()).toContain('已有有效标注')
    wrapper.unmount()
  })

  it('does not offer the form for a closed alert', async () => {
    getMock.mockResolvedValue([])
    const wrapper = mountDrawer({ status: 'resolved' })
    await flushPromises()

    expect(wrapper.find('form').exists()).toBe(false)
    expect(wrapper.text()).toContain('已结案的告警不接受新标注')
    expect(postMock).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('reads the alert status when the caller does not provide it', async () => {
    getMock.mockImplementation((path: string) => Promise.resolve(path === '/api/v1/alerts/9' ? { id: 9, status: 'false_positive', alertType: 'model' } : []))
    const wrapper = mountDrawer({})
    await flushPromises()

    expect(getMock).toHaveBeenCalledWith('/api/v1/alerts/9')
    expect(wrapper.find('form').exists()).toBe(false)
    wrapper.unmount()
  })

  it('hides the form without the label permission and shows the backend error on conflict', async () => {
    canMock.mockImplementation((p: string) => p !== 'alert.feedback.label')
    getMock.mockResolvedValue([])
    const readonly = mountDrawer({ status: 'new' })
    await flushPromises()
    expect(readonly.find('form').exists()).toBe(false)
    readonly.unmount()

    canMock.mockImplementation(() => true)
    postMock.mockRejectedValue(new Error('该告警已有有效标注（request-id req-9）'))
    const wrapper = mountDrawer({ status: 'new' })
    await flushPromises()
    await wrapper.get('input[value="true_positive"]').setValue(true)
    await wrapper.get('textarea').setValue('依据')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(toastMock).toHaveBeenCalledWith('该告警已有有效标注（request-id req-9）', 'threat')
    expect(wrapper.emitted('changed')).toBeUndefined()
    wrapper.unmount()
  })
})
