import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const { getMock, canMock } = vi.hoisted(() => ({ getMock: vi.fn(), canMock: vi.fn() }))
vi.mock('@/api/client', () => ({ api: { get: getMock } }))
vi.mock('@/api/session', () => ({ can: canMock }))
vi.mock('@/composables/reveal', () => ({ vReveal: { mounted: vi.fn() } }))

import OverviewView from './OverviewView.vue'

describe('overview operations summary', () => {
  beforeEach(() => {
    getMock.mockReset()
    canMock.mockImplementation((permission: string) => permission === 'ops.status.read')
    getMock.mockImplementation((path: string) => {
      if (path === '/ops/status') return Promise.resolve({
        outboxPending: 3,
        outboxFailed: 1,
        outboxDeadLetter: 0,
        oldestPendingAgeSeconds: 75,
        averagePublishedDelaySeconds24h: 2.5,
        sensorsOnline: 2,
        sensorsHeartbeatTimeout: 1,
        ingestRejectionRatio24h: 0.125,
        loginThrottleBlocked: 4,
        loginThrottleFailures15m: 6,
      })
      if (path === '/overview') return Promise.resolve({ hourlyAlerts: [], quality24h: { accepted: 0, manualReview: 0, rejected: 0 } })
      return Promise.resolve([])
    })
  })

  it('loads the protected runtime summary and renders only aggregated operational counts', async () => {
    const wrapper = mount(OverviewView, {
      global: {
        stubs: ['RouterLink', 'PageHead', 'Metric', 'Tag', 'LoadState'],
        directives: { reveal: () => undefined },
      },
    })
    await flushPromises()

    expect(getMock).toHaveBeenCalledWith('/ops/status')
    expect(wrapper.text()).toContain('运行摘要')
    expect(wrapper.text()).toContain('失败 1 · 死信 0')
    expect(wrapper.text()).toContain('12.5%')
    expect(wrapper.text()).toContain('75s')
    expect(wrapper.text()).toContain('过去 24 小时平均 3s')
    expect(wrapper.text()).not.toContain('jdbc:')
    wrapper.unmount()
  })

  it('does not request or render the summary without the dedicated permission', async () => {
    canMock.mockReturnValue(false)
    const wrapper = mount(OverviewView, {
      global: {
        stubs: ['RouterLink', 'PageHead', 'Metric', 'Tag', 'LoadState'],
        directives: { reveal: () => undefined },
      },
    })
    await flushPromises()

    expect(getMock).not.toHaveBeenCalledWith('/ops/status')
    expect(wrapper.text()).not.toContain('运行摘要')
    wrapper.unmount()
  })
})
