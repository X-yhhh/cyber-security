import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import Drawer from './Drawer.vue'

afterEach(() => { document.body.innerHTML = ''; vi.restoreAllMocks() })

describe('详情抽屉键盘操作', () => {
  it('初次挂载即打开时，Escape 也能请求关闭并在关闭后归还焦点', async () => {
    const trigger = document.createElement('button')
    document.body.append(trigger)
    trigger.focus()
    const wrapper = mount(Drawer, { props: { open: true, title: '长告警键'.repeat(30) }, attachTo: document.body })
    await nextTick()
    expect(document.activeElement?.tagName).toBe('H2')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(wrapper.emitted('close')).toHaveLength(1)
    await wrapper.setProps({ open: false })
    expect(document.activeElement).toBe(trigger)
    wrapper.unmount()
  })

  it('Tab 与 Shift+Tab 在模态控件之间循环', async () => {
    // jsdom 不进行布局；只为此键盘测试模拟可见控件的几何信息。
    vi.spyOn(HTMLElement.prototype, 'getClientRects').mockReturnValue([{}] as unknown as DOMRectList)
    const wrapper = mount(Drawer, { props: { open: true, title: '详情' }, slots: { default: '<input aria-label="理由" />' }, attachTo: document.body })
    await nextTick()
    const close = document.querySelector<HTMLButtonElement>('button[aria-label="关闭"]')!
    const input = document.querySelector<HTMLInputElement>('input')!
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, cancelable: true }))
    expect(document.activeElement).toBe(input)
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', cancelable: true }))
    expect(document.activeElement).toBe(close)
    wrapper.unmount()
  })
})
