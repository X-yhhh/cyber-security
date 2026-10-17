/** jsdom 只模拟 dialog 开关，顶层遮挡和原生焦点隔离另由浏览器验证。 */
import { mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick, reactive } from 'vue'
import ToastHost from './ToastHost.vue'
import Drawer from './Drawer.vue'
import { alerts, dismissToast, toast, toasts } from '@/composables/toast'
import { useActionError } from '@/composables/actionError'

beforeEach(() => {
  alerts.splice(0); toasts.splice(0)
  vi.useFakeTimers()
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value: function (this: HTMLDialogElement) { this.open = true } })
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value: function (this: HTMLDialogElement) { this.open = false } })
})
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); alerts.splice(0); toasts.splice(0); document.body.innerHTML = '' })
const currentDialog = () => document.querySelector<HTMLDialogElement>('dialog')!
const confirm = () => currentDialog().querySelector<HTMLButtonElement>('button')!

describe('全局系统警告', () => {
  it('错误持续显示、同条去重，多条逐一确认，成功提示自动消失', async () => {
    const w = mount(ToastHost, { attachTo: document.body })
    toast('保存失败（request-id demo-1）', 'threat')
    toast('保存失败（request-id demo-1）', 'threat')
    toast('请填写理由', 'warn'); toast('已保存')
    await nextTick()
    expect(currentDialog().open).toBe(true)
    expect(document.activeElement).toBe(confirm())
    expect(currentDialog().textContent).toContain('操作未完成')
    expect(currentDialog().textContent).toContain('request-id demo-1')
    for (const shiftKey of [false, true]) {
      const key = new KeyboardEvent('keydown', { key: 'Tab', shiftKey, bubbles: true, cancelable: true })
      confirm().dispatchEvent(key)
      expect(key.defaultPrevented).toBe(true)
      expect(document.activeElement).toBe(confirm())
    }
    vi.advanceTimersByTime(60_000)
    expect(alerts).toHaveLength(2); expect(toasts).toHaveLength(0)
    confirm().click(); await nextTick()
    expect(currentDialog().textContent).toContain('请注意')
    expect(currentDialog().textContent).toContain('请填写理由')
    confirm().click(); await nextTick()
    expect(currentDialog().open).toBe(false)
    w.unmount()
  })
  it('Escape 只关闭警告，返回原操作焦点且抽屉仍在', async () => {
    const drawer = mount(Drawer, { props: { open: true, title: '修改口令' }, slots: { default: '<input aria-label="当前口令" />' }, attachTo: document.body })
    const host = mount(ToastHost, { attachTo: document.body }); await nextTick()
    const input = document.querySelector<HTMLInputElement>('input')!
    input.focus()
    toast('当前口令不正确', 'threat'); await nextTick()
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(drawer.emitted('close')).toBeUndefined()
    currentDialog().dispatchEvent(new Event('cancel', { cancelable: true })); await nextTick()
    expect(currentDialog().open).toBe(false)
    expect(document.activeElement).toBe(input)
    expect(drawer.emitted('close')).toBeUndefined()
    host.unmount(); drawer.unmount()
  })
  it('挂载前的错误不丢失，文案按纯文本显示，背景点击不关闭', async () => {
    toast('<img src=x onerror=alert(1)>', 'threat')
    const w = mount(ToastHost, { attachTo: document.body }); await nextTick()
    expect(currentDialog().open).toBe(true)
    expect(currentDialog().querySelector('img')).toBeNull()
    currentDialog().click(); await nextTick()
    expect(alerts).toHaveLength(1)
    w.unmount()
  })
  it('确认后相同错误再次提醒，清空表单不误清警告', () => {
    const form = reactive({ error: useActionError() })
    form.error = '权限不足'
    expect(form.error).toBe('权限不足')
    dismissToast(alerts[0]!.id)
    form.error = '权限不足'
    expect(alerts).toHaveLength(1)
    form.error = ''
    expect(form.error).toBe(''); expect(alerts).toHaveLength(1)
  })
  it('提交按钮请求中失焦后，确认仍恢复该操作位置', async () => {
    const host = mount(ToastHost, { attachTo: document.body }); await nextTick()
    const submit = document.createElement('button')
    document.body.append(submit); submit.focus(); submit.blur()
    toast('保存失败', 'threat'); await nextTick()
    confirm().click(); await nextTick()
    expect(document.activeElement).toBe(submit)
    host.unmount()
  })
})
