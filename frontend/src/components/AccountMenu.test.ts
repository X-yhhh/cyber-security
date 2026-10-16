/**
 * 账户菜单修改口令：就地校验（长度、新旧相同、两次一致）在满足前禁用“修改”，后端错误写在抽屉内；
 * 提示层高于抽屉。不连接真实后端，changePassword 以模拟替代。
 */
import { mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'

const changePassword = vi.fn()
vi.mock('@/api/session', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/api/session')>()
  return { ...actual, changePassword: (...a: unknown[]) => changePassword(...a) }
})

import AccountMenu from './AccountMenu.vue'
import ToastHost from './ToastHost.vue'
import { session } from '@/api/session'
import { singleRoleUsers } from '@/test/roles'

const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', name: 'login', component: { render: () => null } }] })

beforeEach(() => { session.user = singleRoleUsers.auditor as unknown as typeof session.user; changePassword.mockReset() })
afterEach(() => { session.user = null; document.body.innerHTML = '' })

async function open() {
  const w = mount(AccountMenu, { global: { plugins: [router] }, attachTo: document.body })
  await w.findAll('button').find((b) => b.text().includes('修改口令'))!.trigger('click')
  await nextTick()
  const inputs = [...document.querySelectorAll<HTMLInputElement>('aside input[type="password"]')]
  const submit = [...document.querySelectorAll<HTMLButtonElement>('aside button')].find((b) => b.textContent?.trim() === '修改')!
  const fill = async (current: string, next: string, confirm: string) => {
    for (const [el, v] of [[inputs[0], current], [inputs[1], next], [inputs[2], confirm]] as const) {
      el.value = v
      el.dispatchEvent(new Event('input'))
    }
    await nextTick()
  }
  return { w, submit, fill, problem: () => document.querySelector('[data-password-problem]')?.textContent ?? '' }
}

describe('修改口令', () => {
  it('新口令不足 12 个字符时就地说明原因并禁用“修改”，不发请求', async () => {
    const { w, submit, fill, problem } = await open()
    await fill('old-password-123', 'abcde', 'abcde')
    expect(problem()).toContain('至少 12 个字符，当前 5 个')
    expect(submit.disabled).toBe(true)
    submit.click()
    expect(changePassword).not.toHaveBeenCalled()
    w.unmount()
  })

  it('新旧相同或两次不一致时同样就地提示', async () => {
    const { w, submit, fill, problem } = await open()
    await fill('same-password-1', 'same-password-1', 'same-password-1')
    expect(problem()).toContain('不能与当前口令相同')
    await fill('old-password-123', 'new-password-456', 'new-password-457')
    expect(problem()).toContain('两次输入的新口令不一致')
    expect(submit.disabled).toBe(true)
    w.unmount()
  })

  it('满足规则后可提交；后端拒绝时错误写在抽屉内', async () => {
    changePassword.mockRejectedValueOnce(Object.assign(new Error('当前口令不正确'), { status: 401, code: 'AUTH_INVALID', requestId: 'req-pw' }))
    const { w, submit, fill } = await open()
    await fill('old-password-123', 'new-password-456', 'new-password-456')
    expect(submit.disabled).toBe(false)
    submit.click()
    await vi.waitFor(() => expect(document.querySelector('[data-password-failure]')).not.toBeNull())
    expect(changePassword).toHaveBeenCalledWith('old-password-123', 'new-password-456')
    w.unmount()
  })

  it('提示层叠放在抽屉之上', () => {
    const t = mount(ToastHost)
    expect(t.get('[aria-live]').classes()).toContain('z-[60]')
    t.unmount()
  })
})
