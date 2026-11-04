/**
 * 处置记录页面行为验收。FE-16a：人工处置按 BE-25 的 createdBy 隐藏本人批准与驳回，
 * 覆盖“本人、他人、空”三种情况；空值照常显示，自批由后端 403 拦截。FE-16d 的其余用例在此文件续写。
 */
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import { createMemoryHistory, RouterView } from 'vue-router'
import { createAppRouter } from '@/router'
import { resetCsrf } from '@/api/client'
import { session } from '@/api/session'
import { SELF_APPROVAL_NOTE } from '@/composables/owner'
import { resetSummaryCache } from '@/composables/summary'
import { alerts, toasts } from '@/composables/toast'
import { server, requests } from '@/test/handlers'
import { signIn } from '@/test/handlers/auth'
import { resetDetectState } from '@/test/handlers/detect'
import { ACTION_PENDING, resetResponseState, responseState } from '@/test/handlers/response'
import { me, singleRoleUsers, type MeFixture } from '@/test/roles'

const Host = defineComponent({ render: () => h(RouterView) })
let wrapper: VueWrapper | null = null
async function settle() {
  for (let i = 0; i < 8; i++) { await flushPromises(); await new Promise((r) => setTimeout(r, 0)) }
}
function dispose() { wrapper?.unmount(); wrapper = null; document.body.innerHTML = '' }
async function open(user: MeFixture, path: string) {
  dispose()
  signIn(user); session.user = { ...user, permissions: [...user.permissions] }; session.checked = true
  const router = createAppRouter(createMemoryHistory())
  await router.push(path); await router.isReady()
  wrapper = mount(Host, { global: { plugins: [router] }, attachTo: document.body })
  await settle()
  return { router, w: wrapper }
}
const dialog = () => new DOMWrapper(document.body.querySelector<HTMLElement>('[role="dialog"]')!)
const button = (text: string, root: ParentNode = document.body) => Array.from(root.querySelectorAll('button')).find((b) => b.textContent?.trim() === text)
async function click(text: string, root?: ParentNode) {
  const el = button(text, root); expect(el, `缺少按钮 ${text}`).toBeTruthy(); el!.click(); await settle()
}

beforeAll(() => { server.listen({ onUnhandledRequest: 'error' }); window.scrollTo = () => undefined; Element.prototype.scrollIntoView = () => undefined })
afterAll(() => server.close())
beforeEach(() => {
  resetResponseState(); resetDetectState(); resetCsrf(); resetSummaryCache()
  session.user = null; session.checked = false; requests.length = 0; toasts.length = 0; alerts.length = 0
  localStorage.clear(); sessionStorage.clear()
})
afterEach(() => dispose())

const path = `/console/response/actions?tab=all&id=${ACTION_PENDING}`
const analyst = singleRoleUsers.security_analyst
/** 与申请人同一账户 ID 的审批身份：只用于构造“本人”情况。 */
const selfReviewer = () => me(['security_reviewer'], analyst.id, 'demo-self-reviewer')
const pending = () => responseState.actions.find((r) => r.action.id === ACTION_PENDING)!

describe('FE-16a 本人处置申请隐藏批准', () => {
  it('他人申请：显示批准与驳回', async () => {
    await open(singleRoleUsers.security_reviewer, path)
    expect(button('批准')).toBeTruthy(); expect(button('驳回')).toBeTruthy()
    expect(dialog().text()).not.toContain(SELF_APPROVAL_NOTE)
  })

  it('本人申请：隐藏批准与驳回并说明需他人审批，撤销入口不受影响', async () => {
    await open(selfReviewer(), path)
    expect(button('批准')).toBeUndefined(); expect(button('驳回')).toBeUndefined()
    expect(dialog().get('[role="status"]').text()).toContain(SELF_APPROVAL_NOTE)
    expect(button('撤销')).toBeTruthy()
    expect(requests.filter((r) => r.startsWith('POST '))).toEqual([])
  })

  it('归属为空或不是数字 ID：照常显示，自批由后端 403 拒绝，动作仍待批', async () => {
    pending().action.createdBy = analyst.username
    await open(selfReviewer(), path)
    expect(button('批准')).toBeTruthy()
    pending().action.createdBy = null
    await open(selfReviewer(), path)
    expect(dialog().text()).not.toContain(SELF_APPROVAL_NOTE)
    await dialog().get('textarea').setValue('自批尝试')
    await click('批准')
    expect(requests.filter((r) => r === `POST /api/v2/actions/${ACTION_PENDING}/decisions`)).toHaveLength(1)
    expect(alerts.some((a) => a.text.includes('request-id'))).toBe(true)
    expect(pending().action.observedState).toBe('pending'); expect(pending().approvedBy).toBeNull()
  })
})
