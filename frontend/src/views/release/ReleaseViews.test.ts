/**
 * 发布管理页面行为验收。FE-16a：组合、策略、lab 会话按 BE-25 归属字段隐藏本人审批入口，
 * 覆盖“本人、他人、空”三种情况；字段为空时入口照常显示，自批由后端 403 拦截（前端不拦截提交）。
 * FE-16c 的其余用例在此文件续写。MSW 夹具不替代后端职责分离与发布资格验收。
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
import { resetAssetsState } from '@/test/handlers/assets'
import { RELEASE_IDS, RELEASE_SHA, releaseState, resetReleaseState } from '@/test/handlers/release'
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
async function fill(label: string, value: string) {
  const field = dialog().findAll('label').find((l) => l.find('.label').exists() && l.find('.label').text() === label)
  expect(field, `缺少字段 ${label}`).toBeTruthy()
  await field!.get('input,select,textarea').setValue(value)
}

beforeAll(() => { server.listen({ onUnhandledRequest: 'error' }); window.scrollTo = () => undefined; Element.prototype.scrollIntoView = () => undefined })
afterAll(() => server.close())
beforeEach(() => {
  resetReleaseState(); resetDetectState(); resetAssetsState(); resetCsrf(); resetSummaryCache()
  session.user = null; session.checked = false; requests.length = 0; toasts.length = 0; alerts.length = 0
  localStorage.clear(); sessionStorage.clear()
})
afterEach(() => dispose())

const operator = singleRoleUsers.model_operator
/** 与起草/申请人同一账户 ID 的审核身份：只用于构造“本人”情况，真实环境中角色互斥不会同时持有。 */
const selfReviewer = () => me(['security_reviewer'], operator.id, 'demo-self-reviewer')
const otherReviewer = singleRoleUsers.security_reviewer
type Owner = number | string | null
const bundleRow = () => releaseState.rows['release-bundles'].find((r) => r.id === RELEASE_IDS.bundle)!
const approvedBundle = () => releaseState.rows['release-bundles'].find((r) => r.id === RELEASE_IDS.approvedBundle)!
const policyRow = () => releaseState.rows['decision-policies'].find((r) => r.id === RELEASE_IDS.policy)!
const labRow = () => releaseState.rows['lab-validation-runs'].find((r) => r.id === RELEASE_IDS.lab)!

const decisionCases = [
  {
    title: '发布组合', path: `/console/release/bundles?tab=bundles&id=${RELEASE_IDS.bundle}`, approve: '批准组合', confirm: '确认批准',
    write: `POST /api/v2/release-bundles/${RELEASE_IDS.bundle}/decisions`,
    setup: (by: Owner) => Object.assign(bundleRow(), { status: 'evaluated', sealedManifestSha256: RELEASE_SHA, sealedManifest: { reports: [RELEASE_IDS.evaluation] }, requestedBy: by }),
    status: () => bundleRow().status, pending: 'evaluated',
  },
  {
    title: '决策策略', path: `/console/release/bundles?tab=policies&id=${RELEASE_IDS.policy}`, approve: '审核通过', confirm: '确认审核通过',
    write: `POST /api/v2/decision-policies/${RELEASE_IDS.policy}/reviews`,
    setup: (by: Owner) => Object.assign(policyRow(), { createdBy: by }),
    status: () => policyRow().status, pending: 'draft',
  },
  {
    title: 'lab 会话', path: `/console/release/bundles?tab=validation&record=lab&id=${RELEASE_IDS.lab}`, approve: '批准资格', confirm: '确认批准',
    write: `POST /api/v2/lab-validation-runs/${RELEASE_IDS.lab}/decisions`,
    setup: (by: Owner) => Object.assign(labRow(), { requestedBy: by }),
    status: () => labRow().eligibilityStatus, pending: 'pending',
  },
]

describe('FE-16a 本人审批入口隐藏', () => {
  it.each(decisionCases)('$title：他人申请显示批准与驳回', async (c) => {
    c.setup(operator.id)
    await open(otherReviewer, c.path)
    expect(button(c.approve)).toBeTruthy(); expect(button('驳回')).toBeTruthy()
    expect(dialog().text()).not.toContain(SELF_APPROVAL_NOTE)
  })

  it.each(decisionCases)('$title：本人申请隐藏批准与驳回并说明需他人审批（数字字符串同口径）', async (c) => {
    for (const by of [operator.id, String(operator.id)]) {
      c.setup(by)
      await open(selfReviewer(), c.path)
      expect(button(c.approve)).toBeUndefined(); expect(button('驳回')).toBeUndefined()
      expect(dialog().get('[role="status"]').text()).toContain(SELF_APPROVAL_NOTE)
    }
    expect(requests.filter((r) => r.startsWith('POST '))).toEqual([])
  })

  it.each(decisionCases)('$title：归属为空或不是数字 ID 时照常显示，自批由后端 403 拒绝且状态不变', async (c) => {
    c.setup('demo-operator')
    await open(selfReviewer(), c.path)
    expect(button(c.approve)).toBeTruthy()
    c.setup(null)
    await open(selfReviewer(), c.path)
    expect(dialog().text()).not.toContain(SELF_APPROVAL_NOTE)
    await click(c.approve); await fill('理由', '自批尝试'); await click(c.confirm)
    expect(requests.filter((r) => r === c.write)).toHaveLength(1)
    const error = dialog().get('[role="alert"]').text()
    expect(error).toContain('必须由另一位具有权限的用户审核'); expect(error).toContain('request-id req-release-error')
    expect(c.status()).toBe(c.pending)
  })

  it('组合激活：本人申请隐藏，他人与空值显示', async () => {
    const path = `/console/release/bundles?tab=bundles&id=${RELEASE_IDS.approvedBundle}`
    approvedBundle().requestedBy = operator.id
    await open(me(['security_reviewer'], operator.id), path)
    expect(button('按资产激活')).toBeUndefined()
    expect(dialog().get('[role="status"]').text()).toContain(SELF_APPROVAL_NOTE)
    await open(otherReviewer, path)
    expect(button('按资产激活')).toBeTruthy()
    approvedBundle().requestedBy = null
    await open(me(['security_reviewer'], operator.id), path)
    expect(button('按资产激活')).toBeTruthy()
  })

  it('策略草稿删除：本人与空值显示，他人起草不显示', async () => {
    const path = `/console/release/bundles?tab=policies&id=${RELEASE_IDS.policy}`
    await open(operator, path)
    expect(button('删除草稿')).toBeTruthy()
    await open(me(['model_operator'], 999, 'demo-operator-2'), path)
    expect(button('删除草稿')).toBeUndefined()
    policyRow().createdBy = null
    await open(me(['model_operator'], 999, 'demo-operator-2'), path)
    expect(button('删除草稿')).toBeTruthy()
  })
})
