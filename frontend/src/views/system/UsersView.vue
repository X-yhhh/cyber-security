<script setup lang="ts">
/**
 * 用户管理（系统管理 / Users，前端设计文档第 10.8 节，任务单 F5）。读写均需 iam.manage（全局）。
 *
 * 数据：GET /api/v2/users（q 前缀搜索、status、from、sort 由后端筛选并绑定游标）；GET /roles 与各角色 members 组成“角色索引”，
 * 让台账能直接显示每个用户的角色（≤10 个角色各读一页 200 条，超出时注明索引不完整）。
 * - 筛选同步到 URL；`?id=` 打开用户抽屉（角色管理成员列表与审计跳转复用）。
 * - 新建只建账号不授予角色；本人账号的所有管理按钮禁用并说明原因，后端仍以 403 拒绝。
 */
import { computed, ref, watch } from 'vue'
import { Lock, Plus, Search, ShieldCheck, UserCheck, UserMinus, Users, UserX } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import StatBand from '@/components/StatBand.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { countIf } from '@/components/viz'
import { useCursor } from '@/composables/cursor'
import { errText } from '@/composables/load'
import { queryString, useQueryState } from '@/composables/query'
import { toast } from '@/composables/toast'
import { session } from '@/api/session'
import { iamApi, type CreateUser, type IamUser } from '@/api/v2/iam'
import { roleName, rolesApi, type IamRole, type RoleMember } from '@/api/v2/roles'
import { iamUserTone } from '@/data/tones'
import { scopeText, SELF_REASON, userStatusLabel } from './shared'
import UserDrawer from './UserDrawer.vue'
import UserFormDrawer from './UserFormDrawer.vue'

const STATUSES = ['active', 'disabled', 'locked'] as const
const RANGES = { '7d': 7, '30d': 30, '90d': 90 } as const
type Range = keyof typeof RANGES | ''
const status = ref('')
const range = ref<Range>('')
const sort = ref<'' | 'updatedAt'>('')
const q = ref('')
const qDraft = ref('')
const openId = ref('')
useQueryState({
  q: { state: q, default: '', parse: (v) => queryString(v).trim().slice(0, 64) },
  status: { state: status, default: '', parse: (v) => ((STATUSES as readonly string[]).includes(queryString(v)) ? queryString(v) : '') },
  range: { state: range, default: '', parse: (v) => (queryString(v) in RANGES ? queryString(v) as Range : '') },
  sort: { state: sort, default: '', parse: (v) => (queryString(v) === 'updatedAt' ? 'updatedAt' : '') },
  id: { state: openId, default: '', parse: (v) => (/^[1-9]\d{0,18}$/.test(queryString(v)) ? queryString(v) : '') },
}, () => { qDraft.value = q.value })

const fromOf = (r: Range) => (r ? new Date(Date.now() - RANGES[r] * 864e5).toISOString() : undefined)
const users = useCursor<IamUser>((cursor) => iamApi.listUsers({ q: q.value || undefined, status: (status.value || undefined) as IamUser['status'] | undefined, from: fromOf(range.value), sort: sort.value || undefined, cursor }))
watch([status, q, range, sort], () => users.reset())

let typing: ReturnType<typeof setTimeout> | undefined
watch(qDraft, (v) => {
  clearTimeout(typing)
  typing = setTimeout(() => { q.value = v.trim().slice(0, 64) }, 350)
})

/* 角色目录与角色索引：用户 ID → 绑定（角色 + 范围）。只用于展示，绑定的增删仍在抽屉里重读。 */
type IndexedBinding = RoleMember & { roleKey: string }
const catalogue = ref<IamRole[]>([])
const index = ref(new Map<number, IndexedBinding[]>())
const indexPartial = ref(false)
const indexError = ref('')
const indexReady = ref(false)
let indexSeq = 0
async function loadIndex() {
  const mine = ++indexSeq
  indexError.value = ''
  try {
    const roles = await rolesApi.listRoles()
    const pages = await Promise.all(roles.map((r) => rolesApi.listMembers(r.roleKey, { limit: 200 })))
    if (mine !== indexSeq) return
    const map = new Map<number, IndexedBinding[]>()
    pages.forEach((p, i) => p.items.forEach((m) => map.set(m.id, [...(map.get(m.id) ?? []), { ...m, roleKey: roles[i].roleKey }])))
    catalogue.value = roles
    index.value = map
    indexPartial.value = pages.some((p) => !!p.nextCursor)
  } catch (e) { if (mine === indexSeq) indexError.value = errText(e) } finally { if (mine === indexSeq) indexReady.value = true }
}
void loadIndex()
const bindingsOf = (id: number) => index.value.get(id) ?? []
const roleOf = (key: string) => catalogue.value.find((r) => r.roleKey === key)

const me = computed(() => session.user?.id)
const stats = computed(() => {
  const loaded = !users.loading.value
  const items = users.items.value
  return [
    { key: 'page', label: '当前页用户', value: loaded ? items.length : undefined, icon: Users, hint: users.next.value ? '还有下一页' : '已到末页' },
    { key: 'active', label: '启用', value: loaded ? countIf(items, (u) => u.status === 'active') : undefined, icon: UserCheck, tone: 'ok' as const, hint: '按当前页统计' },
    { key: 'off', label: '停用或锁定', value: loaded ? countIf(items, (u) => u.status !== 'active') : undefined, icon: UserX, tone: 'warn' as const, hint: '按当前页统计' },
    { key: 'unbound', label: '未绑定角色', value: loaded && indexReady.value && !indexError.value ? countIf(items, (u) => !bindingsOf(u.id).length) : undefined, icon: UserMinus, hint: indexPartial.value ? '角色索引不完整，仅供参考' : '按当前页与角色成员索引' },
  ]
})

/** 角色分布：按已启用角色统计不同用户数（全体成员，不限当前页）。 */
const roleBars = computed(() => {
  const rows = catalogue.value.filter((r) => r.status === 'active').map((r) => {
    const ids = new Set<number>()
    for (const [id, list] of index.value) if (list.some((b) => b.roleKey === r.roleKey)) ids.add(id)
    return { key: r.roleKey, label: r.name, builtin: r.builtin, value: ids.size }
  })
  const max = Math.max(1, ...rows.map((r) => r.value))
  return rows.sort((a, b) => b.value - a.value).map((r) => ({ ...r, pct: Math.round((r.value / max) * 100) }))
})

const filtered = computed(() => !!(status.value || q.value || range.value))
const emptyText = computed(() => (filtered.value ? '当前筛选条件下没有用户。' : '还没有用户账号。'))
function clearFilters() { status.value = ''; range.value = ''; q.value = ''; qDraft.value = '' }

const open = (u: IamUser) => { openId.value = String(u.id) }
const avatar = (u: IamUser) => (u.displayName || u.username).trim().slice(0, 1).toUpperCase()

/* 新建 */
const formOpen = ref(false)
const busy = ref(false)
async function create(body: CreateUser) {
  busy.value = true
  try {
    const u = await iamApi.createUser(body)
    formOpen.value = false
    toast('已新建用户。新账号没有任何角色，请为其添加绑定。')
    users.reset()
    openId.value = String(u.id)
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
function changed() { users.reset(); void loadIndex() }
</script>

<template>
  <div>
    <PageHead title="用户管理" desc="人工账号与角色绑定。角色变更、停用或重置口令后，该用户的会话由后端撤销。">
      <button type="button" class="act" @click="formOpen = true"><Plus :size="15" :stroke-width="1.5" />新建用户</button>
    </PageHead>

    <StatBand class="mb-5" label="用户概览" :stats="stats" />

    <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_18rem]">
      <Panel title="用户台账" :icon="Users" flush>
        <template #actions>
          <select v-model="sort" class="field !h-7 !w-auto text-[12px]" aria-label="排序">
            <option value="">最近创建在前</option><option value="updatedAt">最近更新在前</option>
          </select>
        </template>
        <template #toolbar>
          <div class="toolbar w-full" role="search">
            <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
              <input v-model="qDraft" type="search" class="field !w-44" maxlength="64" placeholder="用户名或显示名" aria-label="搜索用户" />
            </label>
            <div class="chips" role="group" aria-label="账号状态">
              <button type="button" class="chip" :aria-pressed="status === ''" @click="status = ''">全部</button>
              <button v-for="s in STATUSES" :key="s" type="button" class="chip" :aria-pressed="status === s" @click="status = status === s ? '' : s">{{ userStatusLabel[s] }}</button>
            </div>
            <span class="toolbar-sep" aria-hidden="true" />
            <label class="toolbar-field">
              <select v-model="range" class="field" aria-label="创建时间范围">
                <option value="">创建时间不限</option><option value="7d">最近 7 天</option><option value="30d">最近 30 天</option><option value="90d">最近 90 天</option>
              </select>
            </label>
            <button v-if="filtered" type="button" class="link toolbar-end text-[12.5px]" @click="clearFilters">清除筛选</button>
          </div>
        </template>

        <LoadState :loading="users.loading.value" :error="users.error.value" :empty="!users.items.value.length" :empty-text="emptyText">
          <table class="table min-w-[720px]">
            <thead><tr><th>用户</th><th>角色与范围</th><th>状态</th><th class="text-right">编号</th></tr></thead>
            <tbody>
              <tr v-for="u in users.items.value" :key="u.id" class="row-link" tabindex="0" @click="open(u)" @keydown.enter="open(u)">
                <td class="max-w-[16rem]">
                  <span class="flex items-center gap-3">
                    <span class="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-ink-line text-[12.5px] font-medium" :class="u.status === 'active' ? 'text-ink' : 'text-ink-4'" aria-hidden="true">{{ avatar(u) }}</span>
                    <span class="min-w-0">
                      <span class="flex items-center gap-2">
                        <span class="truncate font-medium text-ink">{{ u.displayName || u.username }}</span>
                        <span v-if="u.id === me" class="shrink-0 rounded-sm bg-paper-soft px-1.5 text-[11px] text-ink-3" :title="SELF_REASON">本人</span>
                      </span>
                      <span class="num block truncate text-[11.5px] text-ink-4">{{ u.username }}</span>
                    </span>
                  </span>
                </td>
                <td class="max-w-[22rem]">
                  <span v-if="!indexReady" class="text-[12px] text-ink-4">读取中…</span>
                  <span v-else-if="indexError" class="text-[12px] text-ink-4">—</span>
                  <span v-else-if="!bindingsOf(u.id).length" class="text-[12.5px] text-ink-4">未绑定角色</span>
                  <span v-else class="flex flex-wrap gap-1.5">
                    <span v-for="b in bindingsOf(u.id)" :key="b.bindingId" class="inline-flex items-center gap-1 rounded-sm border border-ink-line px-1.5 py-px text-[12px]"
                      :class="roleOf(b.roleKey)?.status === 'disabled' ? 'text-ink-4 line-through' : 'text-ink-2'" :title="roleOf(b.roleKey)?.status === 'disabled' ? '角色已停用，不产生权限' : undefined">
                      {{ roleName(b.roleKey, catalogue) }}<span v-if="b.scopeType !== 'global'" class="num text-[11px] text-ink-4">{{ scopeText(b) }}</span>
                    </span>
                  </span>
                </td>
                <td class="whitespace-nowrap"><Tag pill :tone="iamUserTone[u.status]" :label="userStatusLabel[u.status] ?? u.status" /></td>
                <td class="num whitespace-nowrap text-right text-ink-3">#{{ u.id }}</td>
              </tr>
            </tbody>
          </table>
        </LoadState>
        <template #foot>
          <CursorPager :count="users.items.value.length" :has-next="!!users.next.value" :has-prev="!!users.stack.value.length"
            :busy="users.turning.value" label="用户" @next="users.forward()" @prev="users.back()" />
        </template>
      </Panel>

      <aside class="space-y-4 xl:sticky xl:top-20">
        <Panel title="角色分布" :icon="ShieldCheck" :desc="indexPartial ? '部分角色成员超过 200 人，计数不完整' : '按全部用户的启用角色统计人数'">
          <p v-if="indexError" class="text-[12.5px] text-ink-3" role="alert">{{ indexError }}</p>
          <p v-else-if="!indexReady" class="text-[12.5px] text-ink-4">正在读取角色成员…</p>
          <ul v-else class="space-y-2.5">
            <li v-for="r in roleBars" :key="r.key">
              <RouterLink :to="{ path: '/console/system/roles', query: { role: r.key } }" class="group block">
                <span class="flex items-baseline justify-between gap-2 text-[12.5px]">
                  <span class="truncate text-ink-2 group-hover:text-ink">{{ r.label }}<span v-if="!r.builtin" class="ml-1.5 text-[11px] text-ink-4">自定义</span></span>
                  <span class="num text-ink">{{ r.value }}</span>
                </span>
                <span class="mt-1 block h-1.5 overflow-hidden rounded-full bg-paper-soft"><span class="block h-full rounded-full bg-ink-3 transition-[width] duration-500" :style="{ width: `${r.pct}%` }" /></span>
              </RouterLink>
            </li>
          </ul>
        </Panel>
        <Panel title="管理规则" :icon="Lock">
          <ul class="space-y-3 text-[12.5px] leading-relaxed">
            <li><span class="text-ink">不能管理本人</span><span class="block text-ink-3">本人账号的编辑、停用、重置口令与绑定均不可用。</span></li>
            <li><span class="text-ink">职责分离</span><span class="block text-ink-3">申请与审批类权限不能落在同一人身上；审计员不能兼任其他角色。</span></li>
            <li><span class="text-ink">保留平台管理员</span><span class="block text-ink-3">至少保留一位有效的全局平台管理员。</span></li>
            <li><span class="text-ink">只停用不删除</span><span class="block text-ink-3">删除只用于没有绑定和审计引用的账号，其余请停用。</span></li>
          </ul>
        </Panel>
      </aside>
    </div>

    <UserDrawer :id="openId" :catalogue="catalogue" @close="openId = ''" @changed="changed" />
    <UserFormDrawer :open="formOpen" :busy="busy" @create="create" @close="formOpen = false" />
  </div>
</template>
