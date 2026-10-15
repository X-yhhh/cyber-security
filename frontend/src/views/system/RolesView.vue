<script setup lang="ts">
/**
 * 角色管理（系统管理 / Roles，前端设计文档第 10.8 节，任务单 F5）。查看需 iam.manage 或 audit.read，写入与成员需 iam.manage。
 *
 * 数据：GET /api/v2/roles 返回全量数组（≤10 个启用角色 + 停用角色），搜索与状态筛选在已加载数组上进行并同步 URL，
 * 读数带与名额始终按全量计算；`?role=` 打开角色抽屉。
 * 主视觉为“权限矩阵”：行是权限设计第 4 节分组的 25 个人工权限（中文说明），列是角色。
 * 内置角色只读；自定义角色可新建、编辑、停用/启用与删除，冲突权限对与名额上限在表单中实时提示，最终以后端为准。
 */
import { computed, ref } from 'vue'
import { Check, Gauge, Layers, Plus, Search, ShieldCheck, ShieldOff, UserCog } from 'lucide-vue-next'
import PageHead from '@/components/PageHead.vue'
import Panel from '@/components/Panel.vue'
import StatBand from '@/components/StatBand.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import { countIf } from '@/components/viz'
import { errText } from '@/composables/load'
import { queryString, useQueryState } from '@/composables/query'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { conflictPairs, permissionGroups, roleLimitReached, rolesApi, type IamRole, type RoleDefinition } from '@/api/v2/roles'
import { roleStatusTone } from '@/data/tones'
import { permText, roleStatusLabel } from './shared'
import RoleDrawer from './RoleDrawer.vue'
import RoleFormDrawer from './RoleFormDrawer.vue'

const manage = can('iam.manage')

const status = ref<'' | 'active' | 'disabled'>('')
const kind = ref<'' | 'builtin' | 'custom'>('')
const q = ref('')
const openKey = ref('')
useQueryState({
  q: { state: q, default: '', parse: (v) => queryString(v).trim().slice(0, 64) },
  status: { state: status, default: '', parse: (v) => (['active', 'disabled'].includes(queryString(v)) ? queryString(v) as 'active' | 'disabled' : '') },
  kind: { state: kind, default: '', parse: (v) => (['builtin', 'custom'].includes(queryString(v)) ? queryString(v) as 'builtin' | 'custom' : '') },
  role: { state: openKey, default: '', parse: (v) => (/^[a-z][a-z0-9_]{0,63}$/.test(queryString(v)) ? queryString(v) : '') },
})

const roles = ref<IamRole[]>([])
const loading = ref(true)
const error = ref('')
let seq = 0
async function load() {
  const mine = ++seq
  error.value = ''
  try {
    const list = await rolesApi.listRoles()
    if (mine === seq) roles.value = list
  } catch (e) { if (mine === seq) error.value = errText(e) } finally { if (mine === seq) loading.value = false }
}
void load()

/** 内置在前（按权限设计第 3.1 节顺序由后端返回），启用在前。 */
const shown = computed(() => {
  const needle = q.value.toLowerCase()
  return roles.value
    .filter((r) => (!status.value || r.status === status.value) && (!kind.value || (kind.value === 'builtin') === r.builtin)
      && (!needle || r.name.toLowerCase().includes(needle) || r.roleKey.includes(needle)))
    .sort((a, b) => Number(b.status === 'active') - Number(a.status === 'active'))
})
const filtered = computed(() => !!(status.value || kind.value || q.value))
function clearFilters() { status.value = ''; kind.value = ''; q.value = '' }

const activeCount = computed(() => countIf(roles.value, (r) => r.status === 'active'))
const full = computed(() => roleLimitReached(roles.value))
const stats = computed(() => [
  { key: 'active', label: '启用人工角色', value: loading.value || error.value ? undefined : `${activeCount.value} / 8`, icon: ShieldCheck, hint: '另有 2 个机器模板，合计上限 10' },
  { key: 'builtin', label: '内置角色', value: loading.value || error.value ? undefined : countIf(roles.value, (r) => r.builtin), icon: Layers, hint: '含已停用的 v1 角色，只读' },
  { key: 'custom', label: '自定义角色', value: loading.value || error.value ? undefined : countIf(roles.value, (r) => !r.builtin), icon: UserCog, tone: 'signal' as const, hint: '最多启用 2 个' },
  { key: 'disabled', label: '已停用', value: loading.value || error.value ? undefined : countIf(roles.value, (r) => r.status === 'disabled'), icon: ShieldOff, hint: '停用角色不产生权限、不占名额' },
])

/** 名额格：2 个机器模板 + 启用人工角色 + 空位，共 10 格。 */
const slots = computed(() => {
  const active = roles.value.filter((r) => r.status === 'active')
  return [
    ...['采集器', '执行器'].map((name) => ({ key: `m-${name}`, kind: 'machine' as const, name })),
    ...active.map((r) => ({ key: r.roleKey, kind: r.builtin ? 'builtin' as const : 'custom' as const, name: r.name })),
    ...Array.from({ length: Math.max(0, 8 - active.length) }, (_, i) => ({ key: `e-${i}`, kind: 'empty' as const, name: '空位' })),
  ]
})
const slotClass = { machine: 'bg-ink-4', builtin: 'bg-ink', custom: 'bg-signal', empty: 'border border-dashed border-ink-line bg-paper' }

const has = (r: IamRole, p: string) => r.permissions.includes(p)
const conflictOf = (r: IamRole) => conflictPairs.filter(([a, b]) => has(r, a) && has(r, b))

const open = (r: IamRole) => { openKey.value = r.roleKey }

/* 新建 / 编辑 */
const form = ref<{ open: boolean; role: IamRole | null }>({ open: false, role: null })
const busy = ref(false)
function startCreate() { form.value = { open: true, role: null } }
function startEdit(r: IamRole) { openKey.value = ''; form.value = { open: true, role: r } }
async function create(body: RoleDefinition) {
  busy.value = true
  try {
    const r = await rolesApi.createRole(body)
    form.value = { open: false, role: null }
    toast(`已新建自定义角色「${r.name}」。可在用户管理中为用户添加绑定。`)
    await load()
    openKey.value = r.roleKey
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
async function update(body: Partial<Omit<RoleDefinition, 'roleKey'>>) {
  const r = form.value.role
  if (!r) return
  busy.value = true
  try {
    await rolesApi.updateRole(r.roleKey, r.revision, body)
    form.value = { open: false, role: null }
    toast(body.permissions ? '已保存角色，已绑定成员的会话已撤销。' : '已保存角色。')
    await load()
    openKey.value = r.roleKey
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
</script>

<template>
  <div>
    <PageHead title="角色管理" :desc="manage ? '内置角色只读；自定义角色只能从人工权限中选择，且不能包含互斥的申请与审批权限。' : '只读查看角色及其权限；成员与写入需身份与访问管理权限。'">
      <button v-if="manage" type="button" class="act" :disabled="full || loading" :title="full ? '启用角色已达上限，请先停用一个角色。' : undefined" @click="startCreate">
        <Plus :size="15" :stroke-width="1.5" />新建自定义角色
      </button>
    </PageHead>

    <StatBand class="mb-5" label="角色概览" :stats="stats" />

    <Panel title="权限矩阵" :icon="ShieldCheck" flush>
      <template #actions><span class="text-[12px] text-ink-3">点击列头查看角色</span></template>
      <template #toolbar>
        <div class="toolbar w-full" role="search">
          <label class="toolbar-field"><Search :size="14" :stroke-width="1.5" aria-hidden="true" />
            <input v-model="q" type="search" class="field !w-48" maxlength="64" placeholder="按名称或角色键筛选" aria-label="筛选角色" />
          </label>
          <div class="chips" role="group" aria-label="角色状态">
            <button type="button" class="chip" :aria-pressed="status === ''" @click="status = ''">全部</button>
            <button type="button" class="chip" :aria-pressed="status === 'active'" @click="status = status === 'active' ? '' : 'active'">启用</button>
            <button type="button" class="chip" :aria-pressed="status === 'disabled'" @click="status = status === 'disabled' ? '' : 'disabled'">已停用</button>
          </div>
          <span class="toolbar-sep" aria-hidden="true" />
          <div class="chips" role="group" aria-label="角色类型">
            <button type="button" class="chip" :aria-pressed="kind === 'builtin'" @click="kind = kind === 'builtin' ? '' : 'builtin'">内置</button>
            <button type="button" class="chip" :aria-pressed="kind === 'custom'" @click="kind = kind === 'custom' ? '' : 'custom'">自定义</button>
          </div>
          <button v-if="filtered" type="button" class="link toolbar-end text-[12.5px]" @click="clearFilters">清除筛选</button>
        </div>
      </template>

      <LoadState :loading="loading" :error="error" :empty="!shown.length" :empty-text="filtered ? '当前筛选条件下没有角色。' : '角色目录为空。'">
        <table class="table matrix" :style="{ minWidth: `${16 + shown.length * 5.75}rem` }">
          <thead>
            <tr>
              <th class="w-64 align-bottom">权限</th>
              <th v-for="r in shown" :key="r.roleKey" class="w-[5.75rem] !px-1 text-center align-bottom">
                <button type="button" class="group mx-auto flex w-full flex-col items-center gap-1 rounded px-1 py-1 transition-colors hover:bg-paper" :class="r.status === 'disabled' ? 'opacity-50' : ''" :title="`${r.name}（${r.roleKey}）`" @click="open(r)">
                  <span class="text-[12px] font-medium leading-tight text-ink group-hover:underline">{{ r.name }}</span>
                  <span class="text-[10.5px] font-normal" :class="r.builtin ? 'text-ink-4' : 'text-signal'">{{ r.status === 'disabled' ? '已停用' : r.builtin ? '内置' : '自定义' }}</span>
                </button>
              </th>
            </tr>
          </thead>
          <tbody v-for="g in permissionGroups" :key="g.title">
            <tr class="group-row"><th :colspan="shown.length + 1" scope="colgroup" class="!py-1.5 text-left text-[12px] font-medium text-ink-3">{{ g.title }}</th></tr>
            <tr v-for="p in g.permissions" :key="p" class="hover:bg-paper-soft">
              <td class="!py-1.5" :title="p"><span class="text-[13px] text-ink-2">{{ permText(p) }}</span></td>
              <td v-for="r in shown" :key="r.roleKey" class="!py-1.5 text-center" :class="r.status === 'disabled' ? 'opacity-40' : ''">
                <span v-if="has(r, p)" class="inline-flex h-5 w-5 items-center justify-center rounded-sm bg-ink text-paper" :aria-label="`${r.name}持有${permText(p)}`"><Check :size="12" :stroke-width="2" /></span>
                <span v-else class="inline-block h-1 w-1 rounded-full bg-ink-hair" aria-hidden="true" />
              </td>
            </tr>
          </tbody>
          <tfoot>
            <tr>
              <td class="text-[12px] text-ink-3">权限数</td>
              <td v-for="r in shown" :key="r.roleKey" class="num text-center text-[12.5px] text-ink">
                {{ r.permissions.length }}<span v-if="conflictOf(r).length" class="ml-1 text-threat" title="包含互斥权限对">!</span>
              </td>
            </tr>
          </tfoot>
        </table>
      </LoadState>
    </Panel>

    <div class="mt-5 grid items-start gap-5 lg:grid-cols-[minmax(0,1fr)_22rem]">
      <Panel title="角色目录" :icon="UserCog" :desc="filtered ? `筛选后 ${shown.length} 个` : `共 ${roles.length} 个`">
        <ul v-if="shown.length" class="-mx-2 grid gap-x-4 gap-y-0.5 md:grid-cols-2">
          <li v-for="r in shown" :key="r.roleKey">
            <button type="button" class="flex w-full items-center justify-between gap-3 rounded px-2 py-2 text-left transition-colors hover:bg-paper-soft" @click="open(r)">
              <span class="min-w-0">
                <span class="block truncate text-[13px]" :class="r.status === 'active' ? 'text-ink' : 'text-ink-3'">{{ r.name }}</span>
                <span class="num block truncate text-[11px] text-ink-4">{{ r.roleKey }}</span>
              </span>
              <span class="flex shrink-0 flex-col items-end gap-0.5">
                <Tag :tone="roleStatusTone[r.status]" :label="roleStatusLabel[r.status] ?? r.status" />
                <span class="text-[11px]" :class="r.builtin ? 'text-ink-4' : 'text-signal'">{{ r.builtin ? '内置' : '自定义' }} · {{ r.permissions.length }} 项</span>
              </span>
            </button>
          </li>
        </ul>
        <p v-else class="text-[12.5px] text-ink-4">没有符合条件的角色。</p>
      </Panel>

      <Panel title="名额与职责分离" :icon="Gauge">
        <div class="grid grid-cols-10 gap-1" role="img" :aria-label="`启用人工角色 ${activeCount} 个，机器模板 2 个，上限 10 个`">
          <span v-for="s in slots" :key="s.key" class="h-5 rounded-sm" :class="slotClass[s.kind]" :title="s.name" />
        </div>
        <p class="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[11.5px] text-ink-3">
          <span class="inline-flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-ink-4" />机器模板</span>
          <span class="inline-flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-ink" />内置</span>
          <span class="inline-flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-signal" />自定义</span>
          <span class="inline-flex items-center gap-1"><span class="h-2 w-2 rounded-sm border border-dashed border-ink-line" />空位</span>
        </p>
        <p v-if="full" class="note note-warn mt-3">启用角色已满，新建或启用前须先停用一个角色。</p>

        <h3 class="section-title mt-5">互斥权限对</h3>
        <ul class="space-y-2 text-[12px] leading-snug">
          <li v-for="[a, b] in conflictPairs" :key="a + b" class="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2">
            <span class="text-ink-2" :title="a">{{ permText(a) }}</span>
            <span class="text-ink-4" aria-label="不能同时持有">⇄</span>
            <span class="text-right text-ink-2" :title="b">{{ permText(b) }}</span>
          </li>
        </ul>
        <p class="mt-3 text-[11.5px] leading-relaxed text-ink-4">一个角色或一个用户全部启用角色的权限合计都不能包含上述任一对；审计员另须保持纯只读。</p>
      </Panel>
    </div>

    <RoleDrawer :role-key="openKey" :roles="roles" @close="openKey = ''" @changed="load" @edit="startEdit" />
    <RoleFormDrawer v-if="manage" :open="form.open" :role="form.role" :roles="roles" :busy="busy" @create="create" @update="update" @close="form = { open: false, role: null }" />
  </div>
</template>

<style scoped>
.matrix :deep(th), .matrix :deep(td) { white-space: nowrap; }
.matrix tfoot td { border-top: 1px solid #E2E0DA; }
</style>
