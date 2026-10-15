<script setup lang="ts">
/**
 * 身份与角色：用户（/users）、内置角色模板（/roles，只读）与机器客户端台账（/machine-clients）。
 * 用户详情抽屉：修改显示名称、冻结/解冻、管理员重置口令、整体替换角色范围（开发路线 §4.1）。
 * 冻结、重置口令与改角色都会撤销该用户全部会话；不能冻结本人或最后一名有效平台管理员，由后端判定。
 * 机器客户端只列状态与有效期，不返回任何凭据信息；吊销立即生效且不可恢复。按钮可见性只是提示，授权以后端为准。
 * 登记 connector（POST /machine-clients）：按数据源-资产配对签发，资源范围取配对涉及的数据源与资产；
 * 凭据只在响应中出现一次，关闭抽屉即清除。
 */
import { computed, ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import Drawer from '@/components/Drawer.vue'
import LoadState from '@/components/LoadState.vue'
import { api, type Page } from '@/api/client'
import { can, session } from '@/api/session'
import { fmtTime, lifecycleStatusLabel, userStatusLabel, type AssetView, type DataSourceView, type IssuedMachineClient, type MachineClientView, type RoleBindingView, type RoleSummary, type UserDetail, type UserSummary } from '@/api/types'
import { statusTone } from '@/data/tones'
import { toast } from '@/composables/toast'
import { errText, useLoad } from '@/composables/load'

/** 口令类请求体字段名集中定义；口令只放在请求体里，不写入本地状态之外的任何位置。 */
const SECRET_FIELD = { created: 'password', reset: 'newPassword' } as const

const { data, loading, error, reload } = useLoad(async () => {
  if (!can('iam.user.read')) throw new Error('当前身份没有身份管理查看权限。')
  const [users, roles, clients] = await Promise.all([
    api.get<Page<UserSummary>>('/api/v1/users?size=100').then((p) => p.items),
    can('iam.role.read') ? api.get<RoleSummary[]>('/api/v1/roles') : [],
    can('system.config.read') ? api.get<Page<MachineClientView>>('/api/v1/machine-clients?size=100').then((p) => p.items) : [],
  ])
  return { users, roles, clients }
}, { users: [] as UserSummary[], roles: [] as RoleSummary[], clients: [] as MachineClientView[] })

const tab = ref<'users' | 'roles' | 'clients'>('users')
const tabs = computed(() => [
  { value: 'users' as const, label: '用户', count: data.value.users.length },
  { value: 'roles' as const, label: '内置角色', count: data.value.roles.length },
  ...(can('system.config.read') ? [{ value: 'clients' as const, label: '机器客户端', count: data.value.clients.length }] : []),
])
const busy = ref(false)

// ---- 用户详情 ----
const pickedId = ref<number | null>(null)
const user = ref<UserDetail | null>(null)
const bindings = ref<RoleBindingView[]>([])
const detailError = ref('')
const displayName = ref('')
const reason = ref('')
const resetValue = ref('')
const editingRoles = ref(false)
const roleRows = ref<{ roleKey: string; scopeType: string; scopeId: string }[]>([])
const isSelf = computed(() => user.value?.id === session.user?.id)

let userRequest = 0
async function openUser(id: number) {
  const request = ++userRequest
  pickedId.value = id
  user.value = null
  bindings.value = []
  detailError.value = ''
  reason.value = ''
  resetValue.value = ''
  editingRoles.value = false
  try {
    const [detail, roles] = await Promise.all([api.get<UserDetail>(`/api/v1/users/${id}`), api.get<RoleBindingView[]>(`/api/v1/users/${id}/roles`)])
    if (request !== userRequest || pickedId.value !== id) return
    user.value = detail
    bindings.value = roles
    displayName.value = detail.displayName
  } catch (e) { if (request === userRequest && pickedId.value === id) detailError.value = errText(e) }
}
watch(pickedId, (id) => {
  if (id == null) { userRequest++; user.value = null; resetValue.value = ''; roleRows.value = [] }
}, { flush: 'sync' })

async function run(action: () => Promise<unknown>, done: string, needReason = false) {
  if (needReason && !reason.value.trim()) return toast('请填写理由。', 'warn')
  busy.value = true
  try {
    await action()
    toast(done)
    await reload()
    if (pickedId.value != null) await openUser(pickedId.value)
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
const saveProfile = () => run(() => api.put(`/api/v1/users/${user.value!.id}`, { displayName: displayName.value.trim() }), '显示名称已更新。')
const setStatus = (status: 'active' | 'disabled') => run(() => api.post(`/api/v1/users/${user.value!.id}/status`, { status, reason: reason.value.trim() }),
  status === 'disabled' ? '已冻结，该用户的全部会话已撤销。' : '已解冻。', true)
function resetSecret() {
  if (resetValue.value.length < 12) return toast('新口令至少 12 个字符。', 'warn')
  return run(() => api.post(`/api/v1/users/${user.value!.id}/password-reset`, { [SECRET_FIELD.reset]: resetValue.value, reason: reason.value.trim() }),
    '口令已重置，该用户须用新口令重新登录。', true).then(() => { resetValue.value = '' })
}

function editRoles() {
  roleRows.value = bindings.value.map((b) => ({ roleKey: b.roleKey, scopeType: b.scopeType, scopeId: b.scopeId }))
  if (!roleRows.value.length) roleRows.value.push({ roleKey: data.value.roles[0]?.roleKey ?? '', scopeType: 'asset', scopeId: '' })
  editingRoles.value = true
}
const saveRoles = () => run(() => api.put(`/api/v1/users/${user.value!.id}/roles`, { assignments: roleRows.value.map((r) => ({ ...r, scopeId: r.scopeId.trim() })) }),
  '角色范围已整体替换，该用户的会话已撤销。')

// ---- 新建用户 ----
const creating = ref(false)
const createForm = ref({ username: '', displayName: '', initial: '' })
watch(creating, (open) => { if (!open) createForm.value.initial = '' }, { flush: 'sync' })
async function createUser() {
  const f = createForm.value
  if (f.initial.length < 12) return toast('初始口令至少 12 个字符。', 'warn')
  busy.value = true
  try {
    await api.post('/api/v1/users', { username: f.username.trim(), displayName: f.displayName.trim(), [SECRET_FIELD.created]: f.initial })
    toast('用户已创建，未授予任何角色。')
    creating.value = false
    createForm.value = { username: '', displayName: '', initial: '' }
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

// ---- 机器客户端 ----
const client = ref<MachineClientView | null>(null)
const clientReason = ref('')
async function revokeClient() {
  if (!client.value || !clientReason.value.trim()) return toast('请填写吊销理由。', 'warn')
  busy.value = true
  try {
    await api.post(`/api/v1/machine-clients/${client.value.id}/revoke`, { reason: clientReason.value.trim() })
    toast('凭据已吊销，立即失效。')
    client.value = null
    clientReason.value = ''
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}

const issuing = ref(false)
const issueForm = ref({ clientKey: '', pairs: [{ dataSourceId: 0, assetId: 0 }] })
const issueOptions = ref<{ sources: DataSourceView[]; assets: AssetView[] }>({ sources: [], assets: [] })
const issueError = ref('')
/** 只显示一次的新凭据；关闭抽屉即清除。 */
const issuedClient = ref<IssuedMachineClient | null>(null)
watch(issuing, (open) => { if (!open) issuedClient.value = null }, { flush: 'sync' })
async function openIssue() {
  issueForm.value = { clientKey: '', pairs: [{ dataSourceId: 0, assetId: 0 }] }
  issueError.value = ''
  issuing.value = true
  try {
    const [sources, assets] = await Promise.all([
      api.get<Page<DataSourceView>>('/api/v1/data-sources?size=100'), api.get<Page<AssetView>>('/api/v1/assets?size=100')])
    issueOptions.value = { sources: sources.items.filter((x) => x.status === 'active'), assets: assets.items.filter((x) => x.status === 'active') }
  } catch (e) { issueError.value = errText(e) }
}
async function issueClient() {
  const pairs = issueForm.value.pairs
  if (pairs.some((p) => !p.dataSourceId || !p.assetId)) return toast('每一行都须选择数据源与资产。', 'warn')
  const scopes = [...new Set(pairs.map((p) => `data_source:${p.dataSourceId}`)), ...new Set(pairs.map((p) => `asset:${p.assetId}`))]
    .map((k) => ({ scopeType: k.split(':')[0], scopeId: k.split(':')[1] }))
  busy.value = true
  try {
    issuedClient.value = await api.post<IssuedMachineClient>('/api/v1/machine-clients', {
      clientKey: issueForm.value.clientKey.trim(), clientType: 'connector', scopes, sourceAssetBindings: pairs,
    })
    toast('连接器已登记，凭据只显示这一次。')
    await reload()
  } catch (e) { toast(errText(e), 'threat') } finally { busy.value = false }
}
</script>

<template>
  <div>
    <PageHead no="08" title="身份与角色" desc="角色只授予功能权限，资源范围另行限定到明确的资产、数据源或模型注册范围。高影响操作的申请人与审批人必须不同。">
      <template #kicker>Identity</template>
    </PageHead>

    <Segmented v-model="tab" :options="tabs" />

    <LoadState :loading="loading" :error="error">
    <Transition name="fade" mode="out-in">
      <section v-if="tab === 'users'" key="u" class="mt-10">
        <div v-if="can('iam.user.manage')" class="mb-6 flex justify-end"><button class="act-ghost" @click="creating = true">新建用户</button></div>
        <table class="table">
          <thead><tr><th>用户</th><th>用户标识</th><th class="text-right">状态</th></tr></thead>
          <tbody>
            <tr v-for="u in data.users" :key="u.id" class="row-link" tabindex="0" @click="openUser(u.id)" @keydown.enter="openUser(u.id)">
              <td><span class="block">{{ u.displayName }}</span><span class="num text-[12px] text-ink-3">{{ u.username }} · #{{ u.id }}</span></td>
              <td class="num text-ink-2">{{ u.userKey }}</td>
              <td class="text-right"><Tag :tone="statusTone[u.status]" :label="userStatusLabel[u.status] ?? u.status" /></td>
            </tr>
          </tbody>
        </table>
      </section>

      <div v-else-if="tab === 'roles'" key="r" class="mt-10">
        <ul class="border-t border-ink">
          <li v-for="r in data.roles" :key="r.roleKey" class="grid gap-3 border-b border-ink-hair py-6 md:grid-cols-[16rem_1fr] md:gap-10">
            <div><p class="text-[14px]">{{ r.name }}</p><p class="num mt-1 text-[12px] text-ink-3">{{ r.roleKey }}</p><p class="mt-2 text-[12.5px] text-ink-2">{{ r.description }}</p></div>
            <div><p class="label mb-1.5">功能权限</p><p class="num text-[12.5px] leading-relaxed text-ink-2">{{ r.permissions.join('  ·  ') || '—' }}</p></div>
          </li>
        </ul>
        <p class="mt-6 text-[12px] text-ink-3">内置权限模板由版本化迁移维护，平台管理员只能分配、不能改写。管理员身份不能绕过策略执行响应或发布模型。</p>
      </div>

      <section v-else key="c" class="mt-10">
        <div v-if="can('system.config.update')" class="mb-6 flex justify-end"><button class="act-ghost" @click="openIssue">登记连接器</button></div>
        <table class="table">
          <thead><tr><th>客户端</th><th>类型</th><th>有效期至</th><th>最近轮换</th><th>状态</th><th></th></tr></thead>
          <tbody>
            <tr v-for="c in data.clients" :key="c.id">
              <td><span class="num block">{{ c.clientKey }}</span><span class="num text-[12px] text-ink-3">#{{ c.id }}{{ c.sensorId ? ` · 传感器 #${c.sensorId}` : '' }} · 签发 {{ fmtTime(c.createdAt) }}</span></td>
              <td class="text-ink-2">{{ c.clientType }}</td>
              <td class="num text-ink-2">{{ fmtTime(c.expiresAt) }}</td>
              <td class="num text-ink-2">{{ fmtTime(c.rotatedAt) }}</td>
              <td><Tag :tone="statusTone[c.status]" :label="lifecycleStatusLabel[c.status] ?? c.status" /></td>
              <td class="text-right">
                <button v-if="c.clientType === 'connector' && c.status !== 'revoked' && can('system.config.update')" class="link text-[12.5px]" @click="client = c; clientReason = ''">吊销</button>
              </td>
            </tr>
            <tr v-if="!data.clients.length"><td colspan="6" class="py-16 text-center text-ink-3">数据库中暂无机器客户端。</td></tr>
          </tbody>
        </table>
        <p class="mt-6 text-[12.5px] leading-relaxed text-ink-3">凭据只在签发或轮换时返回一次，数据库只保存 SHA-256 验证值。传感器凭据在「资产与传感器」中轮换或吊销。</p>
      </section>
    </Transition>
    </LoadState>

    <Drawer :open="pickedId != null" :title="user?.displayName ?? '用户'" :kicker="user ? `USER #${user.id} · ${user.username}` : ''" @close="pickedId = null">
      <p v-if="detailError" class="text-[13px] text-threat">{{ detailError }}</p>
      <template v-else-if="user">
        <dl class="border-t border-ink">
          <div v-for="[k, v] in [['状态', userStatusLabel[user.status] ?? user.status], ['最近登录', fmtTime(user.lastLoginAt)], ['最近改密', fmtTime(user.passwordChangedAt)], ['创建', fmtTime(user.createdAt)]]" :key="k" class="grid grid-cols-[6rem_1fr] border-b border-ink-hair py-3 text-[13px]">
            <dt class="text-ink-3">{{ k }}</dt><dd class="num">{{ v }}</dd>
          </div>
        </dl>

        <h3 class="label mb-3 mt-10">角色范围</h3>
        <template v-if="!editingRoles">
          <p v-for="b in bindings" :key="b.roleKey + b.scopeType + b.scopeId" class="num text-[12.5px] text-ink-2">{{ b.roleName }} · {{ b.scopeType }}:{{ b.scopeId }}</p>
          <p v-if="!bindings.length" class="text-[12.5px] text-ink-3">无角色绑定</p>
          <button v-if="can('iam.role.assign') && !isSelf" class="link mt-3 text-[12.5px]" @click="editRoles">整体替换角色范围</button>
        </template>
        <div v-else class="space-y-3">
          <div v-for="(r, i) in roleRows" :key="i" class="grid grid-cols-[1fr_7rem_6rem_auto] items-end gap-3">
            <select v-model="r.roleKey" class="field" aria-label="角色"><option v-for="role in data.roles" :key="role.roleKey" :value="role.roleKey">{{ role.name }}</option></select>
            <select v-model="r.scopeType" class="field" aria-label="范围类型"><option value="asset">asset</option><option value="data_source">data_source</option><option value="model_registry">model_registry</option><option value="global">global</option></select>
            <input v-model="r.scopeId" class="field num" aria-label="范围标识" :placeholder="r.scopeType === 'global' ? '*' : 'ID'" />
            <button class="link text-[12.5px]" @click="roleRows.splice(i, 1)">移除</button>
          </div>
          <div class="flex gap-6 pt-2">
            <button class="link text-[12.5px]" @click="roleRows.push({ roleKey: data.roles[0]?.roleKey ?? '', scopeType: 'asset', scopeId: '' })">添加一行</button>
            <button class="link text-[12.5px]" @click="editingRoles = false">取消</button>
            <button class="link text-[12.5px]" :disabled="busy || !roleRows.length" @click="saveRoles">保存</button>
          </div>
          <p class="text-[12px] text-ink-3">全局范围只允许平台管理员角色，范围标识为 *。</p>
        </div>

        <template v-if="can('iam.user.manage')">
          <h3 class="label mb-3 mt-10">资料</h3>
          <label class="block"><span class="label">显示名称</span><input v-model="displayName" class="field mt-2" maxlength="128" /></label>
          <button class="link mt-3 text-[12.5px]" :disabled="busy || !displayName.trim() || displayName.trim() === user.displayName" @click="saveProfile">保存显示名称</button>

          <template v-if="!isSelf">
            <h3 class="label mb-3 mt-10">账号操作</h3>
            <label class="block"><span class="label">理由（冻结、解冻、重置口令必填）</span><textarea v-model="reason" rows="2" maxlength="1000" class="field mt-2 h-auto resize-none py-2" placeholder="记录到审计" /></label>
            <label class="mt-5 block"><span class="label">重置为新口令（≥ 12 个字符）</span><input v-model="resetValue" type="password" autocomplete="new-password" class="field mt-2" maxlength="128" /></label>
            <p class="mt-4 text-[12px] leading-relaxed text-ink-3">冻结与重置口令会立即撤销该用户的全部会话。不能冻结最后一名有效平台管理员。</p>
          </template>
          <p v-else class="mt-8 text-[12.5px] text-ink-3">本人账号不能在此冻结或重置口令；请使用左下角的「修改口令」。</p>
        </template>
      </template>
      <template v-if="user && can('iam.user.manage') && !isSelf" #foot>
        <button class="link text-[13px]" :disabled="busy || !resetValue" @click="resetSecret">重置口令</button>
        <button v-if="user.status === 'active'" class="act-ghost" :disabled="busy" @click="setStatus('disabled')">冻结</button>
        <button v-else class="act" :disabled="busy" @click="setStatus('active')">解冻</button>
      </template>
    </Drawer>

    <Drawer :open="creating" title="新建用户" kicker="IAM" @close="creating = false">
      <div class="space-y-6">
        <label class="block"><span class="label">用户名</span><input v-model="createForm.username" class="field mt-2 num" maxlength="64" placeholder="3-64 位字母、数字、. _ -" /></label>
        <label class="block"><span class="label">显示名称</span><input v-model="createForm.displayName" class="field mt-2" maxlength="128" /></label>
        <label class="block"><span class="label">初始口令（≥ 12 个字符）</span><input v-model="createForm.initial" type="password" autocomplete="new-password" class="field mt-2" maxlength="128" /></label>
        <p class="text-[12.5px] leading-relaxed text-ink-3">新用户不带任何角色；创建后在用户详情中分配角色与资源范围。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="creating = false">取消</button>
        <button class="act" :disabled="busy || !createForm.username || !createForm.displayName" @click="createUser">创建</button>
      </template>
    </Drawer>

    <Drawer :open="!!client" :title="client?.clientKey ?? ''" :kicker="client ? `CLIENT #${client.id}` : ''" @close="client = null">
      <template v-if="client">
        <p class="text-[13px] leading-relaxed text-ink-2">吊销后该连接器凭据立即失效且不可恢复；如需继续接入，须重新签发新的客户端。</p>
        <label class="mt-8 block"><span class="label">吊销理由</span><textarea v-model="clientReason" rows="3" maxlength="1000" class="field mt-2 h-auto resize-none py-2" /></label>
      </template>
      <template #foot>
        <button class="link text-[13px]" @click="client = null">取消</button>
        <button class="act" :disabled="busy" @click="revokeClient">吊销</button>
      </template>
    </Drawer>

    <Drawer :open="issuing" :title="issuedClient?.clientKey ?? '登记连接器'" :kicker="issuedClient ? `CLIENT #${issuedClient.id}` : 'CONNECTOR'" @close="issuing = false">
      <div v-if="issuedClient">
        <div class="border-l-2 border-warn pl-4">
          <p class="label">新凭据（只显示这一次）</p>
          <p class="num mt-2 select-all break-all text-[12.5px]">{{ issuedClient.credential }}</p>
          <p class="mt-2 text-[12px] text-ink-3">签发于 {{ fmtTime(issuedClient.issuedAt) }}；关闭后无法再次查看，请立即写入连接器主机的密钥存储。</p>
        </div>
        <h3 class="label mb-3 mt-10">数据源-资产配对</h3>
        <p v-for="b in issuedClient.sourceAssetBindings" :key="`${b.dataSourceId}-${b.assetId}`" class="num text-[12.5px] text-ink-2">数据源 #{{ b.dataSourceId }} → 资产 #{{ b.assetId }}</p>
      </div>
      <p v-else-if="issueError" class="text-[13px] text-threat">{{ issueError }}</p>
      <div v-else class="space-y-6">
        <label class="block"><span class="label">客户端标识</span><input v-model="issueForm.clientKey" class="field num mt-2" maxlength="96" placeholder="3-96 位字母、数字、. _ -" /></label>
        <div>
          <p class="label mb-2">数据源-资产配对（1～32 行）</p>
          <div v-for="(pair, i) in issueForm.pairs" :key="i" class="mb-3 grid grid-cols-[1fr_1fr_auto] items-end gap-3">
            <select v-model.number="pair.dataSourceId" class="field" aria-label="数据源"><option :value="0" disabled>数据源</option><option v-for="s in issueOptions.sources" :key="s.id" :value="s.id">{{ s.sourceKey }} · #{{ s.id }}</option></select>
            <select v-model.number="pair.assetId" class="field" aria-label="资产"><option :value="0" disabled>资产</option><option v-for="a in issueOptions.assets" :key="a.id" :value="a.id">{{ a.assetKey }} · #{{ a.id }}</option></select>
            <button class="link text-[12.5px]" :disabled="issueForm.pairs.length === 1" @click="issueForm.pairs.splice(i, 1)">移除</button>
          </div>
          <button class="link text-[12.5px]" :disabled="issueForm.pairs.length >= 32" @click="issueForm.pairs.push({ dataSourceId: 0, assetId: 0 })">添加一行</button>
        </div>
        <p class="text-[12.5px] leading-relaxed text-ink-3">资源范围自动取配对涉及的数据源与资产，连接器只能为这些配对写入批次。配对即在此建立，数据源与资产都须处于生效状态，由后端校验。当前只签发 connector；传感器凭据在「资产与传感器」中登记。</p>
      </div>
      <template #foot>
        <button class="link text-[13px]" @click="issuing = false">{{ issuedClient ? '关闭' : '取消' }}</button>
        <button v-if="!issuedClient && !issueError" class="act" :disabled="busy || !issueForm.clientKey.trim()" @click="issueClient">登记并签发</button>
      </template>
    </Drawer>
  </div>
</template>
