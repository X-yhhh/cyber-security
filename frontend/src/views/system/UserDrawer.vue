<script setup lang="ts">
/**
 * 用户详情抽屉（用户管理 `?id=`）：资料、角色绑定与会话说明；抽屉内切换模式，不叠第二个抽屉。
 *
 * 模式：查看 → 编辑资料 / 重置口令 / 停用 / 启用 / 删除 / 添加绑定 / 撤销绑定。
 * - 写操作带幂等键；资料、停用/启用、删除带 If-Match（修订号），写后重新读取，不做乐观更新。
 * - 添加绑定前用 bindingWarnings 提示职责冲突，最终以后端 409 ROLE_CONFLICT 为准；asset 范围填资产内部编号。
 * - 本人账号：按钮全部禁用并写明原因（后端 403 SELF_ADMINISTRATION_FORBIDDEN）。
 */
import { computed, reactive, ref, watch } from 'vue'
import { KeyRound, Link2, Pencil, Power, PauseCircle, Trash2, X } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { session } from '@/api/session'
import { iamApi, type IamUser, type RoleBinding, type CreateBinding } from '@/api/v2/iam'
import { bindingWarnings, roleName, type IamRole } from '@/api/v2/roles'
import { iamUserTone, roleStatusTone } from '@/data/tones'
import { passwordProblem, permText, scopeText, SELF_REASON, userStatusLabel } from './shared'

const props = defineProps<{ id: string; catalogue: readonly IamRole[] }>()
const emit = defineEmits<{ close: []; changed: [] }>()

type Mode = 'view' | 'edit' | 'password' | 'disable' | 'enable' | 'delete' | 'bind' | 'revoke'
const mode = ref<Mode>('view')
const user = ref<IamUser | null>(null)
const bindings = ref<RoleBinding[]>([])
const loading = ref(false)
const error = ref('')
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = !user.value || String(user.value.id) !== props.id
  error.value = ''
  try {
    const [u, b] = await Promise.all([iamApi.getUser(Number(props.id)), iamApi.listBindings(Number(props.id))])
    if (mine !== seq) return
    user.value = u
    bindings.value = b
  } catch (e) { if (mine === seq) { user.value = null; error.value = errText(e) } } finally { if (mine === seq) loading.value = false }
}

const self = computed(() => !!user.value && user.value.id === session.user?.id)
const title = computed(() => user.value?.displayName || user.value?.username || '用户详情')
const role = (key: string) => props.catalogue.find((r) => r.roleKey === key)
const activeRoles = computed(() => props.catalogue.filter((r) => r.status === 'active'))
const stateNote = computed(() => {
  const s = user.value?.status
  if (self.value) return { text: `这是你本人的账号。${SELF_REASON}`, tone: '' }
  if (s === 'disabled') return { text: '已停用：不能登录，原有会话已撤销；角色绑定保留，启用后恢复。', tone: 'note-warn' }
  if (s === 'locked') return { text: '已锁定：连续登录失败或被后端锁定，当前不能登录。', tone: 'note-threat' }
  return { text: '角色绑定、停用或重置口令生效后，后端立即撤销该用户的全部会话，需要重新登录。', tone: '' }
})

/* ---------------- 模式 ---------------- */
const busy = ref(false)
const formError = ref('')
const reason = ref('')
const edit = reactive({ username: '', displayName: '' })
const secret = reactive({ password: '', confirm: '' })
const bind = reactive({ roleKey: '', scopeType: 'global' as 'global' | 'asset', assetId: '' })
const target = ref<RoleBinding | null>(null)
watch(() => props.id, (id) => { mode.value = 'view'; formError.value = ''; if (id) void load(); else { seq++; user.value = null; bindings.value = [] } }, { immediate: true })

function enter(m: Mode, b?: RoleBinding) {
  if (self.value) return
  reason.value = ''
  formError.value = ''
  Object.assign(secret, { password: '', confirm: '' })
  if (m === 'edit' && user.value) Object.assign(edit, { username: user.value.username, displayName: user.value.displayName })
  if (m === 'bind') Object.assign(bind, { roleKey: '', scopeType: 'global', assetId: '' })
  target.value = b ?? null
  mode.value = m
}
function back() { mode.value = 'view'; formError.value = ''; Object.assign(secret, { password: '', confirm: '' }) }

async function run(fn: () => Promise<unknown>, done: string, close = false) {
  busy.value = true
  try {
    await fn()
    toast(done)
    emit('changed')
    if (close) emit('close')
    else { back(); await load() }
  } catch (e) { formError.value = errText(e) } finally { busy.value = false }
}

function saveEdit() {
  const u = user.value
  if (!u) return
  const username = edit.username.trim(), displayName = edit.displayName.trim()
  if (!username || username.length > 64) { formError.value = '请填写用户名（最多 64 个字符）。'; return }
  if (!displayName || displayName.length > 128) { formError.value = '请填写显示名（最多 128 个字符）。'; return }
  const body: { username?: string; displayName?: string } = {}
  if (username !== u.username) body.username = username
  if (displayName !== u.displayName) body.displayName = displayName
  if (!Object.keys(body).length) { formError.value = '没有需要保存的修改。'; return }
  void run(() => iamApi.updateUser(u.id, u.revision, body), '已保存资料。')
}
function resetPassword() {
  const u = user.value
  if (!u) return
  const pw = passwordProblem(secret.password, secret.confirm)
  if (pw) { formError.value = pw; return }
  if (!reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
  void run(() => iamApi.resetPassword(u.id, secret.password, reason.value.trim()), '已重置口令，该用户的会话已撤销。')
}
function changeStatus(to: 'active' | 'disabled') {
  const u = user.value
  if (!u) return
  if (!reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
  void run(() => iamApi.setUserStatus(u.id, u.revision, to, reason.value.trim()), to === 'disabled' ? '已停用账号，会话已撤销。' : '已启用账号。')
}
function remove() {
  const u = user.value
  if (!u) return
  void run(() => iamApi.deleteUser(u.id, u.revision), '已删除账号。', true)
}

const scopeIdValid = computed(() => /^[1-9]\d{0,18}$/.test(bind.assetId.trim()))
const duplicate = computed(() => bindings.value.some((b) => b.roleKey === bind.roleKey && b.scopeType === bind.scopeType && (b.scopeType === 'global' || b.scopeId === bind.assetId.trim())))
/** 只做事前提示（权限设计第 3.3 节），目录缺失时提示刷新；最终以后端为准。 */
const warnings = computed(() => (bind.roleKey ? bindingWarnings(bindings.value, bind.roleKey, props.catalogue) : [])
  .map((w) => w.replace(/[a-z]+\.[a-z]+/g, (k) => `「${permText(k)}」`)))
function addBinding() {
  const u = user.value
  if (!u) return
  if (!bind.roleKey) { formError.value = '请选择角色。'; return }
  if (bind.scopeType === 'asset' && !scopeIdValid.value) { formError.value = '资产内部编号须为正整数。'; return }
  if (duplicate.value) { formError.value = '该用户已有相同角色与范围的绑定。'; return }
  const body: CreateBinding = bind.scopeType === 'global' ? { roleKey: bind.roleKey, scopeType: 'global', scopeId: '*' } : { roleKey: bind.roleKey, scopeType: 'asset', scopeId: bind.assetId.trim() }
  void run(() => iamApi.addBinding(u.id, body), `已添加绑定：${roleName(bind.roleKey, props.catalogue)}（${scopeText(body)}）。`)
}
function revoke() {
  const b = target.value
  if (!b) return
  if (!reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
  void run(() => iamApi.revokeBinding(b.id, reason.value.trim()), '已撤销绑定，该用户的会话已撤销。')
}

const modeTitle: Record<Mode, string> = { view: '', edit: '编辑资料', password: '重置口令', disable: '停用账号', enable: '启用账号', delete: '删除账号', bind: '添加角色绑定', revoke: '撤销绑定' }
const inactive = computed(() => user.value?.status === 'disabled' || user.value?.status === 'locked')
</script>

<template>
  <Drawer :open="!!id" :title="mode === 'view' ? title : `${modeTitle[mode]} · ${title}`" kicker="用户" @close="emit('close')">
    <LoadState :loading="loading" :error="error">
      <template v-if="user">
        <!-- 查看 -->
        <template v-if="mode === 'view'">
          <p class="note mb-5" :class="stateNote.tone">{{ stateNote.text }}</p>
          <dl class="kv">
            <div><dt>显示名</dt><dd>{{ user.displayName || '—' }}</dd></div>
            <div><dt>用户名</dt><dd class="num">{{ user.username }}</dd></div>
            <div><dt>状态</dt><dd><Tag pill :tone="iamUserTone[user.status]" :label="userStatusLabel[user.status] ?? user.status" /></dd></div>
          </dl>

          <div class="mt-7 flex items-center justify-between gap-3">
            <h3 class="section-title !mb-0">角色绑定<span class="num ml-1.5 text-[12px] font-normal text-ink-4">{{ bindings.length }}</span></h3>
            <button type="button" class="link text-[12.5px]" :disabled="self" :title="self ? SELF_REASON : undefined" :class="self ? 'cursor-not-allowed opacity-40' : ''" @click="enter('bind')"><Link2 :size="13" :stroke-width="1.5" />添加绑定</button>
          </div>
          <p v-if="!bindings.length" class="mt-3 rounded border border-dashed border-ink-line px-4 py-5 text-center text-[12.5px] text-ink-3">没有角色绑定：登录后只能看到待办中心。</p>
          <ul v-else class="mt-3 divide-y divide-ink-hair rounded border border-ink-line">
            <li v-for="b in bindings" :key="b.id" class="flex items-center justify-between gap-3 px-3.5 py-2.5">
              <span class="min-w-0">
                <span class="flex items-center gap-2 text-[13px]">
                  <span class="truncate text-ink">{{ roleName(b.roleKey, catalogue) }}</span>
                  <Tag v-if="role(b.roleKey)?.status === 'disabled'" :tone="roleStatusTone.disabled" label="角色已停用" />
                </span>
                <span class="mt-0.5 block text-[12px] text-ink-3">范围：<span :class="b.scopeType === 'global' ? '' : 'num'">{{ scopeText(b) }}</span></span>
              </span>
              <button type="button" class="act-ghost act-sm shrink-0" :disabled="self" :title="self ? SELF_REASON : '撤销该绑定'" @click="enter('revoke', b)"><X :size="13" :stroke-width="1.5" />撤销</button>
            </li>
          </ul>

          <h3 class="section-title mt-7">会话</h3>
          <p class="text-[12.5px] leading-relaxed text-ink-3">页面不显示在线会话。添加或撤销绑定、停用、重置口令后，后端撤销该用户的全部会话；本人修改口令请走账户菜单。</p>

          <div class="mt-7 flex flex-wrap gap-2.5">
            <button type="button" class="act-ghost act-sm" :disabled="self" :title="self ? SELF_REASON : undefined" @click="enter('edit')"><Pencil :size="13" :stroke-width="1.5" />编辑资料</button>
            <button type="button" class="act-ghost act-sm" :disabled="self" :title="self ? SELF_REASON : undefined" @click="enter('password')"><KeyRound :size="13" :stroke-width="1.5" />重置口令</button>
          </div>

          <details class="mt-7 text-[12.5px]">
            <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
            <dl class="kv mt-2">
              <div><dt>用户编号</dt><dd class="num">{{ user.id }}</dd></div>
              <div><dt>修订号</dt><dd class="num">{{ user.revision }}</dd></div>
              <div v-for="b in bindings" :key="b.id"><dt>绑定 #{{ b.id }}</dt><dd class="num">{{ b.roleKey }} · {{ b.scopeType }}:{{ b.scopeId }}</dd></div>
            </dl>
          </details>
        </template>

        <!-- 编辑资料 -->
        <form v-else-if="mode === 'edit'" class="form" @submit.prevent="saveEdit">
          <label class="form-field"><span class="label">用户名</span><input v-model="edit.username" class="field num" maxlength="64" autocomplete="off" />
            <span class="form-hint">修改后该用户须用新用户名登录。</span>
          </label>
          <label class="form-field"><span class="label">显示名</span><input v-model="edit.displayName" class="field" maxlength="128" /></label>
        </form>

        <!-- 重置口令 -->
        <form v-else-if="mode === 'password'" class="form" autocomplete="off" @submit.prevent="resetPassword">
          <p class="note note-warn">重置后该用户的全部会话立即失效，须用新口令重新登录。请通过线下渠道告知本人。</p>
          <div class="grid grid-cols-2 gap-4">
            <label class="form-field"><span class="label">新口令</span><input v-model="secret.password" type="password" class="field" maxlength="128" autocomplete="new-password" /></label>
            <label class="form-field"><span class="label">再次输入</span><input v-model="secret.confirm" type="password" class="field" maxlength="128" autocomplete="new-password" /></label>
          </div>
          <p class="form-hint">至少 12 位。</p>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </form>

        <!-- 停用 / 启用 -->
        <div v-else-if="mode === 'disable' || mode === 'enable'">
          <p class="note mb-5" :class="mode === 'disable' ? 'note-threat' : ''">
            <template v-if="mode === 'disable'">停用后该用户立即不能登录，全部会话被撤销；角色绑定保留，重新启用后恢复。不能停用最后一位有效的全局平台管理员。</template>
            <template v-else>启用后该用户可以用现有口令登录，并恢复其角色绑定对应的权限。</template>
          </p>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>

        <!-- 删除 -->
        <div v-else-if="mode === 'delete'">
          <p class="note note-threat">删除会移除账号本身，不能恢复。只有从未产生审计引用、且没有角色绑定的账号可以删除；有引用时后端拒绝，请改为停用。</p>
          <p v-if="bindings.length" class="mt-4 text-[12.5px] text-threat" role="alert">该账号仍有 {{ bindings.length }} 个角色绑定，请先撤销绑定或改为停用。</p>
        </div>

        <!-- 添加绑定 -->
        <form v-else-if="mode === 'bind'" class="form" @submit.prevent="addBinding">
          <label class="form-field"><span class="label">角色</span>
            <select v-model="bind.roleKey" class="field">
              <option value="" disabled>选择角色</option>
              <option v-for="r in activeRoles" :key="r.roleKey" :value="r.roleKey">{{ r.name }}{{ r.builtin ? '' : '（自定义）' }}</option>
            </select>
            <span v-if="bind.roleKey && role(bind.roleKey)?.description" class="form-hint">{{ role(bind.roleKey)?.description }}</span>
          </label>
          <fieldset class="form-field">
            <legend class="label mb-1.5 text-ink-2">范围</legend>
            <div class="flex gap-5">
              <label class="check"><input v-model="bind.scopeType" type="radio" value="global" />全局</label>
              <label class="check"><input v-model="bind.scopeType" type="radio" value="asset" />指定资产</label>
            </div>
          </fieldset>
          <label v-if="bind.scopeType === 'asset'" class="form-field"><span class="label">资产内部编号</span>
            <input v-model="bind.assetId" class="field num !w-48" inputmode="numeric" maxlength="19" placeholder="如 12" />
            <span class="form-hint block">绑定范围使用资产的内部十进制编号，不是资产页显示的 UUID；资产选择器待编号映射接口补齐后接入。模型、策略、组合、用户等全局对象的权限在资产范围内不生效。</span>
          </label>
          <div v-if="warnings.length" class="note note-warn space-y-1" role="status">
            <p v-for="w in warnings" :key="w">{{ w }}</p>
            <p class="text-ink-3">以上为事前提示，提交后由后端最终判定。</p>
          </div>
          <p v-else-if="bind.roleKey" class="note">未发现职责冲突。生效后该用户的会话会被撤销，下次登录获得新权限。</p>
        </form>

        <!-- 撤销绑定 -->
        <div v-else-if="mode === 'revoke' && target">
          <p class="note note-threat mb-5">撤销后该用户立即失去「{{ roleName(target.roleKey, catalogue) }}」在{{ scopeText(target) }}范围内的权限，会话被撤销。不能撤销导致没有有效全局平台管理员的绑定。</p>
          <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
        </div>

        <p v-if="formError" class="mt-4 text-[12.5px] text-threat" role="alert">{{ formError }}</p>
      </template>
    </LoadState>

    <template v-if="user" #foot>
      <template v-if="mode === 'view'">
        <button type="button" class="act-danger" :disabled="self" :title="self ? SELF_REASON : undefined" @click="enter('delete')"><Trash2 :size="14" :stroke-width="1.5" />删除账号</button>
        <button v-if="inactive" type="button" class="act-ghost" :disabled="self" :title="self ? SELF_REASON : undefined" @click="enter('enable')"><Power :size="14" :stroke-width="1.5" />启用账号</button>
        <button v-else type="button" class="act-danger" :disabled="self" :title="self ? SELF_REASON : undefined" @click="enter('disable')"><PauseCircle :size="14" :stroke-width="1.5" />停用账号</button>
      </template>
      <template v-else>
        <button type="button" class="act-ghost" :disabled="busy" @click="back">返回</button>
        <button v-if="mode === 'edit'" type="button" class="act" :disabled="busy" @click="saveEdit">保存资料</button>
        <button v-else-if="mode === 'password'" type="button" class="act" :disabled="busy" @click="resetPassword">重置口令</button>
        <button v-else-if="mode === 'disable'" type="button" class="act-danger" :disabled="busy" @click="changeStatus('disabled')">确认停用</button>
        <button v-else-if="mode === 'enable'" type="button" class="act" :disabled="busy" @click="changeStatus('active')">确认启用</button>
        <button v-else-if="mode === 'delete'" type="button" class="act-danger" :disabled="busy || bindings.length > 0" @click="remove">确认删除</button>
        <button v-else-if="mode === 'bind'" type="button" class="act" :disabled="busy || !bind.roleKey" @click="addBinding">添加绑定</button>
        <button v-else-if="mode === 'revoke'" type="button" class="act-danger" :disabled="busy" @click="revoke">确认撤销</button>
      </template>
    </template>
  </Drawer>
</template>
