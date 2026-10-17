<script setup lang="ts">
import { useActionError } from '@/composables/actionError'
/**
 * 角色详情抽屉（角色管理 `?role=`）：职责、按组的中文权限说明与成员；抽屉内切换停用 / 启用 / 删除模式。
 *
 * - 内置角色只读，显示「内置」标记与不可编辑说明；自定义角色的编辑交给父页面的表单抽屉。
 * - 成员（GET roles/{key}/members，游标）与全部写入需 iam.manage；只有 audit.read 时只读显示职责与权限。
 * - 删除只对没有绑定的自定义角色可用；已读到成员时事先禁用，后端仍以 409 ROLE_IN_USE 为准。
 */
import { computed, ref, watch } from 'vue'
import { PauseCircle, Pencil, Power, Trash2 } from 'lucide-vue-next'
import Drawer from '@/components/Drawer.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import CursorPager from '@/components/CursorPager.vue'
import { useCursor } from '@/composables/cursor'
import { errText } from '@/composables/load'
import { toast } from '@/composables/toast'
import { can } from '@/api/session'
import { permissionGroups, permissionConflicts, roleLimitReached, rolesApi, type IamRole, type RoleMember } from '@/api/v2/roles'
import { iamUserTone, roleStatusTone } from '@/data/tones'
import { permText, roleStatusLabel, scopeText, userStatusLabel } from './shared'

const props = defineProps<{ roleKey: string; roles: readonly IamRole[] }>()
const emit = defineEmits<{ close: []; changed: []; edit: [role: IamRole] }>()

const manage = can('iam.manage')
const role = computed(() => props.roles.find((r) => r.roleKey === props.roleKey) ?? null)
type Mode = 'view' | 'disable' | 'enable' | 'delete'
const mode = ref<Mode>('view')

const members = useCursor<RoleMember>((cursor) => rolesApi.listMembers(props.roleKey, { cursor }), false)

const groups = computed(() => permissionGroups
  .map((g) => ({ title: g.title, items: g.permissions.filter((p) => role.value?.permissions.includes(p)) }))
  .filter((g) => g.items.length))
/** 后端返回但不在 25 个人工权限内的键（理论上不应出现）原样列出，不静默丢弃。 */
const extra = computed(() => (role.value?.permissions ?? []).filter((p) => !permissionGroups.some((g) => (g.permissions as readonly string[]).includes(p))))
const conflicts = computed(() => permissionConflicts(role.value?.permissions ?? []))
const hasMembers = computed(() => members.items.value.length > 0)
const editable = computed(() => manage && !!role.value && !role.value.builtin)
const full = computed(() => roleLimitReached(props.roles))

const busy = ref(false)
const formError = useActionError()
const reason = ref('')
watch(() => props.roleKey, (key) => { mode.value = 'view'; formError.value = ''; if (key && manage) members.reset() }, { immediate: true })
function enter(m: Mode) { reason.value = ''; formError.value = ''; mode.value = m }
async function run(fn: () => Promise<unknown>, done: string, close = false) {
  busy.value = true
  try {
    await fn()
    toast(done)
    emit('changed')
    if (close) emit('close')
    else { mode.value = 'view'; members.reset() }
  } catch (e) { formError.value = errText(e) } finally { busy.value = false }
}
function changeStatus(to: 'active' | 'disabled') {
  const r = role.value
  if (!r) return
  if (!reason.value.trim()) { formError.value = '请填写理由，理由会写入审计。'; return }
  void run(() => rolesApi.setRoleStatus(r.roleKey, r.revision, to, reason.value.trim()), to === 'disabled' ? '已停用角色，成员会话已撤销。' : '已启用角色。')
}
function remove() {
  const r = role.value
  if (r) void run(() => rolesApi.deleteRole(r.roleKey, r.revision), `已删除角色「${r.name}」。`, true)
}
const modeTitle: Record<Mode, string> = { view: '', disable: '停用角色', enable: '启用角色', delete: '删除角色' }
</script>

<template>
  <Drawer :open="!!roleKey" :title="role ? (mode === 'view' ? role.name : `${modeTitle[mode]} · ${role.name}`) : '角色详情'" kicker="角色" @close="emit('close')">
    <p v-if="!role" class="note note-warn">角色目录中没有「{{ roleKey }}」，可能已被删除，请刷新页面。</p>
    <template v-else>
      <template v-if="mode === 'view'">
        <div class="mb-5 flex flex-wrap items-center gap-2">
          <Tag pill :tone="roleStatusTone[role.status]" :label="roleStatusLabel[role.status] ?? role.status" />
          <span class="rounded-sm border px-1.5 py-px text-[11.5px]" :class="role.builtin ? 'border-ink-line text-ink-3' : 'border-signal/40 text-signal'">{{ role.builtin ? '内置' : '自定义' }}</span>
          <span class="text-[12px] text-ink-3"><span class="num text-ink">{{ role.permissions.length }}</span> 项权限</span>
        </div>
        <p v-if="role.builtin" class="note mb-5">内置角色只读：不能改名、改权限、停用或删除。需要不同的权限组合时请新建自定义角色。</p>
        <p v-else-if="role.status === 'disabled'" class="note note-warn mb-5">已停用：该角色不再产生权限，绑定保留；重新启用后恢复。</p>
        <p v-if="conflicts.length" class="note note-threat mb-5" role="alert">该角色包含互斥权限对，后端会拒绝其绑定：{{ conflicts.map(([a, b]) => `${permText(a)} 与 ${permText(b)}`).join('；') }}。</p>

        <h3 class="section-title">职责</h3>
        <p class="text-[13px] leading-relaxed text-ink-2">{{ role.description || '—' }}</p>

        <h3 class="section-title mt-7">权限</h3>
        <p v-if="!groups.length && !extra.length" class="text-[12.5px] text-ink-3">该角色不含任何权限。</p>
        <div v-else class="space-y-4">
          <section v-for="g in groups" :key="g.title">
            <p class="mb-1.5 text-[12px] text-ink-3">{{ g.title }}</p>
            <ul class="flex flex-wrap gap-1.5">
              <li v-for="p in g.items" :key="p" class="rounded-sm border border-ink-line px-2 py-0.5 text-[12.5px] text-ink-2" :title="p">{{ permText(p) }}</li>
            </ul>
          </section>
          <section v-if="extra.length">
            <p class="mb-1.5 text-[12px] text-ink-3">未登记的权限</p>
            <ul class="flex flex-wrap gap-1.5"><li v-for="p in extra" :key="p" class="num rounded-sm border border-warn/40 px-2 py-0.5 text-[12px] text-warn">{{ p }}</li></ul>
          </section>
        </div>

        <h3 class="section-title mt-7">成员</h3>
        <p v-if="!manage" class="text-[12.5px] text-ink-3">查看成员需要身份与访问管理权限。</p>
        <template v-else>
          <LoadState :loading="members.loading.value" :error="members.error.value" :empty="!members.items.value.length" empty-text="该角色当前没有绑定的用户。">
            <ul class="divide-y divide-ink-hair rounded border border-ink-line">
              <li v-for="m in members.items.value" :key="m.bindingId">
                <RouterLink :to="{ path: '/console/system/users', query: { id: String(m.id) } }" class="flex items-center justify-between gap-3 px-3.5 py-2.5 hover:bg-paper-soft">
                  <span class="min-w-0">
                    <span class="block truncate text-[13px] text-ink">{{ m.displayName || m.username }}</span>
                    <span class="num block truncate text-[11.5px] text-ink-4">{{ m.username }}</span>
                  </span>
                  <span class="flex shrink-0 flex-col items-end gap-0.5">
                    <span class="text-[12px] text-ink-2" :class="m.scopeType === 'global' ? '' : 'num'">{{ scopeText(m) }}</span>
                    <Tag :tone="iamUserTone[m.status]" :label="userStatusLabel[m.status] ?? m.status" />
                  </span>
                </RouterLink>
              </li>
            </ul>
          </LoadState>
          <div v-if="members.next.value || members.stack.value.length" class="mt-3">
            <CursorPager :count="members.items.value.length" :has-next="!!members.next.value" :has-prev="!!members.stack.value.length" :busy="members.turning.value" label="成员" @next="members.forward()" @prev="members.back()" />
          </div>
        </template>

        <div v-if="editable" class="mt-7">
          <button type="button" class="act-ghost act-sm" @click="emit('edit', role)"><Pencil :size="13" :stroke-width="1.5" />编辑角色</button>
        </div>

        <details class="mt-7 text-[12.5px]">
          <summary class="cursor-pointer text-ink-3 hover:text-ink">技术细节</summary>
          <dl class="kv mt-2">
            <div><dt>角色键</dt><dd class="num">{{ role.roleKey }}</dd></div>
            <div><dt>修订号</dt><dd class="num">{{ role.revision }}</dd></div>
            <div><dt>权限键</dt><dd class="num text-[12px] leading-relaxed">{{ role.permissions.join(', ') || '—' }}</dd></div>
          </dl>
        </details>
      </template>

      <div v-else-if="mode === 'disable' || mode === 'enable'">
        <p class="note mb-5" :class="mode === 'disable' ? 'note-threat' : full ? 'note-warn' : ''">
          <template v-if="mode === 'disable'">停用后该角色立即不再产生权限，已绑定用户的会话被撤销；绑定保留，重新启用后恢复。</template>
          <template v-else-if="full">启用角色已达上限（6 个内置、最多 2 个自定义与 2 个机器模板），启用会被拒绝，请先停用其他角色。</template>
          <template v-else>启用后已绑定用户重新获得该角色的权限；若会造成成员职责冲突，后端拒绝启用。</template>
        </p>
        <label class="form-field"><span class="label">理由</span><textarea v-model="reason" rows="3" maxlength="1000" class="field resize-none" placeholder="写入审计" /></label>
      </div>

      <div v-else-if="mode === 'delete'">
        <p class="note note-threat">删除移除角色及其权限关联，不能恢复；审计保留角色键与权限快照。只有没有任何绑定的自定义角色可以删除。</p>
        <p v-if="hasMembers" class="mt-4 text-[12.5px] text-threat" role="alert">该角色仍有成员绑定，请先在用户管理中撤销这些绑定，或改为停用。</p>
      </div>

      <p v-if="formError" class="mt-4 text-[12.5px] text-threat" role="alert">{{ formError }}</p>
    </template>

    <template v-if="editable && role" #foot>
      <template v-if="mode === 'view'">
        <button type="button" class="act-danger" @click="enter('delete')"><Trash2 :size="14" :stroke-width="1.5" />删除角色</button>
        <button v-if="role.status === 'disabled'" type="button" class="act-ghost" @click="enter('enable')"><Power :size="14" :stroke-width="1.5" />启用角色</button>
        <button v-else type="button" class="act-danger" @click="enter('disable')"><PauseCircle :size="14" :stroke-width="1.5" />停用角色</button>
      </template>
      <template v-else>
        <button type="button" class="act-ghost" :disabled="busy" @click="mode = 'view'; formError = ''">返回</button>
        <button v-if="mode === 'disable'" type="button" class="act-danger" :disabled="busy" @click="changeStatus('disabled')">确认停用</button>
        <button v-else-if="mode === 'enable'" type="button" class="act" :disabled="busy || full" @click="changeStatus('active')">确认启用</button>
        <button v-else-if="mode === 'delete'" type="button" class="act-danger" :disabled="busy || hasMembers || members.loading.value" @click="remove">确认删除</button>
      </template>
    </template>
  </Drawer>
</template>
