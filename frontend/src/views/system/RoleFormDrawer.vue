<script setup lang="ts">
/**
 * 自定义角色的新建与编辑（iam.manage，权限设计第 3.4 节）。
 *
 * - 新建：角色键固定以 `custom_` 开头（小写字母、数字、下划线，≤64），名称与说明必填；名额已满时不可提交。
 * - 编辑：名称、说明、权限需 If-Match（父页面提交）；只提交改动过的字段。改权限会撤销成员会话，造成成员冲突时后端 409。
 * - 权限编辑器按第 4 节分组勾选，实时标出第 3.3 节冲突权限对（最终以后端 422 PERMISSION_CONFLICT 为准）。
 */
import { computed, reactive, ref, watch } from 'vue'
import Drawer from '@/components/Drawer.vue'
import { permissionConflicts, permissionGroups, roleLimitReached, type IamRole, type RoleDefinition } from '@/api/v2/roles'
import type { Permission } from '@/router/nav'
import { permText } from './shared'

const props = defineProps<{ open: boolean; role: IamRole | null; roles: readonly IamRole[]; busy?: boolean }>()
const emit = defineEmits<{ create: [body: RoleDefinition]; update: [body: Partial<Omit<RoleDefinition, 'roleKey'>>]; close: [] }>()

const PREFIX = 'custom_'
const editing = computed(() => !!props.role)
const form = reactive({ suffix: '', name: '', description: '', permissions: [] as string[] })
const error = ref('')
watch(() => props.open, (v) => {
  if (!v) return
  error.value = ''
  const r = props.role
  Object.assign(form, { suffix: '', name: r?.name ?? '', description: r?.description ?? '', permissions: [...(r?.permissions ?? [])] })
}, { immediate: true })

const conflicts = computed(() => permissionConflicts(form.permissions))
const conflicted = computed(() => new Set(conflicts.value.flat()))
const full = computed(() => !editing.value && roleLimitReached(props.roles))
const keyValid = computed(() => /^[a-z0-9_]+$/.test(form.suffix) && (PREFIX + form.suffix).length <= 64)
const toggle = (p: Permission) => {
  form.permissions = form.permissions.includes(p) ? form.permissions.filter((x) => x !== p) : [...form.permissions, p]
}
const groupCount = (ps: readonly Permission[]) => ps.filter((p) => form.permissions.includes(p)).length
const sameSet = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every((x) => b.includes(x))

function submit() {
  const name = form.name.trim(), description = form.description.trim()
  if (!editing.value && !keyValid.value) { error.value = '角色键后缀只能包含小写字母、数字与下划线，总长不超过 64。'; return }
  if (!name || name.length > 128) { error.value = '请填写名称（最多 128 个字符）。'; return }
  if (!description || description.length > 500) { error.value = '请填写职责说明（最多 500 个字符）。'; return }
  if (!form.permissions.length) { error.value = '请至少选择一项权限。'; return }
  if (conflicts.value.length) { error.value = '所选权限包含互斥的申请与审批职责，请先取消其中一项。'; return }
  if (full.value) { error.value = '启用角色已达上限，请先停用一个角色。'; return }
  error.value = ''
  if (!editing.value) { emit('create', { roleKey: PREFIX + form.suffix, name, description, permissions: [...form.permissions] }); return }
  const r = props.role!
  const body: Partial<Omit<RoleDefinition, 'roleKey'>> = {}
  if (name !== r.name) body.name = name
  if (description !== r.description) body.description = description
  if (!sameSet(form.permissions, r.permissions)) body.permissions = [...form.permissions]
  if (!Object.keys(body).length) { error.value = '没有需要保存的修改。'; return }
  emit('update', body)
}
</script>

<template>
  <Drawer :open="open" :title="editing ? `编辑角色 · ${role?.name}` : '新建自定义角色'" kicker="角色管理" @close="emit('close')">
    <form class="form" @submit.prevent="submit">
      <p v-if="full" class="note note-warn">启用角色已达上限（6 个内置、最多 2 个自定义与 2 个机器模板）。请先停用一个角色再新建。</p>
      <label v-if="!editing" class="form-field"><span class="label">角色键</span>
        <span class="flex items-stretch">
          <span class="num inline-flex items-center rounded-l-[6px] border border-r-0 border-ink-line bg-paper-soft px-2.5 text-[12.5px] text-ink-3">{{ PREFIX }}</span>
          <input v-model.trim="form.suffix" class="field num !rounded-l-none" maxlength="57" placeholder="如 shift_lead" autocomplete="off" />
        </span>
        <span class="form-hint" :class="form.suffix && !keyValid ? 'text-threat' : ''">小写字母、数字与下划线；创建后不可修改。</span>
      </label>
      <label class="form-field"><span class="label">名称</span><input v-model="form.name" class="field" maxlength="128" placeholder="界面显示的角色名" /></label>
      <label class="form-field"><span class="label">职责说明</span>
        <textarea v-model="form.description" rows="2" maxlength="500" class="field resize-none" placeholder="这个角色负责什么、不能做什么" />
      </label>

      <fieldset>
        <legend class="mb-2 flex w-full items-baseline justify-between text-ink-2">权限<span class="text-[12px] text-ink-3">已选 <span class="num text-ink">{{ form.permissions.length }}</span> / 25</span></legend>
        <div class="space-y-4">
          <section v-for="g in permissionGroups" :key="g.title" class="rounded border border-ink-line">
            <p class="flex items-center justify-between border-b border-ink-hair bg-paper-soft px-3 py-1.5 text-[12px] text-ink-3">{{ g.title }}<span class="num">{{ groupCount(g.permissions) }}/{{ g.permissions.length }}</span></p>
            <ul class="grid grid-cols-1 px-3 py-1 sm:grid-cols-2">
              <li v-for="p in g.permissions" :key="p">
                <label class="check w-full" :class="conflicted.has(p) ? '!text-threat' : ''" :title="p">
                  <input type="checkbox" :checked="form.permissions.includes(p)" @change="toggle(p)" />{{ permText(p) }}
                </label>
              </li>
            </ul>
          </section>
        </div>
      </fieldset>

      <div v-if="conflicts.length" class="note note-threat space-y-1" role="alert">
        <p v-for="[a, b] in conflicts" :key="a + b">职责冲突：「{{ permText(a) }}」与「{{ permText(b) }}」不能同时持有。</p>
      </div>
      <p v-if="editing" class="note">修改权限后，已绑定该角色的用户会话会被撤销；若会使某位成员的权限合计出现冲突，后端拒绝保存。</p>
      <p v-else class="note">只能从 25 个人工权限中选择，不含机器权限。新角色创建后即为启用，可在用户管理中绑定。</p>
      <p v-if="error" class="text-[12.5px] text-threat" role="alert">{{ error }}</p>
    </form>
    <template #foot>
      <button type="button" class="act-ghost" @click="emit('close')">取消</button>
      <button type="button" class="act" :disabled="busy || full || conflicts.length > 0" @click="submit">{{ editing ? '保存角色' : '新建角色' }}</button>
    </template>
  </Drawer>
</template>
