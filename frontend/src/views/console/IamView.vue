<script setup lang="ts">
/**
 * 身份与角色：用户列表（/users）与内置角色及权限模板（/roles），均只读。
 * 选中用户时读取其角色绑定（/users/{id}/roles）；角色权限不可在线改写。
 */
import { ref, watch } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import LoadState from '@/components/LoadState.vue'
import { api, type Page } from '@/api/client'
import { can } from '@/api/session'
import type { RoleBindingView, RoleSummary, UserSummary } from '@/api/types'
import { statusTone } from '@/data/tones'
import { useLoad } from '@/composables/load'

const { data, loading, error } = useLoad(async () => {
  if (!can('iam.user.read')) throw new Error('当前身份没有身份管理查看权限。')
  const [users, roles] = await Promise.all([
    api.get<Page<UserSummary>>('/users?size=100').then((p) => p.items),
    can('iam.role.read') ? api.get<RoleSummary[]>('/roles') : [],
  ])
  return { users, roles }
}, { users: [] as UserSummary[], roles: [] as RoleSummary[] })

const tab = ref<'users' | 'roles'>('users')
const selected = ref<number | null>(null)
const bindings = ref<RoleBindingView[]>([])
watch(selected, async (id) => {
  bindings.value = []
  if (id != null) bindings.value = await api.get<RoleBindingView[]>(`/users/${id}/roles`).catch(() => [])
})
</script>

<template>
  <div>
    <PageHead no="08" title="身份与角色" desc="角色只授予功能权限，资源范围另行限定到明确的资产、数据源或模型注册范围。高影响操作的申请人与审批人必须不同。">
      <template #kicker>Identity</template>
    </PageHead>

    <Segmented v-model="tab" :options="[{ value: 'users', label: '用户', count: data.users.length }, { value: 'roles', label: '内置角色', count: data.roles.length }]" />

    <LoadState :loading="loading" :error="error">
    <Transition name="fade" mode="out-in">
      <table v-if="tab === 'users'" key="u" class="table mt-10">
        <thead><tr><th>用户</th><th>用户标识</th><th>状态</th><th>角色绑定</th></tr></thead>
        <tbody>
          <tr v-for="u in data.users" :key="u.id" class="row-link" tabindex="0" @click="selected = u.id" @keydown.enter="selected = u.id">
            <td><span class="block">{{ u.displayName }}</span><span class="num text-[12px] text-ink-3">{{ u.username }} · #{{ u.id }}</span></td>
            <td class="num text-ink-2">{{ u.userKey }}</td>
            <td><Tag :tone="statusTone[u.status]" :label="u.status" /></td>
            <td class="num text-[12.5px] text-ink-2">
              <template v-if="selected === u.id">
                <span v-for="b in bindings" :key="b.roleKey + b.scopeType + b.scopeId" class="block">{{ b.roleName }} · {{ b.scopeType }}:{{ b.scopeId }}</span>
                <span v-if="!bindings.length" class="text-ink-3">无角色绑定</span>
              </template>
              <span v-else class="text-ink-4">点击查看</span>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-else key="r" class="mt-10">
        <ul class="border-t border-ink">
          <li v-for="r in data.roles" :key="r.roleKey" class="grid gap-3 border-b border-ink-hair py-6 md:grid-cols-[16rem_1fr] md:gap-10">
            <div><p class="text-[14px]">{{ r.name }}</p><p class="num mt-1 text-[12px] text-ink-3">{{ r.roleKey }}</p><p class="mt-2 text-[12.5px] text-ink-2">{{ r.description }}</p></div>
            <div><p class="label mb-1.5">功能权限</p><p class="num text-[12.5px] leading-relaxed text-ink-2">{{ r.permissions.join('  ·  ') || '—' }}</p></div>
          </li>
        </ul>
        <p class="mt-6 text-[12px] text-ink-3">内置权限模板由版本化迁移维护，平台管理员只能分配、不能改写。管理员身份不能绕过策略执行响应或发布模型。</p>
      </div>
    </Transition>
    </LoadState>
  </div>
</template>
