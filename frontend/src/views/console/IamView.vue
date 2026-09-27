<script setup lang="ts">
/** 身份与角色：用户列表与内置角色（只读模板）。角色权限不可在线改写。 */
import { ref } from 'vue'
import PageHead from '@/components/PageHead.vue'
import Segmented from '@/components/Segmented.vue'
import Tag from '@/components/Tag.vue'
import { roles, users } from '@/data/demo'

const tab = ref<'users' | 'roles'>('users')
const roleName = (k: string) => roles.find((r) => r.key === k)?.name ?? k
</script>

<template>
  <div>
    <PageHead no="08" title="身份与角色" desc="角色只授予功能权限，资源范围另行限定到明确的资产、数据源或模型注册范围。高影响操作的申请人与审批人必须不同。">
      <template #kicker>Identity</template>
    </PageHead>

    <Segmented v-model="tab" :options="[{ value: 'users', label: '用户', count: users.length }, { value: 'roles', label: '内置角色', count: roles.length }]" />

    <Transition name="fade" mode="out-in">
      <table v-if="tab === 'users'" key="u" class="table mt-10">
        <thead><tr><th>用户</th><th>角色</th><th>状态</th><th class="text-right">最近登录</th></tr></thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td><span class="block">{{ u.name }}</span><span class="num text-[12px] text-ink-3">{{ u.username }} · {{ u.id }}</span></td>
            <td class="text-ink-2">{{ u.roles.map(roleName).join('、') }}</td>
            <td><Tag :tone="u.status === 'active' ? 'ok' : 'mute'" :label="u.status === 'active' ? '启用' : '冻结'" /></td>
            <td class="num text-right text-ink-3">{{ u.lastLogin }}</td>
          </tr>
        </tbody>
      </table>

      <div v-else key="r" class="mt-10">
        <ul class="border-t border-ink">
          <li v-for="r in roles" :key="r.key" class="grid gap-3 border-b border-ink-hair py-6 md:grid-cols-[16rem_1fr_1fr] md:gap-10">
            <div><p class="text-[14px]">{{ r.name }}</p><p class="num mt-1 text-[12px] text-ink-3">{{ r.key }}</p></div>
            <div><p class="label mb-1.5">资源范围</p><p class="text-[13px] text-ink-2">{{ r.scope }}</p></div>
            <div><p class="label mb-1.5">禁止</p><p class="text-[13px] text-ink-2">{{ r.deny }}</p></div>
          </li>
        </ul>
        <p class="mt-6 text-[12px] text-ink-3">内置权限模板由版本化迁移维护，平台管理员只能分配、不能改写。管理员身份不能绕过策略执行响应或发布模型。</p>
      </div>
    </Transition>
  </div>
</template>
