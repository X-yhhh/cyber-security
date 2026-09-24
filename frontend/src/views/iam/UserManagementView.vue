<template>
  <div class="space-y-6">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
      <div>
        <h1 class="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
          <span>访问控制 (IAM) 与系统运维状态</span>
        </h1>
        <p class="text-xs text-slate-500 mt-1">
          管理用户主体、7 大内置角色权限模板、资源范围过滤与 Connector 机器客户端配对
        </p>
      </div>

      <!-- 系统就绪探针指示 -->
      <div class="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-50 border border-slate-200 text-xs">
        <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
        <span class="text-slate-600 font-medium">系统探针:</span>
        <span class="font-mono text-emerald-600 font-semibold">MySQL 就绪 · API 存活</span>
      </div>
    </div>

    <!-- 7 个内置角色只读权限矩阵速查卡片 -->
    <div class="sec-card p-5 space-y-4">
      <div class="border-b border-slate-100 pb-3 flex items-center justify-between">
        <div>
          <h3 class="text-sm font-bold text-slate-800">7 大专业内置角色权限矩阵 (Built-in Roles)</h3>
          <p class="text-xs text-slate-400">权限模板由数据库与版本化迁移维护，运行时不可在线篡改权限点</p>
        </div>
        <StatusBadge type="neutral" text="只读模板" />
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div
          v-for="role in roles"
          :key="role.roleKey"
          class="p-4 rounded-xl border border-slate-200/80 bg-slate-50/50 space-y-2"
        >
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-slate-900">{{ role.name }}</span>
            <span class="text-[10px] font-mono text-cyber-700 bg-sky-50 px-2 py-0.5 rounded">{{ role.roleKey }}</span>
          </div>
          <p class="text-xs text-slate-500 leading-relaxed min-h-[36px]">{{ role.description }}</p>

          <div class="pt-2 border-t border-slate-200/60 flex flex-wrap gap-1">
            <span
              v-for="p in role.permissions.slice(0, 4)"
              :key="p"
              class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-600"
            >
              {{ p }}
            </span>
            <span v-if="role.permissions.length > 4" class="text-[10px] font-mono text-slate-400 pt-0.5">
              +{{ role.permissions.length - 4 }} 权限点
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- 用户主体列表 -->
    <div class="sec-card p-5 space-y-4">
      <div class="border-b border-slate-100 pb-3">
        <h3 class="text-sm font-bold text-slate-800">系统用户列表 (Users)</h3>
        <p class="text-xs text-slate-400">已配置 BCrypt 密码散列保护，角色变动自动撤销旧会话</p>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead class="bg-slate-50/70 border-b border-slate-100 text-slate-500 font-medium">
            <tr>
              <th class="py-2.5 px-3">用户标识</th>
              <th class="py-2.5 px-3">用户名 / 姓名</th>
              <th class="py-2.5 px-3">分配角色</th>
              <th class="py-2.5 px-3">资源授权范围 (Scope)</th>
              <th class="py-2.5 px-3">账户状态</th>
              <th class="py-2.5 px-3">最近登录 (UTC)</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100 font-network">
            <tr v-for="user in users" :key="user.id" class="hover:bg-slate-50/50">
              <td class="py-2.5 px-3 text-slate-400">{{ user.userKey }}</td>
              <td class="py-2.5 px-3">
                <span class="font-bold text-slate-800 font-sans block">{{ user.displayName }}</span>
                <span class="text-slate-500 text-[11px]">{{ user.username }}</span>
              </td>
              <td class="py-2.5 px-3 font-sans font-medium text-cyber-700">
                {{ user.roles[0]?.roleKey }}
              </td>
              <td class="py-2.5 px-3 font-mono text-slate-600">
                {{ user.roles[0]?.scopeId }}
              </td>
              <td class="py-2.5 px-3">
                <StatusBadge type="safe" text="ACTIVE" />
              </td>
              <td class="py-2.5 px-3 text-slate-400">{{ user.lastLoginAt?.replace('T', ' ').slice(0, 19) || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import StatusBadge from '@/components/common/StatusBadge.vue';
import { mockService } from '@/mock/mockService';

const users = ref(mockService.getUsers().data || []);
const roles = ref(mockService.getRoles().data || []);
</script>
