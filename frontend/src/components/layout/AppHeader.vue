<template>
  <header class="h-16 bg-white border-b border-slate-200/80 px-6 flex items-center justify-between z-20 shadow-xs">
    <!-- 左侧：传感器实时状态药丸 -->
    <div class="flex items-center gap-4">
      <div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-50 border border-slate-200 text-xs">
        <span class="flex h-2 w-2 relative">
          <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
        </span>
        <span class="font-medium text-slate-700">软件传感器:</span>
        <span class="font-mono text-emerald-600 font-semibold">2/2 在线</span>
        <span class="text-slate-300">|</span>
        <span class="text-slate-500 font-mono text-[11px]">Mac(en0) · Win(CUDA)</span>
      </div>

      <!-- 靶场隔离标记 -->
      <div class="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-sky-50 border border-sky-100 text-sky-700 text-xs font-medium">
        <span class="w-1.5 h-1.5 rounded-full bg-sky-500"></span>
        <span>靶场网络外联已物理隔离</span>
      </div>
    </div>

    <!-- 右侧：UTC时钟、7角色模拟切换器、用户卡片 -->
    <div class="flex items-center gap-4">
      <!-- UTC 时钟 -->
      <div class="hidden lg:flex items-center gap-2 text-xs font-mono text-slate-500 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-100">
        <svg class="w-3.5 h-3.5 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span>UTC 2026-09-24 09:30</span>
      </div>

      <!-- 7 角色快速切换模拟器 -->
      <div class="relative">
        <div class="flex items-center gap-2 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-xl px-3 py-1.5 cursor-pointer transition-colors" @click="showRoleDropdown = !showRoleDropdown">
          <span class="text-xs text-slate-400 font-medium">角色模拟:</span>
          <span class="text-xs font-semibold text-cyber-700">{{ currentRoleName }}</span>
          <svg class="w-3.5 h-3.5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        <!-- 下拉菜单 -->
        <div
          v-if="showRoleDropdown"
          class="absolute right-0 mt-2 w-72 bg-white rounded-2xl border border-slate-200 shadow-xl py-2 z-50 animate-in fade-in slide-in-from-top-2 duration-150"
        >
          <div class="px-4 py-2 border-b border-slate-100">
            <p class="text-xs font-bold text-slate-800">快速切换角色体验权限边界</p>
            <p class="text-[11px] text-slate-400">系统内置 7 个严格职责分离的专业岗位</p>
          </div>
          <div class="max-h-72 overflow-y-auto p-1.5 space-y-1">
            <button
              v-for="role in allRoles"
              :key="role.roleKey"
              class="w-full text-left px-3 py-2 rounded-xl text-xs flex flex-col gap-0.5 transition-colors"
              :class="currentRole === role.roleKey ? 'bg-sky-50 border border-sky-200 text-cyber-700 font-medium' : 'hover:bg-slate-50 text-slate-700'"
              @click="handleSelectRole(role.roleKey)"
            >
              <div class="flex items-center justify-between">
                <span class="font-semibold">{{ role.name }}</span>
                <span v-if="currentRole === role.roleKey" class="text-[10px] bg-cyber-600 text-white px-1.5 py-0.2 rounded-full font-mono">当前</span>
              </div>
              <span class="text-[10px] text-slate-400 truncate">{{ role.description }}</span>
            </button>
          </div>
        </div>
      </div>

      <!-- 用户信息卡片 -->
      <div class="flex items-center gap-3 pl-3 border-l border-slate-200">
        <div class="w-8 h-8 rounded-full bg-gradient-to-tr from-sky-400 to-cyber-600 text-white flex items-center justify-center font-bold text-xs shadow-sm">
          {{ currentUser.displayName.slice(0, 1) }}
        </div>
        <div class="hidden sm:flex flex-col">
          <span class="text-xs font-semibold text-slate-800">{{ currentUser.displayName }}</span>
          <span class="text-[10px] text-slate-400 font-mono">{{ currentUser.username }}</span>
        </div>
      </div>
    </div>
  </header>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useAuthStore } from '@/stores/auth';
import { useAlertStore } from '@/stores/alert';
import { storeToRefs } from 'pinia';
import { BuiltinRoleKey } from '@/types/iam';

const authStore = useAuthStore();
const alertStore = useAlertStore();
const { currentUser, currentRole, currentRoleName, allRoles } = storeToRefs(authStore);

const showRoleDropdown = ref(false);

function handleSelectRole(roleKey: BuiltinRoleKey) {
  authStore.switchRole(roleKey);
  showRoleDropdown.value = false;
  alertStore.info('身份已切换', `已进入 [${authStore.currentRoleName}] 视图与权限边界`);
}
</script>
