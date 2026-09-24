<template>
  <aside
    class="bg-white border-r border-slate-200/80 flex flex-col transition-all duration-300 z-30 select-none shadow-sm"
    :class="collapsed ? 'w-18' : 'w-64'"
  >
    <!-- 顶部 Logo 与系统标识 -->
    <div class="h-16 px-4 flex items-center justify-between border-b border-slate-100 bg-white">
      <div v-if="!collapsed" class="flex items-center gap-3 overflow-hidden">
        <div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyber-700 to-cyber-500 flex items-center justify-center text-white shadow-md shadow-cyber-500/20 flex-shrink-0">
          <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <div class="flex flex-col min-w-0">
          <span class="text-sm font-bold text-slate-900 tracking-tight truncate">内网威胁防御平台</span>
          <span class="text-[10px] text-cyber-600 font-mono font-medium tracking-wider">SECOPS CONSOLE</span>
        </div>
      </div>
      <div v-else class="w-full flex justify-center">
        <div class="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyber-700 to-cyber-500 flex items-center justify-center text-white shadow-md shadow-cyber-500/20">
          <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
      </div>

      <button
        v-if="!collapsed"
        class="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
        @click="collapsed = true"
        title="折叠侧栏"
      >
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
        </svg>
      </button>
    </div>

    <!-- 导航菜单列表 -->
    <div class="flex-1 overflow-y-auto px-3 py-4 space-y-6">
      <div v-for="(group, gIdx) in navGroups" :key="gIdx" class="space-y-1">
        <div
          v-if="!collapsed"
          class="px-3 text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-2"
        >
          {{ group.title }}
        </div>
        <router-link
          v-for="item in group.items"
          :key="item.path"
          :to="item.path"
          class="flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all group"
          :class="isActive(item.path) ? 'bg-sky-50 text-cyber-700 font-semibold shadow-xs' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'"
          :title="collapsed ? item.label : undefined"
        >
          <component
            :is="item.icon"
            class="w-4.5 h-4.5 flex-shrink-0 transition-colors"
            :class="isActive(item.path) ? 'text-cyber-600' : 'text-slate-400 group-hover:text-slate-600'"
          />
          <span v-if="!collapsed" class="truncate flex-1">{{ item.label }}</span>
          <span
            v-if="!collapsed && item.badge"
            class="px-2 py-0.5 text-[11px] font-bold font-mono rounded-full"
            :class="item.badgeClass || 'bg-red-100 text-red-700'"
          >
            {{ item.badge }}
          </span>
        </router-link>
      </div>
    </div>

    <!-- 底部收起按钮 (折叠状态下点击展开) -->
    <div v-if="collapsed" class="p-3 border-t border-slate-100 flex justify-center">
      <button
        class="text-slate-400 hover:text-slate-600 p-2 rounded-xl hover:bg-slate-100 transition-colors"
        @click="collapsed = false"
        title="展开侧栏"
      >
        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 5l7 7-7 7M5 5l7 7-7 7" />
        </svg>
      </button>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useRoute } from 'vue-router';
import {
  LayoutDashboard,
  ShieldAlert,
  ShieldCheck,
  Server,
  Database,
  Cpu,
  Repeat,
  FileText,
  Users
} from 'lucide-vue-next';

const route = useRoute();
const collapsed = ref(false);

function isActive(path: string) {
  if (path === '/dashboard') return route.path === '/dashboard';
  return route.path.startsWith(path);
}

const navGroups = [
  {
    title: '态势与研判',
    items: [
      { label: '态势感知总览', path: '/dashboard', icon: LayoutDashboard },
      { label: '威胁研判中心', path: '/incidents', icon: ShieldAlert, badge: '4' },
      { label: '受控防御审批', path: '/response', icon: ShieldCheck, badge: '1', badgeClass: 'bg-purple-100 text-purple-700' }
    ]
  },
  {
    title: '资产与数据源',
    items: [
      { label: '资产与传感器', path: '/assets', icon: Server },
      { label: '数据源与映射', path: '/datasources', icon: Database }
    ]
  },
  {
    title: '模型与演练',
    items: [
      { label: '模型治理中心', path: '/models', icon: Cpu, badge: '候选', badgeClass: 'bg-amber-100 text-amber-800' },
      { label: '隔离靶场回放', path: '/replay', icon: Repeat }
    ]
  },
  {
    title: '治理与运维',
    items: [
      { label: '安全审计日志', path: '/audit', icon: FileText },
      { label: '访问控制与IAM', path: '/iam', icon: Users }
    ]
  }
];
</script>
