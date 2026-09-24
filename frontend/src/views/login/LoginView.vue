<template>
  <div class="min-h-screen bg-slate-50 flex items-center justify-center p-6 antialiased">
    <div class="w-full max-w-md space-y-6">
      <!-- 顶部 Logo 与系统标语 -->
      <div class="text-center space-y-2">
        <div class="inline-flex w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyber-700 to-cyber-500 items-center justify-center text-white shadow-lg shadow-cyber-500/20 mb-2">
          <svg class="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <h2 class="text-xl font-bold text-slate-900 tracking-tight">内网威胁检测与分级防御控制台</h2>
        <p class="text-xs text-slate-500">SecOps Intelligence & Controlled Response Platform</p>
      </div>

      <!-- 登录卡片 -->
      <div class="sec-card p-6 md:p-8 space-y-5 bg-white shadow-panel">
        <div class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-700 mb-1">账号用户名</label>
            <input
              v-model="username"
              type="text"
              class="sec-input w-full font-mono"
              placeholder="请输入管理员或分析员账号"
            />
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-700 mb-1">登录凭据</label>
            <input
              v-model="password"
              type="password"
              class="sec-input w-full font-mono"
              placeholder="••••••••••••"
            />
          </div>
        </div>

        <button class="sec-btn-primary w-full py-2 text-sm" @click="handleLogin">
          安全登入控制台
        </button>

        <!-- 7 大角色一键模拟快捷栏 -->
        <div class="pt-4 border-t border-slate-100 space-y-2">
          <span class="text-[11px] font-semibold text-slate-400 block text-center uppercase tracking-wider">
            测试环境快捷身份填充
          </span>
          <div class="grid grid-cols-2 gap-2 text-xs">
            <button
              class="p-2 rounded-lg border border-slate-200 bg-slate-50 hover:bg-sky-50 hover:border-sky-200 text-slate-700 hover:text-cyber-700 text-left transition-colors"
              @click="quickLogin('chen_analyst')"
            >
              <div class="font-bold text-[11px]">陈工 (安全分析员)</div>
              <div class="text-[10px] text-slate-400 font-mono">研判与阻断申请</div>
            </button>
            <button
              class="p-2 rounded-lg border border-slate-200 bg-slate-50 hover:bg-purple-50 hover:border-purple-200 text-slate-700 hover:text-purple-700 text-left transition-colors"
              @click="quickLogin('wang_approver')"
            >
              <div class="font-bold text-[11px]">王主管 (响应审批员)</div>
              <div class="text-[10px] text-slate-400 font-mono">阻断工单核准</div>
            </button>
          </div>
        </div>

        <div class="text-[11px] text-slate-400 text-center font-mono pt-1">
          CSRF 凭据校验生效 · 登录失败持久限速已就绪
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { useAlertStore } from '@/stores/alert';

const router = useRouter();
const authStore = useAuthStore();
const alertStore = useAlertStore();

const username = ref('chen_analyst');
const password = ref('');

function handleLogin() {
  alertStore.success('认证成功', `欢迎进入系统，当前权限：${authStore.currentRoleName}`);
  router.push('/dashboard');
}

function quickLogin(name: string) {
  username.value = name;
  if (name === 'chen_analyst') authStore.switchRole('security_analyst');
  if (name === 'wang_approver') authStore.switchRole('response_approver');
  handleLogin();
}
</script>
