<template>
  <div class="min-h-screen bg-canvas flex flex-col antialiased">
    <div class="flex-1 flex overflow-hidden">
      <!-- 侧边导航栏 -->
      <AppSidebar />

      <!-- 主区域 -->
      <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
        <!-- 顶栏 -->
        <AppHeader />

        <!-- 页面视图区域 -->
        <main class="flex-1 overflow-y-auto p-6 md:p-8 bg-slate-50/60">
          <div class="max-w-7xl mx-auto space-y-6">
            <router-view v-slot="{ Component }">
              <Transition
                mode="out-in"
                enter-active-class="transition duration-150 ease-out"
                enter-from-class="opacity-0 translate-y-1"
                enter-to-class="opacity-100 translate-y-0"
                leave-active-class="transition duration-100 ease-in"
                leave-from-class="opacity-100 translate-y-0"
                leave-to-class="opacity-0 translate-y-1"
              >
                <component :is="Component" />
              </Transition>
            </router-view>
          </div>
        </main>
      </div>
    </div>

    <!-- 全局轻提示容器 -->
    <ToastContainer />
  </div>
</template>

<script setup lang="ts">
import AppSidebar from './AppSidebar.vue';
import AppHeader from './AppHeader.vue';
import ToastContainer from '@/components/common/ToastContainer.vue';
</script>
