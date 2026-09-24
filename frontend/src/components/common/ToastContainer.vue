<template>
  <div class="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 max-w-sm w-full pointer-events-none">
    <TransitionGroup
      enter-active-class="transition duration-300 ease-out"
      enter-from-class="transform translate-y-4 opacity-0 scale-95"
      enter-to-class="transform translate-y-0 opacity-100 scale-100"
      leave-active-class="transition duration-200 ease-in"
      leave-from-class="transform opacity-100"
      leave-to-class="transform translate-x-8 opacity-0"
    >
      <div
        v-for="toast in toasts"
        :key="toast.id"
        class="pointer-events-auto p-4 rounded-xl border shadow-lg flex items-start gap-3 bg-white"
        :class="borderClass(toast.type)"
      >
        <!-- 图标 -->
        <div class="mt-0.5 flex-shrink-0">
          <span v-if="toast.type === 'success'" class="text-emerald-600">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </span>
          <span v-else-if="toast.type === 'error'" class="text-red-600">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </span>
          <span v-else-if="toast.type === 'warning'" class="text-amber-600">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </span>
          <span v-else class="text-sky-600">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </span>
        </div>

        <div class="flex-1 space-y-0.5">
          <h4 class="text-sm font-semibold text-slate-800">{{ toast.title }}</h4>
          <p v-if="toast.message" class="text-xs text-slate-500 leading-relaxed">{{ toast.message }}</p>
        </div>
      </div>
    </TransitionGroup>
  </div>
</template>

<script setup lang="ts">
import { useAlertStore } from '@/stores/alert';
import { storeToRefs } from 'pinia';

const alertStore = useAlertStore();
const { toasts } = storeToRefs(alertStore);

function borderClass(type: string) {
  switch (type) {
    case 'success':
      return 'border-emerald-200 bg-emerald-50/20';
    case 'error':
      return 'border-red-200 bg-red-50/20';
    case 'warning':
      return 'border-amber-200 bg-amber-50/20';
    default:
      return 'border-sky-200 bg-sky-50/20';
  }
}
</script>
