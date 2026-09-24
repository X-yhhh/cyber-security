import { defineStore } from 'pinia';
import { ref } from 'vue';

export interface ToastMessage {
  id: number;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
}

export const useAlertStore = defineStore('alert', () => {
  const toasts = ref<ToastMessage[]>([]);

  function showToast(type: ToastMessage['type'], title: string, message?: string) {
    const id = Date.now();
    toasts.value.push({ id, type, title, message });
    setTimeout(() => {
      toasts.value = toasts.value.filter(t => t.id !== id);
    }, 4000);
  }

  function success(title: string, message?: string) {
    showToast('success', title, message);
  }

  function error(title: string, message?: string) {
    showToast('error', title, message);
  }

  function warning(title: string, message?: string) {
    showToast('warning', title, message);
  }

  function info(title: string, message?: string) {
    showToast('info', title, message);
  }

  return {
    toasts,
    showToast,
    success,
    error,
    warning,
    info
  };
});
