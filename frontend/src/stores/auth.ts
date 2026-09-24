import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { User, BuiltinRoleKey, RoleInfo } from '@/types/iam';
import { mockService } from '@/mock/mockService';

export const useAuthStore = defineStore('auth', () => {
  const currentUser = ref<User>(mockService.getCurrentUser().data!);
  const allRoles = ref<RoleInfo[]>(mockService.getRoles().data!);

  // 当前激活的首要角色
  const currentRole = computed<BuiltinRoleKey>(() => {
    return currentUser.value.roles[0]?.roleKey || 'security_analyst';
  });

  const currentRoleName = computed<string>(() => {
    const role = allRoles.value.find(r => r.roleKey === currentRole.value);
    return role ? role.name : '未知角色';
  });

  // 检查是否具备某权限
  function hasPermission(permission: string): boolean {
    const role = allRoles.value.find(r => r.roleKey === currentRole.value);
    if (!role) return false;
    return role.permissions.includes(permission) || role.roleKey === 'platform_admin';
  }

  // 模拟切换角色
  function switchRole(roleKey: BuiltinRoleKey) {
    const res = mockService.switchRole(roleKey);
    if (res.success && res.data) {
      currentUser.value = res.data;
      return true;
    }
    return false;
  }

  return {
    currentUser,
    allRoles,
    currentRole,
    currentRoleName,
    hasPermission,
    switchRole
  };
});
