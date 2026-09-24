export type BuiltinRoleKey =
  | 'platform_admin'
  | 'asset_source_admin'
  | 'security_analyst'
  | 'response_approver'
  | 'model_operator'
  | 'model_releaser'
  | 'auditor';

export interface RoleInfo {
  id: number;
  roleKey: BuiltinRoleKey;
  name: string;
  description: string;
  isBuiltin: boolean;
  permissions: string[];
}

export type ScopeType = 'global' | 'asset' | 'data_source' | 'model_registry';

export interface UserRoleScope {
  roleKey: BuiltinRoleKey;
  scopeType: ScopeType;
  scopeId: string; // 'global/*' 或 资源唯一键
}

export interface User {
  id: number;
  userKey: string;
  username: string;
  displayName: string;
  email?: string;
  status: 'active' | 'suspended';
  createdAt: string;
  lastLoginAt?: string;
  roles: UserRoleScope[];
}

export interface MachineClient {
  id: number;
  clientKey: string;
  clientType: 'connector';
  status: 'active' | 'revoked';
  expiresAt?: string;
  credentialSha256: string;
  sourceAssetBindings: Array<{
    dataSourceId: string;
    assetId: string;
  }>;
  createdAt: string;
}
