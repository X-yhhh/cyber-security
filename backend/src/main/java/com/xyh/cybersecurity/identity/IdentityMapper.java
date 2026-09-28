package com.xyh.cybersecurity.identity;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/** 读取身份、内置角色和角色权限模板，不提供模板写入方法。 */
@Mapper
public interface IdentityMapper {

    PrincipalRow findPrincipalByUsername(@Param("username") String username);

    List<String> listUserRoles(@Param("userId") long userId);

    List<String> listUserPermissions(@Param("userId") long userId);

    AdminRow findAdmin();

    int insertAdmin(@Param("userKey") String userKey, @Param("displayName") String displayName,
                    @Param("passwordHash") String passwordHash);

    Long findUserIdByUsername(@Param("username") String username);

    Long findPlatformAdminRoleId();

    int ensureGlobalPlatformAdminBinding(@Param("userId") long userId, @Param("roleId") long roleId);

    int updateLastLogin(@Param("userId") long userId, @Param("loggedAt") java.time.Instant loggedAt);

    int deleteSession(@Param("username") String username);

    int countBlockedThrottle(@Param("keyHash") String keyHash, @Param("now") java.time.Instant now);

    int upsertThrottleFailure(@Param("keyHash") String keyHash, @Param("now") java.time.Instant now);

    int clearThrottle(@Param("keyHash") String keyHash);

    int insertUser(@Param("userKey") String userKey, @Param("username") String username,
                   @Param("displayName") String displayName, @Param("passwordHash") String passwordHash);

    Long findUserIdByKey(@Param("userKey") String userKey);

    int deleteUserRoles(@Param("userId") long userId);

    int insertUserRole(@Param("userId") long userId, @Param("roleId") long roleId,
                       @Param("scopeType") String scopeType, @Param("scopeId") String scopeId);

    boolean hasGlobalConfigAdmin(@Param("userId") long userId);

    int insertMachineClient(@Param("clientKey") String clientKey, @Param("credentialSha256") String credentialSha256,
                            @Param("scopeJson") String scopeJson);

    Long findMachineClientId(@Param("clientKey") String clientKey);

    int insertClientScope(@Param("clientId") long clientId, @Param("scopeType") String scopeType,
                          @Param("scopeId") String scopeId);

    int insertClientBinding(@Param("clientId") long clientId, @Param("dataSourceId") long dataSourceId,
                            @Param("assetId") long assetId);

    int grantMachineIngestPermission(@Param("clientId") long clientId);

    boolean activeSourceAssetPair(@Param("dataSourceId") long dataSourceId, @Param("assetId") long assetId);

    MachineClientRow findActiveMachineClient(@Param("clientId") long clientId);

    List<String> listMachinePermissions(@Param("clientId") long clientId);

    long countUsers();

    List<UserView> listUsers(@Param("offset") int offset, @Param("limit") int limit);

    UserView findUser(@Param("id") long id);

    List<RoleView> listRoles();

    List<String> listRolePermissions(@Param("roleId") long roleId);

    Long findActiveBuiltinRoleId(@Param("roleKey") String roleKey);

    boolean existsScope(@Param("scopeType") String scopeType, @Param("scopeId") String scopeId);

    List<Long> lockActiveGlobalPlatformAdministratorIds();

    List<RoleBinding> listRoleBindings(@Param("userId") long userId);

    record UserView(long id, String userKey, String username, String displayName, String status) { }

    record RoleView(long id, String roleKey, String name, String description) { }

    record RoleBinding(String roleKey, String scopeType, String scopeId) { }

    record PrincipalRow(long id, String userKey, String username, String displayName,
                        String passwordHash, String status) { }

    record AdminRow(long id, String passwordHash) { }

    record MachineClientRow(String clientKey, String clientType, String credentialSha256) { }
}
