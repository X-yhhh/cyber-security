package com.xyh.cybersecurity.identity;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

/** 读取身份、内置角色和角色权限模板，不提供模板写入方法。 */
@Mapper
public interface IdentityMapper {

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
}
