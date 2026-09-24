package com.xyh.cybersecurity.identity;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/** 从 MySQL 身份事实和角色权限模板解析人工用户主体。 */
@Service
public class IdentityUserDetailsService implements UserDetailsService {

    private final JdbcTemplate jdbcTemplate;

    public IdentityUserDetailsService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public IdentityPrincipal loadUserByUsername(String username) throws UsernameNotFoundException {
        List<IdentityPrincipal> users = jdbcTemplate.query(
                "SELECT id, user_key, username, display_name, password_hash, status "
                        + "FROM sys_user WHERE username = ?",
                (rs, rowNum) -> {
                    long id = rs.getLong("id");
                    return new IdentityPrincipal(id, rs.getString("user_key"), rs.getString("username"),
                            rs.getString("display_name"), rs.getString("password_hash"), rs.getString("status"),
                            loadRoles(id), loadPermissions(id));
                }, username);
        if (users.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }
        return users.getFirst();
    }

    private List<String> loadRoles(long userId) {
        return jdbcTemplate.queryForList(
                "SELECT DISTINCT r.role_key FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id = ur.role_id "
                        + "WHERE ur.user_id = ? AND r.status = 'active' ORDER BY r.role_key",
                String.class, userId);
    }

    private List<String> loadPermissions(long userId) {
        return jdbcTemplate.queryForList(
                "SELECT DISTINCT p.permission_key FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id = ur.role_id "
                        + "JOIN sys_role_permission rp ON rp.role_id = r.id "
                        + "JOIN sys_permission p ON p.id = rp.permission_id "
                        + "WHERE ur.user_id = ? AND r.status = 'active' AND p.status = 'active' "
                        + "ORDER BY p.permission_key",
                String.class, userId);
    }

}
