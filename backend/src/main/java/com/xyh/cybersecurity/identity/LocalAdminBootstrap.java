package com.xyh.cybersecurity.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;

/** 仅本机 local profile 确保联调管理员存在；不得重置既有密码、状态或用户标识。 */
@Component
@Profile("local")
@ConditionalOnProperty(prefix = "cyber.security.local-admin-bootstrap", name = "enabled", havingValue = "true")
public class LocalAdminBootstrap implements ApplicationRunner {

    private static final Logger logger = LoggerFactory.getLogger(LocalAdminBootstrap.class);
    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;

    public LocalAdminBootstrap(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        var userIds = jdbcTemplate.query("SELECT id, password_hash FROM sys_user WHERE username='admin'",
                (rs, rowNum) -> new AdminRow(rs.getLong("id"), rs.getString("password_hash")));
        long adminId;
        if (userIds.isEmpty()) {
            jdbcTemplate.update("INSERT INTO sys_user "
                            + "(user_key, username, display_name, status, password_hash) VALUES (?, ?, ?, 'active', ?)",
                    "bootstrap-admin", "admin", "本机测试管理员", passwordEncoder.encode("admin"));
            adminId = jdbcTemplate.queryForObject("SELECT id FROM sys_user WHERE username='admin'", Long.class);
        } else {
            AdminRow admin = userIds.getFirst();
            adminId = admin.id();
            if (admin.passwordHash() == null || !passwordEncoder.matches("admin", admin.passwordHash())) {
                logger.warn("Existing admin password hash was preserved; local credentials may differ from admin/admin.");
            }
        }

        Long roleId = jdbcTemplate.queryForObject(
                "SELECT id FROM sys_role WHERE role_key='platform_admin' AND status='active'", Long.class);
        int added = jdbcTemplate.update("INSERT INTO sys_user_role (user_id, role_id, scope_type, scope_id) "
                        + "SELECT ?, ?, 'global', '*' WHERE NOT EXISTS (SELECT 1 FROM sys_user_role "
                        + "WHERE user_id=? AND role_id=? AND scope_type='global' AND scope_id='*')",
                adminId, roleId, adminId, roleId);
        if (added > 0) {
            jdbcTemplate.update("INSERT INTO audit_log "
                            + "(occurred_at, actor_type, actor_id, action, resource_type, resource_id, outcome, reason) "
                            + "VALUES (?, 'system', 'local-bootstrap', 'iam.admin.bootstrap', 'user', ?, 'success', ?)",
                    Timestamp.from(Instant.now()), Long.toString(adminId), "local profile added platform_admin role binding");
        }
    }

    private record AdminRow(long id, String passwordHash) {
    }
}
