package com.xyh.cybersecurity.audit;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/** 验证审计查询要求范围型记录的全部关联资源均可见。 */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class AuditScopeMapperTest {

    private static final String TEST_SCHEMA = "cyber_security_backend_audit_20260923";
    private static final String AUDITOR = "audit-scope-test";
    private static final String PLATFORM_ADMIN = "audit-platform-test";
    private static final String VISIBLE_ASSET = "10001";
    private static final String HIDDEN_ASSET = "10002";

    @BeforeAll
    static void migrateAuditTestSchema() throws Exception {
        String baseUrl = System.getenv("DB_TEST_BASE_URL");
        String username = System.getenv("DB_TEST_USERNAME");
        String password = System.getenv("DB_TEST_PASSWORD");
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(baseUrl, username, password);
             java.sql.Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(baseUrl.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, username, password)
                .locations("classpath:db/migration").baselineOnMigrate(false).load().migrate();
    }

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        String baseUrl = System.getenv("DB_TEST_BASE_URL");
        registry.add("spring.datasource.url", () -> baseUrl.replaceFirst("/+$", "") + "/" + TEST_SCHEMA
                + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "test-only-key-with-at-least-thirty-two-bytes");
    }

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AuditMapper auditMapper;

    private long auditorId;
    private long platformAdminId;
    private long inScopeAuditId;

    @BeforeEach
    void seedAuditScopeFixtures() {
        jdbcTemplate.update("DELETE FROM SPRING_SESSION");
        jdbcTemplate.update("DELETE FROM audit_resource_scope");
        jdbcTemplate.update("DELETE FROM audit_log");
        jdbcTemplate.update("DELETE FROM sys_user_role");
        jdbcTemplate.update("DELETE FROM sys_user WHERE username IN (?, ?)", AUDITOR, PLATFORM_ADMIN);
        auditorId = createUser(AUDITOR);
        platformAdminId = createUser(PLATFORM_ADMIN);
        bindRole(AUDITOR, "auditor", "asset", VISIBLE_ASSET);
        bindRole(PLATFORM_ADMIN, "platform_admin", "global", "*");

        inScopeAuditId = createAudit("audit.in-scope", VISIBLE_ASSET);
        createAudit("audit.out-of-scope", HIDDEN_ASSET);
        createUnscopedAudit("audit.system-unscoped");
        long mixedScopeAuditId = createUnscopedAudit("audit.mixed-scope");
        attachScope(mixedScopeAuditId, VISIBLE_ASSET);
        attachScope(mixedScopeAuditId, HIDDEN_ASSET);
    }

    @Test
    void scopedAuditorSeesOnlyRecordsWhoseEveryResourceIsInScope() {
        assertThat(auditMapper.countVisible(auditorId)).isEqualTo(1);
        assertThat(auditMapper.listVisible(auditorId, 0, 20))
                .extracting(AuditMapper.AuditView::id).containsExactly(inScopeAuditId);
    }

    @Test
    void platformAdminCanReadGlobalAndUnscopedAuditRecords() {
        assertThat(auditMapper.countVisible(platformAdminId)).isEqualTo(4);
        assertThat(auditMapper.listVisible(platformAdminId, 0, 20)).hasSize(4);
    }

    private long createUser(String username) {
        jdbcTemplate.update("INSERT INTO sys_user (user_key, username, display_name, status, password_hash) "
                        + "VALUES (?, ?, ?, 'active', ?)", username, username, username,
                "$2a$10$5aZVHpZ0LX0HnZ7GdPzzauEAwRK1EZ6f1A2a9B6utZbXv1Cyga7HS");
        return jdbcTemplate.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private void bindRole(String username, String roleKey, String scopeType, String scopeId) {
        jdbcTemplate.update("INSERT INTO sys_user_role (user_id, role_id, scope_type, scope_id) "
                        + "SELECT u.id, r.id, ?, ? FROM sys_user u JOIN sys_role r ON r.role_key=? "
                        + "WHERE u.username=?", scopeType, scopeId, roleKey, username);
    }

    private long createAudit(String action, String scopeId) {
        long auditId = createUnscopedAudit(action);
        attachScope(auditId, scopeId);
        return auditId;
    }

    private long createUnscopedAudit(String action) {
        jdbcTemplate.update("INSERT INTO audit_log (occurred_at, actor_type, action, resource_type, outcome) "
                        + "VALUES (UTC_TIMESTAMP(3), 'human', ?, 'test', 'success')", action);
        return jdbcTemplate.queryForObject("SELECT LAST_INSERT_ID()", Long.class);
    }

    private void attachScope(long auditId, String scopeId) {
        jdbcTemplate.update("INSERT INTO audit_resource_scope (audit_id, scope_type, scope_id) VALUES (?, 'asset', ?)",
                auditId, scopeId);
    }
}
