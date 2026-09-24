package com.xyh.cybersecurity.identity;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/** 验证 local profile 只为缺失账号设置测试密码，已有 admin 只补预定义角色。 */
@SpringBootTest
@ActiveProfiles("local")
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class LocalAdminBootstrapIntegrationTest {

    private static final String TEST_SCHEMA = "cyber_security_backend_bootstrap_20260923";

    @BeforeAll
    static void migrateBootstrapTestSchema() throws Exception {
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
    private PasswordEncoder passwordEncoder;

    @Autowired
    private LocalAdminBootstrap bootstrap;

    @BeforeEach
    void resetOnlyTheIsolatedAdminFixture() {
        jdbcTemplate.update("UPDATE sys_user SET password_hash=? WHERE username='admin'",
                passwordEncoder.encode("admin"));
        jdbcTemplate.update("DELETE ur FROM sys_user_role ur JOIN sys_user u ON u.id=ur.user_id "
                + "JOIN sys_role r ON r.id=ur.role_id WHERE u.username='admin' AND r.role_key='platform_admin'");
        bootstrap.run(new DefaultApplicationArguments(new String[0]));
    }

    @Test
    void createsMissingAdminAndPreservesAnExistingHashWhenBindingItsRole() {
        String initialHash = jdbcTemplate.queryForObject(
                "SELECT password_hash FROM sys_user WHERE username='admin'", String.class);
        long adminId = jdbcTemplate.queryForObject("SELECT id FROM sys_user WHERE username='admin'", Long.class);
        assertThat(passwordEncoder.matches("admin", initialHash)).isTrue();
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id=ur.role_id WHERE ur.user_id=? "
                        + "AND r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*'",
                Integer.class, adminId)).isEqualTo(1);

        String preservedHash = passwordEncoder.encode("preserved-local-hash-fixture");
        jdbcTemplate.update("UPDATE sys_user SET password_hash=? WHERE id=?", preservedHash, adminId);
        bootstrap.run(new DefaultApplicationArguments(new String[0]));

        assertThat(jdbcTemplate.queryForObject(
                "SELECT password_hash FROM sys_user WHERE id=?", String.class, adminId)).isEqualTo(preservedHash);
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM sys_user WHERE username='admin'", Integer.class))
                .isEqualTo(1);
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM sys_user_role ur "
                        + "JOIN sys_role r ON r.id=ur.role_id WHERE ur.user_id=? "
                        + "AND r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*'",
                Integer.class, adminId)).isEqualTo(1);
    }
}
