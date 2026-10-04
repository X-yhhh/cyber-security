package com.xyh.cybersecurity.database;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 验证应用自身保证数据库连接使用 UTC，而不依赖 {@code DB_URL} 是否带时区参数。
 *
 * <p>数据源地址刻意不带 {@code connectionTimeZone}/{@code forceConnectionTimeZoneToSession}，
 * 模拟开发库的真实写法。若 application.yml 未设置 Hikari 数据源属性，会话时区会跟随服务端
 * （本机为 UTC+8），Java 写入的 {@link Instant} 与 SQL 中 {@code UTC_TIMESTAMP} 的比较会错位。</p>
 */
@SpringBootTest
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class DataSourceTimeZoneIntegrationTest {

    private static final String TEST_SCHEMA = "cyber_security_backend_timezone_20260929";

    @BeforeAll
    static void migrateTimeZoneTestSchema() throws Exception {
        String baseUrl = System.getenv("DB_TEST_BASE_URL");
        String username = System.getenv("DB_TEST_USERNAME");
        String credential = System.getenv("DB_TEST_PASSWORD");
        try (java.sql.Connection connection = java.sql.DriverManager.getConnection(baseUrl, username, credential);
             java.sql.Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(baseUrl.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, username, credential)
                .locations("classpath:db/migration").baselineOnMigrate(false).load().migrate();
    }

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        String baseUrl = System.getenv("DB_TEST_BASE_URL");
        // 不附加任何时区参数：时区必须由 application.yml 的 Hikari 数据源属性保证。
        registry.add("spring.datasource.url", () -> baseUrl.replaceFirst("[/?]+$", "") + "/" + TEST_SCHEMA);
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "test-only-key-with-at-least-thirty-two-bytes");
    }

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void sessionTimeZoneIsUtcEvenWhenTheUrlOmitsTimeZoneParameters() {
        assertThat(jdbcTemplate.queryForObject("SELECT @@session.time_zone", String.class))
                .isIn("UTC", "+00:00");
        // 会话时区为 UTC 时，列默认值 CURRENT_TIMESTAMP 与 UTC_TIMESTAMP 取值一致。
        assertThat(jdbcTemplate.queryForObject(
                "SELECT ABS(TIMESTAMPDIFF(SECOND, NOW(), UTC_TIMESTAMP()))", Long.class)).isLessThanOrEqualTo(1L);
    }

    @Test
    void javaInstantIsStoredOnTheSameClockAsUtcTimestamp() {
        // Java 写入的当前时刻与数据库 UTC 当前时刻应同一口径；错位时差值会是整小时数。
        Long driftSeconds = jdbcTemplate.queryForObject(
                "SELECT ABS(TIMESTAMPDIFF(SECOND, CAST(? AS DATETIME(3)), UTC_TIMESTAMP(3)))",
                Long.class, Instant.now());
        assertThat(driftSeconds).isLessThanOrEqualTo(5L);
    }
}
