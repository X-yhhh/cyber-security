package com.xyh.cybersecurity.database;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MigrationIntegrationTest {

    private static final String EMPTY_SCHEMA = "cyber_security_backend_test_v3_20260923";
    private static final String OCCUPIED_SCHEMA = "cyber_security_backend_occupied_v3_20260923";
    private static String baseUrl;
    private static String username;
    private static String password;

    @BeforeAll
    static void prepareIsolatedSchemas() throws Exception {
        baseUrl = requiredEnv("DB_TEST_BASE_URL");
        username = requiredEnv("DB_TEST_USERNAME");
        password = requiredEnv("DB_TEST_PASSWORD");
        try (Connection connection = DriverManager.getConnection(baseUrl, username, password);
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + EMPTY_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
            statement.execute("CREATE DATABASE IF NOT EXISTS " + OCCUPIED_SCHEMA
                    + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
            statement.execute("CREATE TABLE IF NOT EXISTS " + OCCUPIED_SCHEMA
                    + ".preexisting_sentinel (id INT PRIMARY KEY)");
        }
    }

    @Test
    void migratesEmptySchemaWithRolePermissionMatrix() throws Exception {
        Flyway.configure()
                .dataSource(schemaUrl(EMPTY_SCHEMA), username, password)
                .locations("classpath:db/migration")
                .baselineOnMigrate(false)
                .load()
                .migrate();

        try (Connection connection = DriverManager.getConnection(schemaUrl(EMPTY_SCHEMA), username, password);
             Statement statement = connection.createStatement()) {
            assertThat(count(statement, "information_schema.tables", "table_schema='" + EMPTY_SCHEMA + "' AND table_type='BASE TABLE'"))
                    .isEqualTo(44);
            assertThat(count(statement, EMPTY_SCHEMA + ".sys_role", "is_builtin=1 AND status='active'"))
                    .isEqualTo(7);
            assertThat(count(statement, EMPTY_SCHEMA + ".sys_permission", "status='active'"))
                    .isEqualTo(37);
            assertThat(rolePermissionCount(statement, "platform_admin")).isEqualTo(21);
            assertThat(rolePermissionCount(statement, "asset_source_admin")).isEqualTo(10);
            assertThat(rolePermissionCount(statement, "security_analyst")).isEqualTo(8);
            assertThat(rolePermissionCount(statement, "response_approver")).isEqualTo(5);
            assertThat(rolePermissionCount(statement, "model_operator")).isEqualTo(5);
            assertThat(rolePermissionCount(statement, "model_releaser")).isEqualTo(2);
            assertThat(rolePermissionCount(statement, "auditor")).isEqualTo(3);
            assertThat(count(statement, EMPTY_SCHEMA + ".sys_role_permission rp JOIN " + EMPTY_SCHEMA
                    + ".sys_permission p ON p.id=rp.permission_id JOIN " + EMPTY_SCHEMA
                    + ".sys_role r ON r.id=rp.role_id", "p.permission_key='response.policy.manage'"))
                    .isZero();
            assertThat(count(statement, EMPTY_SCHEMA + ".sys_role_permission rp JOIN " + EMPTY_SCHEMA
                    + ".sys_permission p ON p.id=rp.permission_id JOIN " + EMPTY_SCHEMA
                    + ".sys_role r ON r.id=rp.role_id", "r.role_key='platform_admin' AND p.permission_key IN ('approval.decide','model.release.approve')"))
                    .isZero();
            assertThat(count(statement, EMPTY_SCHEMA + ".sys_user", "1=1")).isZero();
            assertThat(count(statement, EMPTY_SCHEMA + ".flyway_schema_history", "success=1")).isEqualTo(8);
            assertThat(count(statement, "information_schema.tables", "table_schema='" + EMPTY_SCHEMA
                    + "' AND table_name='auth_login_throttle'"))
                    .isEqualTo(1);
            assertThat(columnCount(statement, "model_release_record", "review_status")).isEqualTo(1);
            assertThat(columnCount(statement, "model_release_record", "request_reason")).isEqualTo(1);
            assertThat(columnCount(statement, "model_release_record", "decision_reason")).isEqualTo(1);
            assertThat(columnCount(statement, "approval_task", "idempotency_key")).isEqualTo(1);
            assertThat(columnCount(statement, "approval_task", "request_digest")).isEqualTo(1);
            assertThat(columnCount(statement, "api_client", "sensor_id")).isEqualTo(1);
            assertThat(columnCount(statement, "ingest_batch", "sequence_gap")).isEqualTo(1);
            assertThat(columnCount(statement, "ingest_batch", "feature_contract_version")).isEqualTo(1);
        }
    }

    @Test
    void refusesToBaselineNonemptySchemaWithoutHistory() throws Exception {
        assertThatThrownBy(() -> Flyway.configure()
                .dataSource(schemaUrl(OCCUPIED_SCHEMA), username, password)
                .locations("classpath:db/migration")
                .baselineOnMigrate(false)
                .load()
                .migrate())
                .isInstanceOf(FlywayException.class)
                .hasMessageContaining("non-empty schema");

        try (Connection connection = DriverManager.getConnection(schemaUrl(OCCUPIED_SCHEMA), username, password);
             Statement statement = connection.createStatement()) {
            assertThat(count(statement, "information_schema.tables", "table_schema='" + OCCUPIED_SCHEMA
                    + "' AND table_name='preexisting_sentinel'"))
                    .isEqualTo(1);
            assertThat(count(statement, "information_schema.tables", "table_schema='" + OCCUPIED_SCHEMA
                    + "' AND table_name='flyway_schema_history'"))
                    .isZero();
        }
    }

    @Test
    void applicationConfigurationKeepsAutomaticBaselineDisabled() {
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yml"));
        Properties properties = yaml.getObject();

        assertThat(properties).isNotNull();
        assertThat(properties.getProperty("spring.flyway.baseline-on-migrate")).isEqualTo("false");
    }

    private static int rolePermissionCount(Statement statement, String roleKey) throws Exception {
        String sql = "SELECT COUNT(*) FROM " + EMPTY_SCHEMA + ".sys_role_permission rp "
                + "JOIN " + EMPTY_SCHEMA + ".sys_role r ON r.id=rp.role_id WHERE r.role_key='" + roleKey + "'";
        try (ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

    private static int columnCount(Statement statement, String table, String column) throws Exception {
        String sql = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='" + EMPTY_SCHEMA
                + "' AND table_name='" + table + "' AND column_name='" + column + "'";
        try (ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

    private static int count(Statement statement, String table, String predicate) throws Exception {
        String sql = "SELECT COUNT(*) FROM " + table + " WHERE " + predicate;
        try (ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

    private static String schemaUrl(String schema) {
        return baseUrl.replaceFirst("/+$", "") + "/" + schema
                + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
    }

    private static String requiredEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing test configuration: " + name);
        }
        return value;
    }
}
