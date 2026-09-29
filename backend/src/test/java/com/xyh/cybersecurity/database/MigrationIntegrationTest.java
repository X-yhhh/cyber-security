package com.xyh.cybersecurity.database;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.FlywayException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
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
                    .isEqualTo(46);
            assertThat(count(statement, EMPTY_SCHEMA + ".sys_role", "is_builtin=1 AND status='active'"))
                    .isEqualTo(7);
            assertThat(count(statement, EMPTY_SCHEMA + ".sys_permission", "status='active'"))
                    .isEqualTo(43);
            // V12 新增 inference.request.read（四个角色）与 model.replay.run（仅 model_operator）；
            // V13 新增 detection.rule.read（平台管理员、分析员、审批人）、manage（分析员）、approve（审批人）；
            // V14 新增 source.mapping.approve（平台管理员）。
            assertThat(rolePermissionCount(statement, "platform_admin")).isEqualTo(24);
            assertThat(rolePermissionCount(statement, "asset_source_admin")).isEqualTo(11);
            assertThat(rolePermissionCount(statement, "security_analyst")).isEqualTo(11);
            assertThat(rolePermissionCount(statement, "response_approver")).isEqualTo(7);
            assertThat(rolePermissionCount(statement, "model_operator")).isEqualTo(7);
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
            assertThat(count(statement, EMPTY_SCHEMA + ".flyway_schema_history", "success=1")).isEqualTo(14);
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
            assertThat(indexCount(statement, "ingest_record", "idx_ingest_record_created_quality_asset")).isEqualTo(1);
            assertThat(indexCount(statement, "audit_log", "idx_audit_log_occurred_id")).isEqualTo(1);
            assertThat(indexCount(statement, "approval_task", "idx_approval_task_status_created")).isEqualTo(1);
            assertThat(columnCount(statement, "consumed_message", "message_key")).isEqualTo(1);
            // V11：映射与配置登记契约版本和契约文件 SHA-256（路线 B §3.3）。
            assertThat(columnCount(statement, "sensor_config", "feature_contract_sha256")).isEqualTo(1);
            assertThat(columnCount(statement, "source_mapping", "feature_contract_version")).isEqualTo(1);
            assertThat(columnCount(statement, "source_mapping", "feature_contract_sha256")).isEqualTo(1);
            assertThatThrownBy(() -> statement.executeUpdate("INSERT INTO " + EMPTY_SCHEMA
                    + ".source_mapping (data_source_id, mapping_version, source_schema_json, mapping_json,"
                    + " feature_contract_version, feature_contract_sha256, status) VALUES (1, 'ck', '{}', '{}',"
                    + " 'unsw-nb15-flow-v4', '" + "A".repeat(64) + "', 'draft')"))
                    .isInstanceOf(java.sql.SQLException.class)
                    // 断言约束名，避免外键失败（空 schema 无 data_source）掩盖 CHECK 未生效。
                    .hasMessageContaining("ck_source_mapping_contract_sha256");
            // V12：推理结果快照列与状态不变量（路线 B §10.1）。
            for (String column : List.of("contract_sha256", "attack_probability", "binary_label", "decision_threshold",
                    "threshold_policy_version", "reject_reason")) {
                assertThat(columnCount(statement, "inference_request", column)).as(column).isEqualTo(1);
            }
            assertThat(indexCount(statement, "inference_request", "idx_inference_request_time")).isEqualTo(1);
            assertThat(count(statement, "information_schema.columns", "table_schema='" + EMPTY_SCHEMA
                    + "' AND table_name='inference_request' AND column_name='model_version_id' AND is_nullable='YES'"))
                    .isEqualTo(1);
            // succeeded 行缺分数与阈值快照必须被 CHECK 拒绝；断言约束名，避免外键失败掩盖。
            assertThatThrownBy(() -> statement.executeUpdate("INSERT INTO " + EMPTY_SCHEMA
                    + ".inference_request (request_key, ingest_record_id, deployment_mode, status, requested_at)"
                    + " VALUES ('ck', 1, 'local', 'succeeded', UTC_TIMESTAMP(3))"))
                    .isInstanceOf(java.sql.SQLException.class)
                    .hasMessageContaining("ck_inference_request_result_snapshot");
            // V13：版本化检测策略（每类恰一个 active 默认版本）与告警追溯约束（路线 B §11）。
            assertThat(count(statement, EMPTY_SCHEMA + ".detection_policy", "status='active'")).isEqualTo(3);
            for (String column : List.of("model_version_id", "contract_version", "contract_sha256", "detection_rule_id",
                    "severity_policy_version", "basis_json")) {
                assertThat(columnCount(statement, "detection_alert", column)).as(column).isEqualTo(1);
            }
            assertThat(columnCount(statement, "security_event", "correlation_key")).isEqualTo(1);
            assertThat(columnCount(statement, "security_event", "risk_basis_json")).isEqualTo(1);
            assertThat(columnCount(statement, "detection_rule", "requested_by")).isEqualTo(1);
            assertThatThrownBy(() -> statement.executeUpdate("INSERT INTO " + EMPTY_SCHEMA
                    + ".detection_policy (policy_type, version, config_json, status)"
                    + " VALUES ('correlation', 'second-active', '{}', 'active')"))
                    .isInstanceOf(java.sql.SQLException.class)
                    .hasMessageContaining("uk_detection_policy_active");
            // 模型告警缺推理请求与模型版本必须被 CHECK 拒绝；断言约束名，避免外键失败掩盖。
            assertThatThrownBy(() -> statement.executeUpdate("INSERT INTO " + EMPTY_SCHEMA
                    + ".detection_alert (alert_key, ingest_record_id, alert_type, severity, status, detected_at)"
                    + " VALUES ('ck', 1, 'model', 'high', 'new', UTC_TIMESTAMP(3))"))
                    .isInstanceOf(java.sql.SQLException.class)
                    .hasMessageContaining("ck_detection_alert_model_trace");
            // V14：映射登记人列与“申请人≠批准人”约束。
            assertThat(columnCount(statement, "source_mapping", "requested_by")).isEqualTo(1);
            assertThat(count(statement, "information_schema.check_constraints", "constraint_schema='" + EMPTY_SCHEMA
                    + "' AND constraint_name='ck_source_mapping_separation'")).isEqualTo(1);
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

    private static int indexCount(Statement statement, String table, String index) throws Exception {
        String sql = "SELECT COUNT(DISTINCT index_name) FROM information_schema.statistics WHERE table_schema='" + EMPTY_SCHEMA
                + "' AND table_name='" + table + "' AND index_name='" + index + "'";
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
