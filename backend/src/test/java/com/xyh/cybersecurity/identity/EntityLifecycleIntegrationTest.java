package com.xyh.cybersecurity.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import jakarta.servlet.http.Cookie;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 开发路线 §4.1 第一批实体的增删改查补齐：用户、资产与授权、数据源映射、传感器、机器客户端。
 * 每类覆盖范围外 404、越权写 403、状态或幂等冲突 409，以及会话撤销与凭据立即失效。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
class EntityLifecycleIntegrationTest {
    private static final String TEST_SCHEMA = "cyber_security_backend_entity_lifecycle_20261001";
    private static final String HASH = new BCryptPasswordEncoder(4).encode("admin");
    private static final String CSRF_HEADER = "X-CSRF-TOKEN";
    private static final String V4 = "unsw-nb15-flow-v4";
    private static final String NEW_SECRET_VALUE = "rotated-passphrase-2026";

    @BeforeAll
    static void migrate() throws Exception {
        String base = System.getenv("DB_TEST_BASE_URL");
        try (var connection = java.sql.DriverManager.getConnection(base, System.getenv("DB_TEST_USERNAME"),
                System.getenv("DB_TEST_PASSWORD")); var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE IF NOT EXISTS " + TEST_SCHEMA + " CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
        }
        Flyway.configure().dataSource(base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA, System.getenv("DB_TEST_USERNAME"),
                System.getenv("DB_TEST_PASSWORD")).locations("classpath:db/migration").baselineOnMigrate(false).load().migrate();
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        String base = System.getenv("DB_TEST_BASE_URL");
        registry.add("spring.datasource.url", () -> base.replaceFirst("/+$", "") + "/" + TEST_SCHEMA);
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("spring.flyway.enabled", () -> false);
        registry.add("cyber.security.login-throttle.hmac-key", () -> "test-only-key-with-at-least-thirty-two-bytes");
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper objectMapper;

    private long assetId;
    private long otherAssetId;
    private long spareAssetId;
    private long sourceId;
    private long authorizationId;

    @BeforeEach
    void seed() {
        for (String table : List.of("SPRING_SESSION", "auth_login_throttle", "audit_resource_scope", "audit_log",
                "outbox_event", "ingest_record", "ingest_batch", "sensor_health_window", "sensor_config",
                "api_client_source_asset_scope", "api_client_scope", "api_client_permission", "api_client", "sensor_agent",
                "source_mapping", "data_source", "asset_authorization", "asset", "sys_user_role", "sys_user")) {
            jdbc.update("DELETE FROM " + table);
        }
        for (String user : List.of("lc-admin", "lc-admin2", "lc-source", "lc-analyst", "lc-outsider")) {
            jdbc.update("INSERT INTO sys_user (user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)",
                    user, user, user, HASH);
        }
        assetId = asset("lc-asset");
        otherAssetId = asset("lc-other");
        spareAssetId = asset("lc-spare");
        jdbc.update("INSERT INTO data_source (source_key,source_type,environment,schema_version,scope_json,status) "
                + "VALUES ('lc-source','sensor','lab','v1','{}','active')");
        sourceId = jdbc.queryForObject("SELECT id FROM data_source WHERE source_key='lc-source'", Long.class);
        bind("lc-admin", "platform_admin", "global", "*");
        bind("lc-admin2", "platform_admin", "global", "*");
        bind("lc-source", "asset_source_admin", "asset", Long.toString(assetId));
        bind("lc-source", "asset_source_admin", "asset", Long.toString(spareAssetId));
        bind("lc-source", "asset_source_admin", "data_source", Long.toString(sourceId));
        bind("lc-analyst", "security_analyst", "asset", Long.toString(assetId));
        bind("lc-outsider", "asset_source_admin", "asset", Long.toString(otherAssetId));
        jdbc.update("INSERT INTO asset_authorization (asset_id,authorization_ref,scope_json,valid_from,valid_until,status,"
                + "requested_by,approved_by) SELECT ?, 'test://lc', '{}', UTC_TIMESTAMP(3) - INTERVAL 1 DAY, "
                + "UTC_TIMESTAMP(3) + INTERVAL 1 DAY, 'active', s.id, a.id FROM sys_user s, sys_user a "
                + "WHERE s.username='lc-source' AND a.username='lc-admin'", assetId);
        authorizationId = jdbc.queryForObject("SELECT id FROM asset_authorization WHERE asset_id=?", Long.class, assetId);
        jdbc.update("INSERT INTO asset_authorization (asset_id,authorization_ref,scope_json,valid_from,valid_until,status,"
                + "approved_by) SELECT ?, 'test://lc-spare', '{}', UTC_TIMESTAMP(3) - INTERVAL 1 DAY, "
                + "UTC_TIMESTAMP(3) + INTERVAL 1 DAY, 'active', id FROM sys_user WHERE username='lc-admin'", spareAssetId);
    }

    @Test
    void userProfileFreezeResetAndSelfPasswordChangeRevokeSessions() throws Exception {
        Cookie admin = login("lc-admin", "admin");
        long source = userId("lc-source");
        long admin2Id = userId("lc-admin2");

        send(admin, put("/api/v1/users/{id}", source), Map.of("displayName", "数据源管理员"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.displayName").value("数据源管理员"));
        Cookie sourceSession = login("lc-source", "admin");
        send(sourceSession, put("/api/v1/users/{id}", admin2Id), Map.of("displayName", "x")).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/v1/users/{id}", 999_999).cookie(admin)).andExpect(status().isNotFound());

        // 冻结：不能冻结本人；冻结他人撤销其会话，冻结期间不能登录，解冻后恢复。
        send(admin, post("/api/v1/users/{id}/status", userId("lc-admin")), Map.of("status", "disabled", "reason", "r"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("USER_STATUS_CONFLICT"));
        Cookie admin2 = login("lc-admin2", "admin");
        send(admin, post("/api/v1/users/{id}/status", admin2Id), Map.of("status", "disabled", "reason", "离岗"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("disabled"));
        mockMvc.perform(get("/api/v1/auth/me").cookie(admin2)).andExpect(status().isUnauthorized());
        loginAttempt("lc-admin2", "admin").andExpect(status().isUnauthorized());
        send(admin, post("/api/v1/users/{id}/status", admin2Id), Map.of("status", "disabled", "reason", "again"))
                .andExpect(status().isConflict());
        send(admin, post("/api/v1/users/{id}/status", admin2Id), Map.of("status", "active", "reason", "返岗"))
                .andExpect(status().isOk());
        login("lc-admin2", "admin");

        // 管理员重置他人口令：撤销会话，旧口令失效；不能用该接口重置本人。
        send(admin, post("/api/v1/users/{id}/password-reset", source), Map.of("newPassword", NEW_SECRET_VALUE, "reason", "遗忘"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/auth/me").cookie(sourceSession)).andExpect(status().isUnauthorized());
        loginAttempt("lc-source", "admin").andExpect(status().isUnauthorized());
        send(admin, post("/api/v1/users/{id}/password-reset", userId("lc-admin")),
                Map.of("newPassword", NEW_SECRET_VALUE, "reason", "self")).andExpect(status().isConflict());
        assertThat(jdbc.queryForObject("SELECT password_changed_at IS NOT NULL FROM sys_user WHERE id=?", Boolean.class, source))
                .isTrue();

        // 自助改密：当前口令错误 400；成功后本人全部会话失效，用新口令登录。
        clearThrottle();
        Cookie self = login("lc-source", NEW_SECRET_VALUE);
        send(self, post("/api/v1/auth/password"), Map.of("currentPassword", "wrong-current-value", "newPassword", "another-passphrase-1"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error.code").value("CURRENT_PASSWORD_INVALID"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE action='auth.password.change' AND outcome='denied'",
                Integer.class)).isEqualTo(1);
        send(self, post("/api/v1/auth/password"), Map.of("currentPassword", NEW_SECRET_VALUE, "newPassword", "another-passphrase-1"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/auth/me").cookie(self)).andExpect(status().isUnauthorized());
        clearThrottle();
        login("lc-source", "another-passphrase-1");
        assertThat(jdbc.queryForList("SELECT action FROM audit_log WHERE outcome='success'", String.class))
                .contains("iam.user.profile.update", "iam.user.disabled", "iam.user.enabled", "iam.user.password.reset",
                        "auth.password.change");
    }

    @Test
    void assetStatusTransitionsAndAuthorizationRevocationFailClosed() throws Exception {
        Cookie source = login("lc-source", "admin");
        String asset = "{\"criticality\":\"medium\",\"owner\":\"blue\",\"status\":\"%s\"}";
        sendRaw(source, put("/api/v1/assets/{id}", spareAssetId), asset.formatted("disabled"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("disabled"));
        sendRaw(source, put("/api/v1/assets/{id}", spareAssetId), asset.formatted("retired")).andExpect(status().isOk());
        sendRaw(source, put("/api/v1/assets/{id}", spareAssetId), asset.formatted("active"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("ASSET_STATUS_CONFLICT"));
        sendRaw(login("lc-outsider", "admin"), put("/api/v1/assets/{id}", assetId), asset.formatted("disabled"))
                .andExpect(status().isNotFound());

        String revoke = "/api/v1/assets/{assetId}/authorizations/{authorizationId}/revoke";
        send(login("lc-outsider", "admin"), post(revoke, assetId, authorizationId), Map.of("reason", "r"))
                .andExpect(status().isNotFound());
        send(login("lc-analyst", "admin"), post(revoke, assetId, authorizationId), Map.of("reason", "r"))
                .andExpect(status().isForbidden());
        send(source, post(revoke, assetId, authorizationId), Map.of("reason", "实验结束"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("revoked"));
        send(source, post(revoke, assetId, authorizationId), Map.of("reason", "again"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("AUTHORIZATION_STATUS_CONFLICT"));
        mockMvc.perform(get("/api/v1/assets/{id}/authorizations", assetId).cookie(source))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data[0].revokedBy").value("lc-source"));
        // 撤销后资产没有有效授权：登记传感器被拒绝（接入同样依赖有效授权）。
        registerSensor(login("lc-admin", "admin"), "lc-after-revoke").andExpect(status().isBadRequest());
    }

    @Test
    void mappingRejectAndRetireRequireSeparationAndLegalStates() throws Exception {
        Cookie source = login("lc-source", "admin");
        Cookie admin = login("lc-admin", "admin");
        Cookie admin2 = login("lc-admin2", "admin");
        long bySource = createMapping(source, "m-1");
        long byAdmin = createMapping(admin, "m-2");
        String base = "/api/v1/data-sources/{id}/mappings/{mappingId}/";

        send(source, post(base + "reject", sourceId, bySource), Map.of("reason", "r")).andExpect(status().isForbidden());
        send(admin, post(base + "reject", sourceId, byAdmin), Map.of("reason", "自审")).andExpect(status().isForbidden());
        send(admin2, post(base + "reject", sourceId, byAdmin), Map.of("reason", "字段缺失"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("rejected"))
                .andExpect(jsonPath("$.data.decisionReason").value("字段缺失"));
        send(admin2, post(base + "reject", sourceId, byAdmin), Map.of("reason", "again"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("MAPPING_STATUS_CONFLICT"));
        send(admin2, post(base + "retire", sourceId, byAdmin), Map.of("reason", "r")).andExpect(status().isConflict());

        mockMvc.perform(post(base + "approve", sourceId, bySource).cookie(admin).header(CSRF_HEADER, csrf(admin)))
                .andExpect(status().isOk());
        send(admin2, post(base + "retire", sourceId, bySource), Map.of("reason", "换版"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("retired"));
        assertThat(jdbc.queryForObject("SELECT retired_by FROM source_mapping WHERE id=?", Long.class, bySource))
                .isEqualTo(userId("lc-admin2"));
        send(login("lc-outsider", "admin"), post(base + "retire", sourceId, bySource), Map.of("reason", "r"))
                .andExpect(status().isForbidden());

        // 数据源停用后仍可查看；退役为终态。
        String update = "{\"environment\":\"lab\",\"schemaVersion\":\"v1\",\"status\":\"%s\"}";
        sendRaw(source, put("/api/v1/data-sources/{id}", sourceId), update.formatted("retired")).andExpect(status().isOk());
        sendRaw(source, put("/api/v1/data-sources/{id}", sourceId), update.formatted("active"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("SOURCE_STATUS_CONFLICT"));
        mockMvc.perform(get("/api/v1/data-sources/{id}", sourceId).cookie(source))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("retired"));
        mockMvc.perform(get("/api/v1/data-sources/{id}", sourceId).cookie(login("lc-outsider", "admin")))
                .andExpect(status().isNotFound());
    }

    @Test
    void sensorConfigApprovalCredentialRotationRevocationAndDecommission() throws Exception {
        Cookie admin = login("lc-admin", "admin");
        Cookie source = login("lc-source", "admin");
        Cookie analyst = login("lc-analyst", "admin");
        JsonNode issued = data(registerSensor(admin, "lc-sensor").andExpect(status().isCreated()).andReturn());
        long sensorId = issued.path("sensorId").asLong();
        String first = issued.path("credential").asText();
        heartbeat(sensorId, first).andExpect(status().isNoContent());

        MvcResult detail = mockMvc.perform(get("/api/v1/sensors/{id}", sensorId).cookie(analyst))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.credential.status").value("active")).andReturn();
        String detailBody = detail.getResponse().getContentAsString();
        assertThat(detailBody).doesNotContain("credentialSha256").doesNotContain("secretRef")
                .doesNotContain(first.substring(first.indexOf('.') + 1));
        mockMvc.perform(get("/api/v1/sensors/{id}", sensorId).cookie(login("lc-outsider", "admin"))).andExpect(status().isNotFound());
        send(analyst, put("/api/v1/sensors/{id}", sensorId), Map.of("platform", "linux")).andExpect(status().isForbidden());
        send(source, put("/api/v1/sensors/{id}", sensorId), Map.of("platform", "macos-14"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.sensor.platform").value("macos-14"));

        long cfg2 = data(draft(source, sensorId, "cfg-2").andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.status").value("pending")).andReturn()).path("id").asLong();
        draft(source, sensorId, "cfg-2").andExpect(status().isConflict());
        String decide = "/api/v1/sensors/{id}/configs/{configId}/decision";
        send(source, post(decide, sensorId, cfg2), Map.of("decision", "approve", "reason", "r")).andExpect(status().isForbidden());
        long cfg3 = data(draft(admin, sensorId, "cfg-3").andReturn()).path("id").asLong();
        send(admin, post(decide, sensorId, cfg3), Map.of("decision", "approve", "reason", "自审")).andExpect(status().isForbidden());
        send(admin, post(decide, sensorId, cfg2), Map.of("decision", "approve", "reason", "复核通过"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("approved"));
        send(admin, post(decide, sensorId, cfg2), Map.of("decision", "reject", "reason", "again")).andExpect(status().isConflict());
        String activate = "/api/v1/sensors/{id}/configs/{configId}/activate";
        mockMvc.perform(post(activate, sensorId, cfg3).cookie(source).header(CSRF_HEADER, csrf(source)))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("CONFIG_STATUS_CONFLICT"));
        mockMvc.perform(post(activate, sensorId, cfg2).cookie(source).header(CSRF_HEADER, csrf(source)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("active"));
        assertThat(jdbc.queryForList("SELECT status FROM sensor_config WHERE sensor_id=? ORDER BY id", String.class, sensorId))
                .containsExactly("retired", "active", "pending");

        // 轮换：旧凭据立即失效，新凭据只返回一次。
        MvcResult rotated = mockMvc.perform(post("/api/v1/sensors/{id}/credentials/rotate", sensorId)
                .cookie(source).header(CSRF_HEADER, csrf(source))).andExpect(status().isOk()).andReturn();
        String second = data(rotated).path("credential").asText();
        assertThat(second).isNotEqualTo(first);
        heartbeat(sensorId, first).andExpect(status().isUnauthorized());
        heartbeat(sensorId, second).andExpect(status().isNoContent());

        send(source, post("/api/v1/sensors/{id}/credentials/revoke", sensorId), Map.of("reason", "设备丢失"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.credential.status").value("revoked"));
        heartbeat(sensorId, second).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/v1/sensors/{id}/credentials/rotate", sensorId).cookie(source).header(CSRF_HEADER, csrf(source)))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("CREDENTIAL_STATUS_CONFLICT"));

        send(source, post("/api/v1/sensors/{id}/decommission", sensorId), Map.of("reason", "实验结束"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.sensor.status").value("revoked"));
        send(source, post("/api/v1/sensors/{id}/decommission", sensorId), Map.of("reason", "again"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("SENSOR_STATUS_CONFLICT"));
        draft(source, sensorId, "cfg-4").andExpect(status().isConflict());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sensor_config WHERE sensor_id=? AND status='active'",
                Integer.class, sensorId)).isZero();
    }

    @Test
    void machineClientListHidesCredentialsAndRevocationIsImmediate() throws Exception {
        Cookie admin = login("lc-admin", "admin");
        long sensorId = data(registerSensor(admin, "lc-sensor-mc").andReturn()).path("sensorId").asLong();
        MvcResult created = sendRaw(admin, post("/api/v1/machine-clients"), "{\"clientKey\":\"lc-connector\","
                + "\"clientType\":\"connector\",\"scopes\":[{\"scopeType\":\"data_source\",\"scopeId\":\"" + sourceId + "\"},"
                + "{\"scopeType\":\"asset\",\"scopeId\":\"" + assetId + "\"}],\"sourceAssetBindings\":[{\"dataSourceId\":"
                + sourceId + ",\"assetId\":" + assetId + "}]}").andExpect(status().isCreated()).andReturn();
        long connectorId = data(created).path("id").asLong();

        MvcResult list = mockMvc.perform(get("/api/v1/machine-clients").cookie(admin)).andExpect(status().isOk()).andReturn();
        String body = list.getResponse().getContentAsString();
        assertThat(body).contains("lc-connector").doesNotContain("credential").doesNotContain("secretRef").doesNotContain("sha256");
        mockMvc.perform(get("/api/v1/machine-clients").cookie(login("lc-source", "admin"))).andExpect(status().isForbidden());

        send(admin, post("/api/v1/machine-clients/{id}/revoke", connectorId), Map.of("reason", "停用连接器"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("revoked"));
        send(admin, post("/api/v1/machine-clients/{id}/revoke", connectorId), Map.of("reason", "again"))
                .andExpect(status().isConflict());
        long sensorClient = jdbc.queryForObject("SELECT id FROM api_client WHERE sensor_id=?", Long.class, sensorId);
        send(admin, post("/api/v1/machine-clients/{id}/revoke", sensorClient), Map.of("reason", "r"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error.code").value("CLIENT_TYPE_CONFLICT"));
        send(admin, post("/api/v1/machine-clients/{id}/revoke", 999_999), Map.of("reason", "r")).andExpect(status().isNotFound());
    }

    @Test
    void oversizedUtf8PasswordIsClientErrorAndKeepsExistingCredential() throws Exception {
        Cookie admin = login("lc-admin", "admin");
        long target = userId("lc-source");
        String original = jdbc.queryForObject("SELECT password_hash FROM sys_user WHERE id=?", String.class, target);
        send(admin, post("/api/v1/users/{id}/password-reset", target),
                Map.of("newPassword", "密".repeat(25), "reason", "长度校验"))
                .andExpect(status().isBadRequest());
        assertThat(jdbc.queryForObject("SELECT password_hash FROM sys_user WHERE id=?", String.class, target))
                .isEqualTo(original);
    }

    @Test
    void concurrentAdministratorsCannotFreezeEachOtherAndLeaveNoActiveAdmin() throws Exception {
        Cookie first = login("lc-admin", "admin");
        Cookie second = login("lc-admin2", "admin");
        String csrfFirst = csrf(first), csrfSecond = csrf(second);
        long firstId = userId("lc-admin"), secondId = userId("lc-admin2");
        var ready = new java.util.concurrent.CountDownLatch(2);
        var start = new java.util.concurrent.CountDownLatch(1);
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var a = executor.submit(() -> {
                ready.countDown(); start.await();
                return mockMvc.perform(post("/api/v1/users/{id}/status", secondId).cookie(first)
                        .header(CSRF_HEADER, csrfFirst).contentType(APPLICATION_JSON)
                        .content("{\"status\":\"disabled\",\"reason\":\"并发验证\"}"))
                        .andReturn().getResponse().getStatus();
            });
            var b = executor.submit(() -> {
                ready.countDown(); start.await();
                return mockMvc.perform(post("/api/v1/users/{id}/status", firstId).cookie(second)
                        .header(CSRF_HEADER, csrfSecond).contentType(APPLICATION_JSON)
                        .content("{\"status\":\"disabled\",\"reason\":\"并发验证\"}"))
                        .andReturn().getResponse().getStatus();
            });
            assertThat(ready.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();
            start.countDown();
            List<Integer> statuses = List.of(a.get(10, java.util.concurrent.TimeUnit.SECONDS),
                    b.get(10, java.util.concurrent.TimeUnit.SECONDS));
            assertThat(statuses).contains(200).allMatch(code -> code == 200 || code == 401 || code == 403 || code == 409);
        }
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sys_user WHERE username IN ('lc-admin','lc-admin2') "
                + "AND status='active'", Integer.class)).isEqualTo(1);
    }

    private ResultActions registerSensor(Cookie admin, String agentKey) throws Exception {
        return sendRaw(admin, post("/api/v1/sensors"), "{\"agentKey\":\"" + agentKey + "\",\"assetId\":" + assetId
                + ",\"dataSourceId\":" + sourceId + ",\"platform\":\"macos\",\"agentVersion\":\"0.1.0\",\"capabilities\":{},"
                + "\"config\":{\"configVersion\":\"cfg-1\",\"interfaceScope\":{},\"filterPolicy\":{},\"flowWindowSeconds\":60,"
                + "\"featureContractVersion\":\"" + V4 + "\",\"samplingPolicy\":{}}}");
    }

    private ResultActions draft(Cookie cookie, long sensorId, String version) throws Exception {
        return sendRaw(cookie, post("/api/v1/sensors/{id}/configs", sensorId), "{\"configVersion\":\"" + version
                + "\",\"interfaceScope\":{\"interfaces\":[\"en0\"]},\"filterPolicy\":{},\"flowWindowSeconds\":60,"
                + "\"featureContractVersion\":\"" + V4 + "\",\"samplingPolicy\":{},\"reason\":\"调整接口范围\"}");
    }

    private ResultActions heartbeat(long sensorId, String credential) throws Exception {
        return mockMvc.perform(post("/api/v1/machine/sensors/{id}/heartbeat", sensorId)
                .header("Authorization", "Machine " + credential).contentType(APPLICATION_JSON)
                .content("{\"observedAt\":\"" + Instant.now() + "\",\"agentVersion\":\"0.1.0\",\"capabilities\":{}}"));
    }

    private long createMapping(Cookie cookie, String version) throws Exception {
        MvcResult result = sendRaw(cookie, post("/api/v1/data-sources/{id}/mappings", sourceId), "{\"mappingVersion\":\""
                + version + "\",\"sourceSchema\":{},\"mapping\":{},\"featureContractVersion\":\"" + V4 + "\"}")
                .andExpect(status().isCreated()).andReturn();
        assertThat(FeatureContractRegistry.fromClasspath().require(V4).fileSha256()).isNotBlank();
        return data(result).path("id").asLong();
    }

    private ResultActions send(Cookie cookie, MockHttpServletRequestBuilder builder, Map<String, ?> body) throws Exception {
        return sendRaw(cookie, builder, objectMapper.writeValueAsString(body));
    }

    private ResultActions sendRaw(Cookie cookie, MockHttpServletRequestBuilder builder, String body) throws Exception {
        return mockMvc.perform(builder.cookie(cookie).header(CSRF_HEADER, csrf(cookie)).contentType(APPLICATION_JSON).content(body));
    }

    private JsonNode data(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data");
    }

    private long asset(String key) {
        jdbc.update("INSERT INTO asset (asset_key,asset_type,environment,criticality,owner,status,labels_json) "
                + "VALUES (?,'host','lab','medium','test','active','{}')", key);
        return jdbc.queryForObject("SELECT id FROM asset WHERE asset_key=?", Long.class, key);
    }

    private void bind(String username, String role, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user_role (user_id,role_id,scope_type,scope_id) SELECT u.id,r.id,?,? "
                + "FROM sys_user u JOIN sys_role r ON r.role_key=? WHERE u.username=?", scopeType, scopeId, role, username);
    }

    private long userId(String username) {
        return jdbc.queryForObject("SELECT id FROM sys_user WHERE username=?", Long.class, username);
    }

    private void clearThrottle() {
        jdbc.update("DELETE FROM auth_login_throttle");
    }

    private ResultActions loginAttempt(String username, String secret) throws Exception {
        MvcResult csrfResult = mockMvc.perform(get("/api/v1/auth/csrf")).andReturn();
        Cookie cookie = csrfResult.getResponse().getCookie("SESSION");
        String token = objectMapper.readTree(csrfResult.getResponse().getContentAsString()).path("data").path("token").asText();
        return mockMvc.perform(post("/api/v1/auth/login").cookie(cookie).header(CSRF_HEADER, token).contentType(APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("username", username, "password", secret))));
    }

    private Cookie login(String username, String secret) throws Exception {
        return loginAttempt(username, secret).andExpect(status().isOk()).andReturn().getResponse().getCookie("SESSION");
    }

    private String csrf(Cookie cookie) throws Exception {
        var result = mockMvc.perform(get("/api/v1/auth/csrf").cookie(cookie)).andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString()).path("data").path("token").asText();
    }
}
