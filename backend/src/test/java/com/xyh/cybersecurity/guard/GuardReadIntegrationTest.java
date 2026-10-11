package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.database.IsolatedDatabaseSchemas;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** 随机 MySQL schema + 完整安全链验证只读查询；不连接 broker、回放、模型或防火墙。 */
@SpringBootTest(properties = {"cyber.ingest.consumer.enabled=false", "cyber.ingest.outbox-relay.enabled=false",
        "cyber.drift.enabled=false", "cyber.guard.automation-enabled=false", "cyber.security.local-admin-bootstrap.enabled=false",
        "spring.rabbitmq.listener.simple.auto-startup=false", "spring.rabbitmq.listener.direct.auto-startup=false",
        "spring.datasource.hikari.maximum-pool-size=3"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@ExtendWith(IsolatedDatabaseSchemas.class)
class GuardReadIntegrationTest {
    private static final String SCHEMA = IsolatedDatabaseSchemas.name(GuardReadIntegrationTest.class, "b5query");
    private static final LocalDateTime TIME = LocalDateTime.parse("2026-01-01T00:00:00");
    private static final String FIXTURE_LOGIN = "isolated-b5-query-fixture";
    private static final String HASH = new BCryptPasswordEncoder(4).encode(FIXTURE_LOGIN);
    private final Map<Long, Cookie> sessions = new HashMap<>();
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> System.getenv("DB_TEST_BASE_URL").replaceFirst("/+$", "")
                + "/" + SCHEMA + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("cyber.security.login-throttle.hmac-key", () -> "isolated-b5-query-test-only-key-32-characters");
    }

    record Resource(long pk, String id) { }
    Resource a, b, sa, sb, ea, eb, ca, cb, aa, ab, scopeA, scopeB, ha, hb;
    IdentityPrincipal reader, ordinary, other, both;

    @BeforeEach
    void seed() {
        a = asset(); b = asset();
        sa = sensor(a); sb = sensor(b);
        ca = config(sa); cb = config(sb);
        ea = executor(a); eb = executor(b);
        aa = authorization(a); ab = authorization(b);
        scopeA = scope(a, sa); scopeB = scope(b, sb);
        ha = health(a, sa, scopeA, "COUNTER_UNKNOWN"); hb = health(b, sb, scopeB, "healthy");
        reader = identity(List.of("resource.read", "audit.read", "ops.read", "ops.status.read"), "asset", Long.toString(a.pk));
        ordinary = identity(List.of("resource.read"), "asset", Long.toString(a.pk));
        other = identity(List.of("resource.read", "audit.read", "ops.read"), "asset", Long.toString(b.pk));
        both = identity(List.of("resource.read", "audit.read", "ops.read"), "asset", Long.toString(a.pk));
        grantExistingRole(both, "asset", Long.toString(b.pk));
    }

    @Test
    void allNewCollectionsRequireDedicatedPermissionsAndHumanSession() throws Exception {
        for (String route : List.of("authorizations", "sensor-configs", "audit", "health-windows", "sensor-heartbeats", "executor-heartbeats", "ops/status",
                "authorizations/" + aa.id, "sensor-configs/" + ca.id, "health-windows/" + ha.id, "sensor-heartbeats/" + sa.id, "executor-heartbeats/" + ea.id)) {
            var response = mvc.perform(get("/api/v2/" + route)).andReturn().getResponse();
            assertThat(response.getStatus()).isEqualTo(401);
            assertThat(parse(response.getContentAsString()).path("requestId").asText()).isNotBlank().isNotEqualTo("unknown")
                    .isEqualTo(response.getHeader("X-Request-Id"));
            assertThat(response.getContentAsString()).doesNotContain("sentinel-private");
        }
        for (String route : List.of("audit", "health-windows", "sensor-heartbeats", "executor-heartbeats", "ops/status",
                "health-windows/" + ha.id, "sensor-heartbeats/" + sa.id, "executor-heartbeats/" + ea.id)) {
            error(ordinary, route, 403, "SCOPE_DENIED");
        }
        IdentityPrincipal none = identity(List.of(), "asset", Long.toString(a.pk));
        error(none, "authorizations", 403, "SCOPE_DENIED");
        error(none, "authorizations/" + aa.id, 403, "SCOPE_DENIED");
        error(none, "sensor-configs", 403, "SCOPE_DENIED");
        error(none, "sensor-configs/" + ca.id, 403, "SCOPE_DENIED");
    }

    @Test
    void listsDetailsAndReferenceFiltersHaveTheSameAssetBoundary() throws Exception {
        Map<String, Resource[]> paths = Map.of("authorizations", new Resource[]{aa, ab}, "sensor-configs", new Resource[]{ca, cb},
                "health-windows", new Resource[]{ha, hb}, "sensor-heartbeats", new Resource[]{sa, sb}, "executor-heartbeats", new Resource[]{ea, eb});
        for (var path : paths.entrySet()) {
            JsonNode page = data(reader, path.getKey(), "limit", "1");
            assertThat(page.path("items")).hasSize(1);
            assertThat(page.at("/items/0/id").asText()).isEqualTo(path.getValue()[0].id);
            assertThat(page.path("nextCursor").isNull()).isTrue();
            assertThat(data(reader, path.getKey() + "/" + path.getValue()[0].id).path("assetId").asText()).isEqualTo(a.id);
            error(reader, path.getKey() + "/" + path.getValue()[1].id, 404, "RESOURCE_NOT_FOUND");
            error(reader, path.getKey(), 404, "RESOURCE_NOT_FOUND", "assetId", b.id);
        }
        error(reader, "sensor-configs", 404, "RESOURCE_NOT_FOUND", "sensorId", sb.id);
        error(reader, "health-windows", 404, "RESOURCE_NOT_FOUND", "captureScopeId", scopeB.id);
        error(reader, "executor-heartbeats", 404, "RESOURCE_NOT_FOUND", "executorId", eb.id);
        assertThat(data(both, "sensor-configs", "assetId", a.id, "sensorId", sb.id).path("items")).isEmpty();
        assertThat(data(reader, "ops/status").path("items")).hasSize(1);
    }

    @Test
    void queryPermissionsCannotBeCombinedWithAnUnrelatedRoleScope() throws Exception {
        addRole(reader, List.of("action.read"), "asset", Long.toString(b.pk));
        error(reader, "sensor-configs/" + cb.id, 404, "RESOURCE_NOT_FOUND");
        error(reader, "ops/status", 404, "RESOURCE_NOT_FOUND", "assetId", b.id);
        jdbc.update("UPDATE sys_user SET status='disabled' WHERE id=?", reader.id());
        error(reader, "authorizations/" + aa.id, 403, "SCOPE_DENIED");
    }

    @Test
    void equalTimestampsAndAppendsUseStableKeysetPages() throws Exception {
        Resource second = authorization(a), third = authorization(a);
        var first = data(reader, "authorizations", "limit", "1", "assetId", a.id);
        assertThat(first.at("/items/0/id").asText()).isEqualTo(third.id);
        String cursor = first.path("nextCursor").asText();
        Resource appended = CompletableFuture.supplyAsync(() -> authorization(a)).join();
        var next = data(reader, "authorizations", "limit", "2", "assetId", a.id, "cursor", cursor);
        assertThat(next.path("items").findValuesAsText("id")).containsExactly(second.id, aa.id).doesNotContain(appended.id);
        assertThat(next.path("nextCursor").isNull()).isTrue();
        assertThat(next).isEqualTo(data(reader, "authorizations", "limit", "2", "assetId", a.id, "cursor", cursor));
        assertThat(data(reader, "authorizations", "limit", "1", "assetId", a.id).at("/items/0/id").asText()).isEqualTo(appended.id);
    }

    @Test
    void cursorRejectsCrossAssetCrossActorCrossCollectionAndTampering() throws Exception {
        authorization(a);
        String cursor = data(both, "authorizations", "limit", "1", "assetId", a.id).path("nextCursor").asText();
        error(both, "authorizations", 400, "INVALID_CURSOR", "assetId", b.id, "cursor", cursor);
        error(reader, "authorizations", 400, "INVALID_CURSOR", "assetId", a.id, "cursor", cursor);
        error(both, "sensor-configs", 400, "INVALID_CURSOR", "assetId", a.id, "cursor", cursor);
        error(both, "authorizations", 400, "INVALID_CURSOR", "assetId", a.id, "cursor", "x" + cursor);
        error(both, "authorizations", 400, "INVALID_CURSOR", "cursor", aa.id);
        String unfiltered = data(both, "authorizations", "limit", "1").path("nextCursor").asText();
        jdbc.update("DELETE FROM sys_user_role WHERE user_id=? AND scope_id=?", both.id(), Long.toString(a.pk));
        error(both, "authorizations", 404, "RESOURCE_NOT_FOUND", "cursor", unfiltered);
    }

    record Paging(String path, String[] scoped, String[] empty) { }

    /** 每个列表：空集、恰好满页、最后一页无游标、游标篡改/截断/换筛选/换主体、跨资产与脱敏。 */
    @Test
    void everyListHandlesEmptyAndLastPagesAndRejectsTamperedCursors() throws Exception {
        String action = "fixture." + id();
        audit(action, id(), aa.id, a.pk);
        audit(action, id(), ca.id, a.pk);
        authorization(a); config(sa); health(a, sa, scopeA, "CAPTURE_GAP"); sensor(a); executor(a);
        Resource empty = asset();
        grantExistingRole(reader, "asset", Long.toString(empty.pk));
        List<Paging> routes = new ArrayList<>();
        for (String route : List.of("authorizations", "sensor-configs", "health-windows", "sensor-heartbeats", "executor-heartbeats")) {
            routes.add(new Paging(route, new String[]{"assetId", a.id}, new String[]{"assetId", empty.id}));
        }
        routes.add(new Paging("audit", new String[]{"action", action}, new String[]{"action", action, "assetId", empty.id}));
        for (Paging p : routes) {
            JsonNode none = data(reader, p.path(), p.empty());
            assertThat(none.path("items")).withFailMessage(p.path()).isEmpty();
            assertThat(none.path("nextCursor").isNull()).isTrue();
            assertThat(none.path("asOf").isTextual()).isTrue();

            JsonNode first = data(reader, p.path(), params(p.scoped(), "limit", "1"));
            assertThat(first.path("items")).withFailMessage(p.path()).hasSize(1);
            String cursor = first.path("nextCursor").asText();
            assertThat(cursor).isNotBlank().matches("[A-Za-z0-9_-]+");
            JsonNode last = data(reader, p.path(), params(p.scoped(), "limit", "1", "cursor", cursor));
            assertThat(last.path("items")).withFailMessage(p.path()).hasSize(1);
            assertThat(last.path("nextCursor").isNull()).isTrue();
            assertThat(last.path("asOf")).isEqualTo(first.path("asOf"));
            assertThat(last.at("/items/0/id").asText()).isNotEqualTo(first.at("/items/0/id").asText());
            JsonNode whole = data(reader, p.path(), params(p.scoped(), "limit", "2"));
            assertThat(whole.path("items")).withFailMessage(p.path()).hasSize(2);
            assertThat(whole.path("nextCursor").isNull()).isTrue();
            for (JsonNode page : List.of(first, last, whole)) {
                assertThat(page.toString()).doesNotContain("sentinel-private", "198.51.100.7", "203.0.113.9", "internal_id", "internalId");
            }

            String flipped = cursor.substring(0, 20) + (cursor.charAt(20) == 'A' ? 'B' : 'A') + cursor.substring(21);
            error(reader, p.path(), 400, "INVALID_CURSOR", params(p.scoped(), "cursor", flipped));
            error(reader, p.path(), 400, "INVALID_CURSOR", params(p.scoped(), "cursor", cursor.substring(0, cursor.length() - 4)));
            error(reader, p.path(), 400, "INVALID_CURSOR", params(p.scoped(), "cursor", cursor + "A"));
            error(reader, p.path(), 400, "INVALID_CURSOR", params(p.scoped(), "cursor", "not+base64/="));
            error(reader, p.path(), 400, "INVALID_CURSOR", params(p.empty(), "cursor", cursor));
            error(other, p.path(), 400, "INVALID_CURSOR", "cursor", cursor);

            if (p.path().equals("audit")) assertThat(data(other, p.path(), p.scoped()).path("items")).isEmpty();
            else error(other, p.path(), 404, "RESOURCE_NOT_FOUND", p.scoped());
        }
        error(reader, "audit", 404, "RESOURCE_NOT_FOUND", "assetId", b.id);
        error(reader, "audit", 400, "INVALID_UUID", "assetId", "not-a-uuid");
        error(reader, "audit", 400, "INVALID_QUERY", "requestId", "bad request id");
    }

    /** 健康窗口与心跳都给出 unknown/stale/unhealthy/healthy 四态；未知与过期都不能显示为 healthy。 */
    @Test
    void healthStatesSeparateUnknownStaleUnhealthyAndHealthy() throws Exception {
        assertThat(data(reader, "health-windows/" + ha.id).path("healthState").asText()).isEqualTo("unknown");
        assertThat(data(other, "health-windows/" + hb.id).path("healthState").asText()).isEqualTo("stale");
        Resource gap = health(a, sa, scopeA, "CAPTURE_GAP");
        assertThat(data(reader, "health-windows/" + gap.id).path("healthState").asText()).isEqualTo("unhealthy");
        Resource current = freshHealth(a, sa, scopeA, "healthy");
        var healthy = data(reader, "health-windows/" + current.id);
        assertThat(healthy.path("healthState").asText()).isEqualTo("healthy");
        assertThat(healthy.path("healthBasis").asText()).isEqualTo("server_verified_window");
        assertThat(healthy.path("serverVerifiedHealthy").asBoolean()).isTrue();
        Resource freshUnknown = freshHealth(a, sa, scopeA, "COUNTER_UNKNOWN");
        var unknown = data(reader, "health-windows/" + freshUnknown.id);
        assertThat(unknown.path("freshness").asText()).isEqualTo("fresh");
        assertThat(unknown.path("healthState").asText()).isEqualTo("unknown");
        assertThat(data(reader, "health-windows", "assetId", a.id, "limit", "200").path("items").findValuesAsText("healthState"))
                .containsExactlyInAnyOrder("unknown", "unhealthy", "healthy", "unknown");

        assertThat(sensorState()).isEqualTo("unknown");
        jdbc.update("UPDATE sensor_agent SET last_heartbeat_at=? WHERE id=?", TIME, sa.pk);
        assertThat(sensorState()).isEqualTo("stale");
        jdbc.update("UPDATE sensor_agent SET last_heartbeat_at=UTC_TIMESTAMP(3) WHERE id=?", sa.pk);
        assertThat(sensorState()).isEqualTo("healthy");
        jdbc.update("UPDATE sensor_agent SET status='offline' WHERE id=?", sa.pk);
        assertThat(sensorState()).isEqualTo("unhealthy");
        jdbc.update("UPDATE sensor_agent SET status='active',last_heartbeat_at=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 DAY) WHERE id=?", sa.pk);
        assertThat(sensorState()).isEqualTo("unknown");
        var sensor = data(reader, "sensor-heartbeats/" + sa.id);
        assertThat(sensor.path("healthBasis").asText()).isEqualTo("heartbeat_and_status");
        assertThat(sensor.toString()).doesNotContain("sentinel-private", "credential");

        assertThat(executorState()).isEqualTo("stale");
        jdbc.update("UPDATE guard_executor SET last_heartbeat=UTC_TIMESTAMP(6) WHERE id=?", ea.pk);
        assertThat(executorState()).isEqualTo("unknown");
        jdbc.update("UPDATE guard_executor SET status='active' WHERE id=?", ea.pk);
        assertThat(executorState()).isEqualTo("healthy");
        jdbc.update("UPDATE guard_executor SET status='suspended' WHERE id=?", ea.pk);
        assertThat(executorState()).isEqualTo("unhealthy");
        jdbc.update("UPDATE guard_executor SET status='active',last_heartbeat=NULL WHERE id=?", ea.pk);
        assertThat(executorState()).isEqualTo("unknown");
        assertThat(data(reader, "executor-heartbeats", "assetId", a.id).at("/items/0/healthState").asText()).isEqualTo("unknown");
    }

    private String sensorState() throws Exception {
        return data(reader, "sensor-heartbeats/" + sa.id).path("healthState").asText();
    }

    private String executorState() throws Exception {
        return data(reader, "executor-heartbeats/" + ea.id).path("healthState").asText();
    }

    private static String[] params(String[] base, String... extra) {
        String[] result = Arrays.copyOf(base, base.length + extra.length);
        System.arraycopy(extra, 0, result, base.length, extra.length);
        return result;
    }

    @Test
    void timeFiltersAreHalfOpenAndInvalidParametersFailExplicitly() throws Exception {
        assertThat(data(reader, "authorizations", "from", "2026-01-01T00:00:00Z", "until", "2026-01-01T00:00:00.001Z").path("items")).hasSize(1);
        assertThat(data(reader, "authorizations", "until", "2026-01-01T00:00:00Z").path("items")).isEmpty();
        assertThat(data(reader, "authorizations", "status", "revoked").path("items")).isEmpty();
        for (String limit : List.of("0", "201", "-1", "NaN")) error(reader, "authorizations", 400, "INVALID_PAGE_SIZE", "limit", limit);
        error(reader, "authorizations", 400, "INVALID_QUERY", "limit", "1", "limit", "2");
        error(reader, "authorizations", 400, "INVALID_QUERY", "status", "bogus");
        error(reader, "sensor-configs", 400, "INVALID_QUERY", "unknown", "x");
        error(reader, "authorizations", 400, "INVALID_UUID", "assetId", "1");
        error(reader, "authorizations", 400, "INVALID_TIME_RANGE", "from", "2026-01-02T00:00:00Z", "until", "2026-01-01T00:00:00Z");
        assertThat(data(reader, "authorizations", "limit", "200").path("items")).hasSize(1);
    }

    @Test
    void authorizationValidityAndConfigurationFieldsAreReadWithoutSecrets() throws Exception {
        var authorization = data(reader, "authorizations/" + aa.id);
        assertThat(authorization.path("status").asText()).isEqualTo("active");
        assertThat(authorization.path("validity").asText()).isEqualTo("expired");
        assertThat(authorization.path("revision").asLong()).isEqualTo(1);
        assertThat(authorization.at("/scope/executionScopes/0/servicePort").asInt()).isEqualTo(443);
        assertThat(authorization.toString()).doesNotContain("sentinel-private", "evidenceRef", "stableTargetToken", "approvedBy", "authorizationRef",
                "198.51.100.7", "203.0.113.9", "peerAddress", "observedAddresses");
        assertThat(data(reader, "authorizations").toString()).doesNotContain("sentinel-private", "198.51.100.7", "203.0.113.9");
        var config = data(reader, "sensor-configs/" + ca.id);
        assertThat(config.at("/definition/limits/maxBatchSize").asInt()).isEqualTo(100);
        assertThat(config.at("/definition/interfaceIds/0").asText()).isEqualTo("fixture0");
        assertThat(config.toString()).doesNotContain("sentinel-private", "filterPolicy", "privateKey", "credential");
        jdbc.update("UPDATE sensor_config SET guard_definition_json=NULL WHERE id=?", ca.pk);
        assertThat(data(reader, "sensor-configs/" + ca.id).path("definition").isNull()).isTrue();
    }

    @Test
    void auditRequiresEveryScopeAndRetainsTheLegacyGlobalAdminException() throws Exception {
        String action = "fixture." + id();
        String request = id();
        long visible = audit(action, request, aa.id, a.pk);
        long multi = audit(action, request, ca.id, a.pk, b.pk);
        long noScope = audit(action, request, "sentinel-private");
        long withSource = audit(action, request, sa.id, a.pk);
        jdbc.update("INSERT INTO audit_resource_scope(audit_id,scope_type,scope_id) VALUES (?,'data_source','fixture-source')", withSource);
        var page = data(reader, "audit", "action", action, "requestId", request);
        assertThat(page.path("items")).hasSize(1);
        assertThat(page.at("/items/0/resourceId").asText()).isEqualTo(aa.id);
        assertThat(data(both, "audit", "action", action).path("items")).hasSize(2);
        addRole(reader, List.of("audit.read"), "data_source", "fixture-source");
        assertThat(data(reader, "audit", "action", action).path("items")).hasSize(2);
        IdentityPrincipal global = identity(List.of("audit.read"), "global", "*");
        assertThat(data(global, "audit", "action", action).path("items")).isEmpty();
        IdentityPrincipal admin = identity(List.of(), "global", "*");
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key='platform_admin'", admin.id());
        var all = data(admin, "audit", "action", action);
        assertThat(all.path("items")).hasSize(4);
        assertThat(all.toString()).doesNotContain("sentinel-private", "reason", "metadata", "actorId");
        assertThat(data(admin, "audit", "action", action, "assetId", a.id).path("items")).hasSize(3);
        assertThat(visible).isPositive(); assertThat(multi).isPositive(); assertThat(noScope).isPositive();
    }

    @Test
    void auditPagesHandleTiesBackdatedAppendsAndNullRequestIds() throws Exception {
        String action = "fixture." + id();
        audit(action, null, aa.id, a.pk); audit(action, null, ca.id, a.pk); audit(action, null, sa.id, a.pk);
        var first = data(reader, "audit", "action", action, "limit", "1");
        assertThat(first.at("/items/0/requestId").isNull()).isTrue();
        assertThat(first.at("/items/0/resourceId").asText()).isEqualTo(sa.id);
        String cursor = first.path("nextCursor").asText();
        long appended = audit(action, null, ea.id, a.pk);
        jdbc.update("UPDATE audit_log SET occurred_at=? WHERE id=?", TIME.minusDays(1), appended);
        var next = data(reader, "audit", "action", action, "cursor", cursor, "limit", "200");
        assertThat(next.path("items").findValuesAsText("resourceId")).containsExactly(ca.id, aa.id);
        assertThat(next).isEqualTo(data(reader, "audit", "action", action, "cursor", cursor, "limit", "200"));
    }

    @Test
    void healthAndLatestHeartbeatsSeparateUnknownStaleAndVerified() throws Exception {
        var h = data(reader, "health-windows/" + ha.id);
        assertThat(h.path("verificationStatus").asText()).isEqualTo("COUNTER_UNKNOWN");
        assertThat(h.path("serverVerifiedHealthy").asBoolean()).isFalse();
        assertThat(h.path("failureReason").asText()).isEqualTo("COUNTER_UNKNOWN");
        assertThat(h.path("freshness").asText()).isEqualTo("stale");
        assertThat(h.at("/counterEnd/kernelDrops").isNull()).isTrue();
        assertThat(h.toString()).doesNotContain("sentinel-private", "metrics", "payload", "previousSha256");
        assertThat(data(reader, "health-windows", "verificationStatus", "healthy").path("items")).isEmpty();
        var sensor = data(reader, "sensor-heartbeats/" + sa.id);
        assertThat(sensor.path("freshness").asText()).isEqualTo("no_record");
        assertThat(sensor.path("serverVerifiedHealthy").isNull()).isTrue();
        assertThat(sensor.path("lastSequence").isNull()).isTrue();
        assertThat(sensor.path("reportedConfigSha256").isNull()).isTrue();
        assertThat(sensor.at("/currentConfig/id").asText()).isEqualTo(ca.id);
        jdbc.update("UPDATE sensor_agent SET last_heartbeat_at=UTC_TIMESTAMP(3),guard_boot_id=? WHERE id=?", id(), sa.pk);
        assertThat(data(reader, "sensor-heartbeats/" + sa.id).path("freshness").asText()).isEqualTo("fresh");
        jdbc.update("UPDATE sensor_agent SET last_heartbeat_at=DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 DAY) WHERE id=?", sa.pk);
        assertThat(data(reader, "sensor-heartbeats/" + sa.id).path("freshness").asText()).isEqualTo("unknown");
        var executor = data(reader, "executor-heartbeats/" + ea.id);
        assertThat(executor.path("freshness").asText()).isEqualTo("stale");
        assertThat(executor.at("/reported/activeRuleCount").isNull()).isTrue();
        assertThat(executor.path("serverVerifiedHealthy").isNull()).isTrue();
        assertThat(executor.toString()).doesNotContain("sentinel-private", "credential", "apiClient");
        assertThat(data(reader, "sensor-heartbeats").path("items")).hasSize(1);
        assertThat(data(reader, "executor-heartbeats", "from", "2026-01-01T00:00:00Z", "until", "2026-01-01T00:00:00.001Z").path("items")).hasSize(1);
    }

    @Test
    void everyCollectionUsesTheSharedPageAndFilterContract() throws Exception {
        sensor(a); executor(a); config(sa); health(a, sa, scopeA, "CAPTURE_GAP");
        for (String route : List.of("sensor-configs", "sensor-heartbeats", "executor-heartbeats", "health-windows")) {
            var first = data(reader, route, "limit", "1");
            var second = data(reader, route, "limit", "1", "cursor", first.path("nextCursor").asText());
            assertThat(second.path("items")).hasSize(1);
            assertThat(second.at("/items/0/id").asText()).isNotEqualTo(first.at("/items/0/id").asText());
        }
        var ops = data(both, "ops/status", "limit", "1");
        assertThat(data(both, "ops/status", "cursor", ops.path("nextCursor").asText()).path("items")).hasSize(1);
        assertThat(data(reader, "health-windows", "sensorId", sa.id, "captureScopeId", scopeA.id, "verificationStatus", "CAPTURE_GAP").path("items")).hasSize(1);
    }

    @Test
    void opsCountsOnlyPersistedResetsAndQueriesDoNotChangeBusinessFacts() throws Exception {
        String target = id();
        jdbc.update("INSERT INTO guard_budget_target(public_id,asset_id,environment,stable_target_token,resolver_executor_id,scope_digest) VALUES (?,?,'lab',?,?,?)",
                target, a.pk, "a".repeat(64), ea.pk, "b".repeat(64));
        long targetPk = pk("guard_budget_target", target);
        jdbc.update("INSERT INTO guard_target_budget(public_id,budget_target_id,charged_ms,revision,cycle_started_at) VALUES (?,?,12345,7,?)", id(), targetPk, TIME);
        jdbc.update("INSERT INTO guard_budget_event(public_id,budget_target_id,event_kind,old_revision,new_revision,before_json,after_json,proof_json,proof_sha256)"
                + " VALUES (?,?,'reset',5,6,'{}','{}','{}',?)", id(), targetPk, "c".repeat(64));
        login(reader);
        Map<String, List<Map<String, Object>>> before = snapshot();
        for (String route : List.of("authorizations", "sensor-configs", "audit", "health-windows", "sensor-heartbeats", "executor-heartbeats", "ops/status")) {
            data(reader, route); data(reader, route, "assetId", a.id);
        }
        for (var item : Map.of("authorizations", aa, "sensor-configs", ca, "health-windows", ha,
                "sensor-heartbeats", sa, "executor-heartbeats", ea).entrySet()) data(reader, item.getKey() + "/" + item.getValue().id);
        assertThat(snapshot()).isEqualTo(before);
        var ops = data(reader, "ops/status").at("/items/0");
        assertThat(ops.path("id").asText()).isEqualTo(a.id);
        assertThat(ops.path("sensorCount").asLong()).isEqualTo(1);
        assertThat(ops.path("budgetResetCount").asLong()).isEqualTo(1);
        assertThat(ops.path("lastBudgetResetAt").isTextual()).isTrue();
        assertThat(ops.has("healthy")).isFalse();
        assertThat(ops.path("lastSensorHeartbeatAt").isNull()).isTrue();
    }

    @Test
    void emptyAssetsHaveKnownZeroCountsButNoInventedHeartbeatTime() throws Exception {
        Resource empty = asset();
        grantExistingRole(reader, "asset", Long.toString(empty.pk));
        var ops = data(reader, "ops/status", "assetId", empty.id).at("/items/0");
        assertThat(ops.path("sensorCount").asInt()).isZero();
        assertThat(ops.path("budgetResetCount").asInt()).isZero();
        assertThat(ops.path("lastHealthReceivedAt").isNull()).isTrue();
        assertThat(ops.path("lastBudgetResetAt").isNull()).isTrue();
        assertThat(data(reader, "health-windows", "assetId", empty.id).path("items")).isEmpty();
        error(reader, "sensor-heartbeats/" + id(), 404, "RESOURCE_NOT_FOUND");
    }

    @Test
    void existingV2AndV1ReadRoutesRemainAvailable() throws Exception {
        assertThat(data(reader, "assets/" + a.id).path("id").asText()).isEqualTo(a.id);
        assertThat(data(reader, "sensors/" + sa.id).path("id").asText()).isEqualTo(sa.id);
        assertThat(request(reader, "/api/v1/audit").getResponse().getStatus()).isEqualTo(200);
        assertThat(request(reader, "/api/v1/ops/status").getResponse().getStatus()).isEqualTo(200);
    }

    private Resource asset() {
        String id = id();
        jdbc.update("INSERT INTO asset(public_id,asset_key,asset_type,environment,criticality,owner,status,labels_json,created_at) VALUES (?,?,'host','lab','low','fixture','active','{}',?)", id, id, TIME);
        return new Resource(pk("asset", id), id);
    }

    private Resource sensor(Resource asset) {
        String id = id();
        jdbc.update("INSERT INTO sensor_agent(public_id,agent_key,asset_id,platform,agent_version,capabilities_json,credential_ref,status,registered_at,created_at)"
                + " VALUES (?,?,?,'macos','fixture-v1','{}','sentinel-private','active',?,?)", id, id, asset.pk, TIME, TIME);
        return new Resource(pk("sensor_agent", id), id);
    }

    private Resource config(Resource sensor) {
        String id = id();
        JsonNode def = object("contractVersion", CONTRACT, "profileSha256", "a".repeat(64), "captureHealthVersion", HEALTH,
                "interfaceIds", List.of("fixture0", object("credential", "sentinel-private")),
                "limits", object("maxBatchSize", 100, "privateKey", "sentinel-private"), "buildSha256", "b".repeat(64));
        jdbc.update("INSERT INTO sensor_config(public_id,sensor_id,config_version,interface_scope_json,filter_policy_json,flow_window_seconds,feature_contract_version,sampling_policy_json,status,guard_definition_json,content_sha256,created_at)"
                + " VALUES (?,?,?,'[]',?,30,?,'{}','active',?,?,?)", id, sensor.pk, id,
                canonical(object("credential", "sentinel-private")), CONTRACT, canonical(def), "c".repeat(64), TIME);
        return new Resource(pk("sensor_config", id), id);
    }

    private Resource executor(Resource asset) {
        String id = id(), client = id();
        jdbc.update("INSERT INTO api_client(public_id,client_key,client_type,secret_ref,scope_json,status) VALUES (?,?,'executor','sentinel-private','{}','active')", client, client);
        JsonNode health = object("pendingRecovery", true, "activeRuleCount", null, "clockSkewMs", null, "privateKey", "sentinel-private");
        jdbc.update("INSERT INTO guard_executor(public_id,asset_id,api_client_id,platform,adapter_version,health_json,last_heartbeat,created_at) VALUES (?,?,?,'macos','fixture',?,?,?)",
                id, asset.pk, pk("api_client", client), canonical(health), TIME, TIME);
        return new Resource(pk("guard_executor", id), id);
    }

    private Resource authorization(Resource asset) {
        String id = id();
        JsonNode body = object("interfaces", List.of("fixture0"), "observationAllowed", true, "evidenceRef", "sentinel-private",
                "observedAddresses", List.of("203.0.113.9"),
                "executionScopes", List.of(object("scope", "peer_service", "direction", "inbound", "transport", "tcp", "servicePort", 443,
                        "addressFamily", "ipv4", "capabilityId", id(), "stableTargetToken", "sentinel-private", "peerAddress", "198.51.100.7")));
        jdbc.update("INSERT INTO asset_authorization(public_id,asset_id,authorization_ref,scope_json,valid_from,valid_until,status,created_at) VALUES (?,?,'sentinel-private',?,?,?,'active',?)",
                id, asset.pk, canonical(body), TIME.minusDays(1), TIME.plusDays(1), TIME);
        return new Resource(pk("asset_authorization", id), id);
    }

    private Resource scope(Resource asset, Resource sensor) {
        String id = id();
        jdbc.update("INSERT INTO guard_capture_scope(public_id,asset_id,sensor_id,scope_key,address_family,status) VALUES (?,?,?,'fixture0','ipv4','pending')", id, asset.pk, sensor.pk);
        return new Resource(pk("guard_capture_scope", id), id);
    }

    private Resource health(Resource asset, Resource sensor, Resource scope, String status) {
        String id = id();
        JsonNode payload = object("healthVersion", HEALTH, "configSha256", "c".repeat(64), "buildSha256", "b".repeat(64), "captureGap", false,
                "counterEnd", object("packetsSeen", 1, "kernelDrops", null, "capacityDrops", null),
                "metrics", object("credential", "sentinel-private"));
        jdbc.update("INSERT INTO guard_capture_health_window(public_id,sensor_id,asset_id,capture_scope_id,observer_session_id,sequence_no,interval_start,interval_end,content_sha256,payload_json,verification_status,received_at)"
                + " VALUES (?,?,?,?,?,1,?,?,?,?,?,?)", id, sensor.pk, asset.pk, scope.pk, id(), TIME.minusSeconds(5), TIME, "d".repeat(64), canonical(payload), status, TIME);
        return new Resource(pk("guard_capture_health_window", id), id);
    }

    /** 以数据库当前 UTC 时间写入 1 秒窗口，用于区分新鲜 healthy 与新鲜但未知的已存储判定。 */
    private Resource freshHealth(Resource asset, Resource sensor, Resource scope, String status) {
        String id = id();
        JsonNode payload = object("healthVersion", HEALTH, "captureGap", false, "clockSkewMs", 0,
                "counterEnd", object("packetsSeen", 1, "kernelDrops", 0, "capacityDrops", 0));
        jdbc.update("INSERT INTO guard_capture_health_window(public_id,sensor_id,asset_id,capture_scope_id,observer_session_id,sequence_no,interval_start,interval_end,content_sha256,payload_json,verification_status,received_at)"
                + " VALUES (?,?,?,?,?,1,DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 2 SECOND),DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND),?,?,?,UTC_TIMESTAMP(6))",
                id, sensor.pk, asset.pk, scope.pk, id(), "d".repeat(64), canonical(payload), status);
        return new Resource(pk("guard_capture_health_window", id), id);
    }

    private long audit(String action, String requestId, String resource, long... assets) {
        String marker = id();
        jdbc.update("INSERT INTO audit_log(occurred_at,actor_type,actor_id,action,resource_type,resource_id,request_id,outcome,reason,metadata_json) VALUES (?,'human',?,?,'guard',?,?,'success','sentinel-private',?)",
                TIME, marker, action, resource, requestId, canonical(object("privateKey", "sentinel-private")));
        long pk = jdbc.queryForObject("SELECT id FROM audit_log WHERE actor_id=?", Long.class, marker);
        for (long asset : assets) jdbc.update("INSERT INTO audit_resource_scope(audit_id,scope_type,scope_id) VALUES (?,'asset',?)", pk, Long.toString(asset));
        return pk;
    }

    private IdentityPrincipal identity(List<String> permissions, String scopeType, String scopeId) {
        String id = id();
        jdbc.update("INSERT INTO sys_user(user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)", id, id, "查询隔离测试", HASH);
        long pk = jdbc.queryForObject("SELECT id FROM sys_user WHERE user_key=?", Long.class, id);
        var identity = new IdentityPrincipal(pk, id, id, "查询隔离测试", "fixture-no-login", "active", List.of(), permissions);
        addRole(identity, permissions, scopeType, scopeId);
        return identity;
    }

    private void addRole(IdentityPrincipal actor, List<String> permissions, String scopeType, String scopeId) {
        String key = id();
        jdbc.update("INSERT INTO sys_role(role_key,name,status) VALUES (?,?,'active')", key, "查询隔离角色");
        long role = jdbc.queryForObject("SELECT id FROM sys_role WHERE role_key=?", Long.class, key);
        for (String permission : permissions) jdbc.update("INSERT INTO sys_role_permission(role_id,permission_id) SELECT ?,id FROM sys_permission WHERE permission_key=?", role, permission);
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) VALUES (?,?,?,?)", actor.id(), role, scopeType, scopeId);
    }

    private void grantExistingRole(IdentityPrincipal actor, String scopeType, String scopeId) {
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT user_id,role_id,?,? FROM sys_user_role WHERE user_id=? LIMIT 1", scopeType, scopeId, actor.id());
    }

    private long pk(String table, String id) {
        return jdbc.queryForObject("SELECT id FROM " + table + " WHERE public_id=?", Long.class, id);
    }

    private MvcResult request(IdentityPrincipal actor, String path, String... params) throws Exception {
        var request = get(path).cookie(login(actor));
        for (int i = 0; i < params.length; i += 2) request.param(params[i], params[i + 1]);
        var result = mvc.perform(request).andReturn();
        if (result.getResponse().getStatus() >= 500 && result.getResolvedException() != null) throw result.getResolvedException();
        return result;
    }

    /** 使用真实 JDBC 会话，确保权限撤销测试检验旧会话，而非替换安全过滤器。 */
    private Cookie login(IdentityPrincipal actor) throws Exception {
        if (sessions.containsKey(actor.id())) return sessions.get(actor.id());
        var csrf = mvc.perform(get("/api/v1/auth/csrf")).andReturn().getResponse();
        String csrfValue = parse(csrf.getContentAsString()).at("/data/token").asText();
        var response = mvc.perform(post("/api/v1/auth/login").cookie(csrf.getCookie("SESSION"))
                .header("X-CSRF-TOKEN", csrfValue).contentType("application/json")
                .content(canonical(object("username", actor.getUsername(), "password", FIXTURE_LOGIN)))).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(200);
        Cookie cookie = response.getCookie("SESSION");
        assertThat(cookie).isNotNull();
        sessions.put(actor.id(), cookie);
        return cookie;
    }

    private JsonNode data(IdentityPrincipal actor, String path, String... params) throws Exception {
        var result = request(actor, "/api/v2/" + path, params);
        assertThat(result.getResponse().getStatus()).withFailMessage("%s: %s", path, result.getResponse().getContentAsString()).isEqualTo(200);
        var response = parse(result.getResponse().getContentAsString());
        assertThat(response.path("requestId").asText()).isEqualTo(result.getResponse().getHeader("X-Request-Id")).isNotBlank();
        return response.path("data");
    }

    private void error(IdentityPrincipal actor, String path, int status, String code, String... params) throws Exception {
        var response = request(actor, "/api/v2/" + path, params).getResponse();
        assertThat(response.getStatus()).withFailMessage("%s: %s", path, response.getContentAsString()).isEqualTo(status);
        var body = parse(response.getContentAsString());
        assertThat(body.at("/error/code").asText()).isEqualTo(code);
        assertThat(body.path("requestId").asText()).isNotBlank();
    }

    private Map<String, List<Map<String, Object>>> snapshot() {
        Map<String, List<Map<String, Object>>> result = new LinkedHashMap<>();
        for (String table : List.of("asset_authorization", "sensor_config", "sensor_agent", "guard_executor", "guard_capture_health_window",
                "guard_target_budget", "guard_budget_event", "guard_action", "guard_command", "audit_log", "outbox_event")) {
            result.put(table, jdbc.queryForList("SELECT * FROM " + table + " ORDER BY id"));
        }
        return result;
    }
}
