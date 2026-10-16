package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.database.IsolatedDatabaseSchemas;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
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
        "spring.datasource.hikari.maximum-pool-size=3",
        "spring.datasource.hikari.connection-init-sql=SET SESSION sort_buffer_size=262144"})
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

    /** P1R-2：600KB JSON 超过每连接 256KB 排序缓冲；无资产筛选的列表仍须先限定范围，再稳定翻页。 */
    @ParameterizedTest
    @ValueSource(strings = {"authorizations", "sensor-configs", "health-windows", "sensor-heartbeats"})
    void wideReadListsPageInsideScopeWithoutSortingPayloads(String route) throws Exception {
        assertThat(jdbc.queryForObject("SELECT @@SESSION.sort_buffer_size", Integer.class)).isEqualTo(262144);
        String large = canonical(object("padding", "x".repeat(600_000), "privateKey", "sentinel-private"));
        LocalDateTime time = LocalDateTime.parse("2025-03-01T12:00:00");
        var visible = new ArrayList<Resource>();
        for (int i = 0; i < 4; i++) {
            Resource asset = i == 3 ? b : a;
            Resource sensor = i == 3 ? sb : sa;
            Resource scope = i == 3 ? scopeB : scopeA;
            Resource row;
            String table, payload;
            switch (route) {
                case "authorizations" -> { row = authorization(asset); table = "asset_authorization"; payload = "scope_json"; }
                case "sensor-configs" -> { row = config(sensor); table = "sensor_config"; payload = "guard_definition_json"; }
                case "health-windows" -> { row = health(asset, sensor, scope, "COUNTER_UNKNOWN"); table = "guard_capture_health_window"; payload = "payload_json"; }
                default -> { row = sensor(asset); table = "sensor_agent"; payload = null; }
            }
            LocalDateTime created = i == 3 ? time.plusSeconds(1) : time;
            jdbc.update("UPDATE " + table + " SET created_at=? WHERE id=?", created, row.pk);
            if (route.equals("health-windows")) jdbc.update("UPDATE " + table + " SET received_at=? WHERE id=?", created, row.pk);
            if (route.equals("sensor-heartbeats")) jdbc.update("UPDATE " + table + " SET last_heartbeat_at=? WHERE id=?", created, row.pk);
            if (payload != null) jdbc.update("UPDATE " + table + " SET " + payload + "=? WHERE id=?", large, row.pk);
            if (route.equals("sensor-heartbeats")) {
                config(row);
                Resource current = config(row), draft = config(row);
                jdbc.update("UPDATE sensor_config SET guard_definition_json=? WHERE id=?", large, current.pk);
                jdbc.update("UPDATE sensor_config SET status='draft' WHERE id=?", draft.pk);
                assertThat(data(i == 3 ? other : reader, route + "/" + row.id).at("/currentConfig/id").asText()).isEqualTo(current.id);
            }
            if (i < 3) visible.add(row);
        }
        String from = "2025-03-01T00:00:00Z", until = "2025-03-02T00:00:00Z";
        IdentityPrincipal global = identity(List.of("resource.read", "ops.read"), "global", "*");
        assertThat(data(global, route, "from", from, "until", until, "limit", "200").path("items")).hasSize(4);
        var seen = new ArrayList<String>();
        String cursor = null;
        for (int page = 0; page < 3; page++) {
            String[] params = cursor == null ? new String[]{"from", from, "until", until, "limit", "1"}
                    : new String[]{"from", from, "until", until, "limit", "1", "cursor", cursor};
            var result = data(reader, route, params);
            assertThat(result.path("items")).hasSize(1);
            seen.add(result.at("/items/0/id").asText());
            assertThat(result.at("/items/0/assetId").asText()).isEqualTo(a.id);
            assertThat(result.toString()).doesNotContain("sentinel-private", "padding", "privateKey");
            cursor = result.path("nextCursor").isTextual() ? result.path("nextCursor").asText() : null;
            assertThat(cursor == null).isEqualTo(page == 2);
        }
        assertThat(seen).containsExactly(visible.get(2).id, visible.get(1).id, visible.get(0).id);
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
        jdbc.update("UPDATE asset_authorization SET requested_by=? WHERE id=?", reader.id(), aa.pk);
        jdbc.update("UPDATE sensor_config SET requested_by=? WHERE id=?", reader.id(), ca.pk);
        var authorization = data(reader, "authorizations/" + aa.id);
        assertThat(authorization.path("requestedBy").asLong()).isEqualTo(reader.id());
        assertThat(data(reader, "authorizations").at("/items/0/requestedBy").asLong()).isEqualTo(reader.id());
        assertThat(authorization.path("status").asText()).isEqualTo("active");
        assertThat(authorization.path("validity").asText()).isEqualTo("expired");
        assertThat(authorization.path("revision").asLong()).isEqualTo(1);
        assertThat(authorization.at("/scope/executionScopes/0/servicePort").asInt()).isEqualTo(443);
        assertThat(authorization.toString()).doesNotContain("sentinel-private", "evidenceRef", "stableTargetToken", "approvedBy", "authorizationRef",
                "198.51.100.7", "203.0.113.9", "peerAddress", "observedAddresses");
        assertThat(data(reader, "authorizations").toString()).doesNotContain("sentinel-private", "198.51.100.7", "203.0.113.9");
        var config = data(reader, "sensor-configs/" + ca.id);
        assertThat(config.path("requestedBy").asLong()).isEqualTo(reader.id());
        assertThat(data(reader, "sensor-configs").at("/items/0/requestedBy").asLong()).isEqualTo(reader.id());
        assertThat(config.at("/definition/limits/maxBatchSize").asInt()).isEqualTo(100);
        assertThat(config.at("/definition/interfaceIds/0").asText()).isEqualTo("fixture0");
        assertThat(config.toString()).doesNotContain("sentinel-private", "filterPolicy", "privateKey", "credential");
        jdbc.update("UPDATE sensor_config SET guard_definition_json=NULL,requested_by=NULL WHERE id=?", ca.pk);
        assertThat(data(reader, "sensor-configs/" + ca.id).path("definition").isNull()).isTrue();
        assertThat(data(reader, "sensor-configs/" + ca.id).path("requestedBy").isNull()).isTrue();
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
        // T1：全局只读审计覆盖已登记范围，但不能绕过历史无范围记录的保护。
        assertThat(data(global, "audit", "action", action).path("items")).hasSize(3);
        assertThat(data(global, "audit", "action", action, "assetId", a.id).path("items")).hasSize(3);
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
    void v2ReadsRemainAvailableAndLegacyHumanEndpointsStayClosed() throws Exception {
        assertThat(data(reader, "assets/" + a.id).path("id").asText()).isEqualTo(a.id);
        assertThat(data(reader, "sensors/" + sa.id).path("id").asText()).isEqualTo(sa.id);
        assertThat(request(reader, "/api/v1/audit").getResponse().getStatus()).isEqualTo(403);
        // C1 已删除所有 v1 人工入口；持有 audit.read 也不能访问旧接口。
        assertThat(request(reader, "/api/v1/ops/status").getResponse().getStatus()).isEqualTo(403);
    }

    @Test
    void summaryMachineClientsAndAssignableUsersRespectScopeAndRedactSecrets() throws Exception {
        IdentityPrincipal analystA = identity(List.of("resource.read", "detection.read", "event.manage"), "asset", Long.toString(a.pk));
        IdentityPrincipal analystB = identity(List.of("event.manage"), "asset", Long.toString(b.pk));
        IdentityPrincipal sensorAdminA = identity(List.of("sensor.manage", "ops.read"), "asset", Long.toString(a.pk));
        IdentityPrincipal reviewerA = identity(List.of("authorization.approve", "policy.approve", "bundle.approve"), "asset", Long.toString(a.pk));
        String sensorClientA = id();
        jdbc.update("INSERT INTO api_client(public_id,client_key,client_type,sensor_id,secret_ref,credential_sha256,scope_json,status,created_at)"
                + " VALUES (?,?,'sensor',?,'sentinel-private',?,'{}','active',?)",
                sensorClientA, sensorClientA, sa.pk, "a".repeat(64), TIME);
        jdbc.update("INSERT INTO security_event(public_id,guard_asset_id,revision,event_key,title,category,severity,status,risk_score,risk_rule_version,first_seen_at,last_seen_at,created_at)"
                + " VALUES (?,?,1,?,'测试事件','dos_slow','high','open',80,'v5',?,?,?)", id(), a.pk, id(), TIME, TIME, TIME);
        jdbc.update("INSERT INTO security_event(public_id,guard_asset_id,revision,event_key,title,category,severity,status,risk_score,risk_rule_version,first_seen_at,last_seen_at,created_at)"
                + " VALUES (?,?,1,?,'跨资产事件','dos_slow','high','open',80,'v5',?,?,?)", id(), b.pk, id(), TIME, TIME, TIME);

        error(reader, "machine-clients", 403, "SCOPE_DENIED");
        var mcList = data(sensorAdminA, "machine-clients", "assetId", a.id);
        assertThat(mcList.path("items")).hasSize(2);
        assertThat(mcList.toString()).doesNotContain("sentinel-private", "credentialSha256", "secretRef");
        assertThat(data(sensorAdminA, "machine-clients/" + sensorClientA).path("sensorId").asText()).isEqualTo(sa.id);
        error(sensorAdminA, "machine-clients", 404, "RESOURCE_NOT_FOUND", "assetId", b.id);

        error(reader, "assignable-users", 403, "SCOPE_DENIED", "assetId", a.id);
        error(analystA, "assignable-users", 400, "INVALID_QUERY");
        error(analystA, "assignable-users", 404, "RESOURCE_NOT_FOUND", "assetId", b.id);
        var assignees = data(analystA, "assignable-users", "assetId", a.id);
        assertThat(assignees.path("items").findValuesAsText("userKey")).contains(analystA.userKey()).doesNotContain(analystB.userKey(), reader.userKey());
        assertThat(assignees.toString()).doesNotContain("password", "HASH");

        var summaryAnalyst = data(analystA, "summary");
        assertThat(summaryAnalyst.path("openEvents").asLong()).isEqualTo(1L);
        assertThat(summaryAnalyst.has("pendingApprovals")).isFalse();
        assertThat(summaryAnalyst.has("ops")).isFalse();

        var summaryReviewer = data(reviewerA, "summary");
        assertThat(summaryReviewer.path("pendingApprovals").isObject()).isTrue();
        assertThat(summaryReviewer.path("releasePipeline").isObject()).isTrue();
        error(analystA, "summary", 400, "INVALID_QUERY", "assetId", a.id);

        // B2.5：6 个单角色账号逐一断言返回的字段集合，且不包含本人发起的待审对象
        var pAdmin = roleUser("platform_admin");
        var pAnalyst = roleUser("security_analyst");
        var pReviewer = roleUser("security_reviewer");
        var pOperator = roleUser("model_operator");
        var pEvidence = roleUser("evidence_reviewer");
        var pAuditor = roleUser("auditor");

        jdbc.update("INSERT INTO asset_authorization(public_id,asset_id,authorization_ref,scope_json,valid_from,valid_until,status,requested_by,created_at) VALUES (?,?,'ref','{}',?,?, 'pending',?,?)",
                id(), a.pk, TIME.minusDays(1), TIME.plusDays(1), pAdmin.id(), TIME);
        jdbc.update("INSERT INTO asset_authorization(public_id,asset_id,authorization_ref,scope_json,valid_from,valid_until,status,requested_by,created_at) VALUES (?,?,'ref','{}',?,?, 'pending',?,?)",
                id(), a.pk, TIME.minusDays(1), TIME.plusDays(1), pReviewer.id(), TIME);

        assertThat(data(pAdmin, "summary").fieldNames()).toIterable()
                .containsExactlyInAnyOrder("ops", "recentAuditCount24h");
        assertThat(data(pAnalyst, "summary").fieldNames()).toIterable()
                .containsExactlyInAnyOrder("openEvents");
        var revSummary = data(pReviewer, "summary");
        assertThat(revSummary.fieldNames()).toIterable()
                .containsExactlyInAnyOrder("openEvents", "pendingApprovals", "releasePipeline", "ops");
        // pReviewer 自己发起的 pending 授权被排除，只计入 pAdmin 发起的 1 条
        assertThat(revSummary.at("/pendingApprovals/authorizations").asLong()).isEqualTo(1L);
        assertThat(data(pOperator, "summary").fieldNames()).toIterable()
                .containsExactlyInAnyOrder("releasePipeline", "modelsPendingValidation");
        assertThat(data(pEvidence, "summary").fieldNames()).toIterable()
                .containsExactlyInAnyOrder("openEvents", "pendingFeedbackReviews", "releasePipeline");
        assertThat(data(pAuditor, "summary").fieldNames()).toIterable()
                .containsExactlyInAnyOrder("openEvents", "releasePipeline", "ops", "recentAuditCount24h");
    }

    /**
     * B5.2 stats/live：按数据库时钟落桶；有健康窗口覆盖且无事件为 0，无覆盖为 null；拦截只计已核对的首个 applied 回执；
     * 字段按权限裁剪、计数按资产范围统计。
     */
    @Test
    void liveStatsBucketsCoverageAndPermissionTrimming() throws Exception {
        assertThat(mvc.perform(get("/api/v2/stats/live")).andReturn().getResponse().getStatus()).isEqualTo(401);
        var full = identity(List.of("detection.read", "action.read", "ops.read"), "asset", Long.toString(a.pk));
        var opsOnly = identity(List.of("ops.read"), "asset", Long.toString(a.pk));
        error(roleUser("model_operator"), "stats/live", 403, "SCOPE_DENIED");
        error(full, "stats/live", 400, "INVALID_QUERY", "range", "2h");
        error(full, "stats/live", 400, "INVALID_QUERY", "range", "7d", "step", "10");
        error(full, "stats/live", 400, "INVALID_QUERY", "window", "15m");

        LocalDateTime now = jdbc.queryForObject("SELECT UTC_TIMESTAMP(6)", LocalDateTime.class);
        LocalDateTime covered = now.minusMinutes(20), uncoveredWithEvent = now.minusMinutes(40);
        healthAt(a, sa, scopeA, covered);
        healthAt(b, sb, scopeB, now.minusMinutes(30));  // 资产 b 不在范围内，不得提供覆盖
        observationAt(a, sa, scopeA, covered);
        observationAt(a, sa, scopeA, covered.plusSeconds(1));
        observationAt(a, sa, scopeA, uncoveredWithEvent);
        observationAt(b, sb, scopeB, covered);  // 范围外，不计
        decisionAt(a, "alert", "brute_force", covered);
        decisionAt(a, "block_candidate", "exotic_family", covered);
        decisionAt(a, "observe", "port_scan", covered);  // 仅观察，不计为告警
        long command = 900_000L + a.pk;
        receiptAt(a, ea, command, "applied", true, null, covered.plusSeconds(2));
        receiptAt(a, ea, command, "applied", true, null, covered.plusSeconds(4));  // 同一命令只计首次
        receiptAt(a, ea, command + 1, "applied", false, null, covered.plusSeconds(3));  // 未通过实态核对
        receiptAt(a, ea, command + 2, "applied", true, 1L, covered.plusSeconds(3));  // 撤销回执
        jdbc.update("UPDATE sensor_agent SET last_heartbeat_at=UTC_TIMESTAMP(6) WHERE id=?", sa.pk);

        JsonNode live = data(full, "stats/live", "range", "1h");
        assertThat(live.path("range").asText()).isEqualTo("1h");
        assertThat(live.path("step").asInt()).isEqualTo(60);
        assertThat(live.path("points").asInt()).isEqualTo(60);
        Instant from = Instant.parse(live.path("from").asText());
        assertThat(Instant.parse(live.path("to").asText())).isEqualTo(from.plusSeconds(3600)).isAfter(now.toInstant(ZoneOffset.UTC));
        int bCovered = (int) ((covered.toInstant(ZoneOffset.UTC).getEpochSecond() - from.getEpochSecond()) / 60);
        int bEvent = (int) ((uncoveredWithEvent.toInstant(ZoneOffset.UTC).getEpochSecond() - from.getEpochSecond()) / 60);
        int bEmpty = (int) ((now.minusMinutes(50).toInstant(ZoneOffset.UTC).getEpochSecond() - from.getEpochSecond()) / 60);

        JsonNode inbound = live.path("inbound");
        assertThat(inbound).hasSize(60);
        assertThat(inbound.get(bCovered).asLong()).isEqualTo(2L);
        assertThat(inbound.get(bEvent).asLong()).isEqualTo(1L);   // 无覆盖但确有事件，如实计数
        assertThat(inbound.get(bEmpty).isNull()).isTrue();         // 无覆盖无事件：null，不补 0
        int bOtherAsset = (int) ((now.minusMinutes(30).toInstant(ZoneOffset.UTC).getEpochSecond() - from.getEpochSecond()) / 60);
        assertThat(inbound.get(bOtherAsset).isNull()).isTrue();    // 范围外资产的健康窗口不提供覆盖
        assertThat(live.at("/alerts").fieldNames()).toIterable()
                .containsExactly("port_scan", "brute_force", "dos_flood", "dos_slow", "exotic_family");
        assertThat(live.at("/alerts/brute_force").get(bCovered).asLong()).isEqualTo(1L);
        assertThat(live.at("/alerts/exotic_family").get(bCovered).asLong()).isEqualTo(1L);
        assertThat(live.at("/alerts/port_scan").get(bCovered).asLong()).isZero();  // 有覆盖、仅观察判定 → 0
        assertThat(live.at("/alerts/port_scan").get(bEmpty).isNull()).isTrue();
        assertThat(live.path("blocked").get(bCovered).asLong()).isEqualTo(1L);
        assertThat(Instant.parse(live.path("asOf").asText())).isEqualTo(covered.toInstant(ZoneOffset.UTC));
        assertThat(live.at("/devices/sensorsOnline").asLong()).isEqualTo(1L);
        assertThat(live.at("/devices/sensorsTotal").asLong()).isEqualTo(1L);
        assertThat(live.at("/devices/executorsOnline").asLong()).isZero();
        assertThat(live.at("/devices/executorsTotal").asLong()).isEqualTo(1L);
        assertThat(live.path("today").fieldNames()).toIterable().containsExactlyInAnyOrder("inbound", "alerts", "blocked", "openEvents");

        JsonNode ops = data(opsOnly, "stats/live");
        assertThat(ops.path("range").asText()).isEqualTo("15m");
        assertThat(ops.path("points").asInt()).isEqualTo(90);
        assertThat(ops.fieldNames()).toIterable()
                .containsExactlyInAnyOrder("range", "step", "from", "to", "points", "asOf", "devices");
    }

    private void healthAt(Resource asset, Resource sensor, Resource scope, LocalDateTime end) {
        JsonNode payload = object("healthVersion", HEALTH, "captureGap", false, "counterEnd", object("packetsSeen", 1));
        jdbc.update("INSERT INTO guard_capture_health_window(public_id,sensor_id,asset_id,capture_scope_id,observer_session_id,sequence_no,interval_start,interval_end,content_sha256,payload_json,verification_status,received_at)"
                + " VALUES (?,?,?,?,?,1,?,?,?,?,'healthy',?)", id(), sensor.pk, asset.pk, scope.pk, id(), end.minusSeconds(2), end, "d".repeat(64), canonical(payload), end);
    }

    /** 观察、判定与回执的外键链很长；聚合测试在同一连接上临时关闭外键检查，只填写聚合与非空列。 */
    private void unchecked(String sql, Object... args) {
        jdbc.execute((ConnectionCallback<Void>) c -> {
            try (var st = c.createStatement()) { st.execute("SET FOREIGN_KEY_CHECKS=0"); }
            try (var ps = c.prepareStatement(sql)) {
                for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
                ps.executeUpdate();
            } finally {
                try (var st = c.createStatement()) { st.execute("SET FOREIGN_KEY_CHECKS=1"); }
            }
            return null;
        });
    }

    private void observationAt(Resource asset, Resource sensor, Resource scope, LocalDateTime asOf) {
        unchecked("INSERT INTO guard_observation(public_id,batch_id,sensor_id,asset_id,boot_id,capture_scope_id,flow_id,parent_connection_id,snapshot_index,profile,as_of,last_packet_at,peer_key,key_epoch,direction,transport,environment,payload_json,content_sha256)"
                + " VALUES (?,999999,?,?,?,?,?,?,0,'final',?,?,?,1,'inbound','tcp','lab','{}',?)",
                id(), sensor.pk, asset.pk, id(), scope.pk, id(), id(), asOf, asOf, "p".repeat(64), "c".repeat(64));
    }

    private void decisionAt(Resource asset, String decision, String family, LocalDateTime at) {
        unchecked("INSERT INTO guard_decision(public_id,episode_id,asset_id,bundle_id,decision_revision,decision_contract_version,decision,evidence_sha256,evidence_json,decided_at)"
                + " VALUES (?,?,?,999999,1,'fixture',?,?,?,?)",
                id(), 1_000_000L + (long) (Math.random() * 1_000_000_000L), asset.pk, decision, "e".repeat(64), canonical(object("family", family)), at);
    }

    private void receiptAt(Resource asset, Resource executor, long command, String status, boolean projected, Long revocation, LocalDateTime at) {
        unchecked("INSERT INTO guard_action_receipt(public_id,command_id,executor_id,asset_id,revocation_id,status,observed_at,state_digest,content_sha256,payload_json,projected)"
                + " VALUES (?,?,?,?,?,?,?,?,?,'{}',?)",
                id(), command, executor.pk, asset.pk, revocation, status, at, "s".repeat(64), "c".repeat(64), projected);
    }

    private IdentityPrincipal roleUser(String roleKey) {
        String key = id();
        jdbc.update("INSERT INTO sys_user(user_key,username,display_name,status,password_hash) VALUES (?,?,?,'active',?)", key, key, roleKey, HASH);
        long pk = jdbc.queryForObject("SELECT id FROM sys_user WHERE user_key=?", Long.class, key);
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key=?", pk, roleKey);
        return new IdentityPrincipal(pk, key, key, roleKey, "fixture-no-login", "active", List.of(roleKey), List.of());
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
        var csrf = mvc.perform(get("/api/v2/auth/csrf")).andReturn().getResponse();
        String csrfValue = parse(csrf.getContentAsString()).at("/data/token").asText();
        var response = mvc.perform(post("/api/v2/auth/login").header("Idempotency-Key",id()).cookie(csrf.getCookie("SESSION"))
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
