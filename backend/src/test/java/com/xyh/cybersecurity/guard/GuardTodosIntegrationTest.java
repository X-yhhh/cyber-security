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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
class GuardTodosIntegrationTest {
    private static final String SCHEMA = IsolatedDatabaseSchemas.name(GuardTodosIntegrationTest.class, "be22");
    private static final LocalDateTime TIME = LocalDateTime.parse("2026-01-01T00:00:00");
    private static final String FIXTURE_LOGIN = "isolated-b5-query-fixture";
    private static final String HASH = new BCryptPasswordEncoder(4).encode(FIXTURE_LOGIN);
    private final Map<Long, Cookie> sessions = new HashMap<>();
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired GuardTodoMapper workbench;

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

    /** 仅收束本测试自建资产的待批夹具，避免下一用例的全局账号受 100 条上限影响。 */
    @org.junit.jupiter.api.AfterEach
    void retirePendingFixtures() {
        jdbc.update("UPDATE asset_authorization SET status='revoked' WHERE asset_id IN (?,?) AND status='pending'", a.pk, b.pk);
    }

    @Test
    void twelveTodoKindsFollowSixRolesAndExcludeOwnApprovals() throws Exception {
        var admin = roleUser("platform_admin");
        var analyst = roleUser("security_analyst");
        var reviewer = roleUser("security_reviewer");
        var operator = roleUser("model_operator");
        var evidence = roleUser("evidence_reviewer");
        var auditor = roleUser("auditor");
        var fixture = catalog(operator.id());
        var otherFixture = catalog(reviewer.id());
        LocalDateTime now = workbench.now();
        jdbc.update("UPDATE asset_authorization SET valid_from=?,valid_until=? WHERE id=?", now.minusDays(1), now.plusDays(1), aa.pk);
        String auth = pendingAuthorization(a, admin.id());
        String ownAuth = pendingAuthorization(a, reviewer.id());
        jdbc.update("UPDATE sensor_config SET status='draft',requested_by=? WHERE id=?", admin.id(), ca.pk);
        var ownConfig = config(sa);
        jdbc.update("UPDATE sensor_config SET status='pending',requested_by=? WHERE id=?", reviewer.id(), ownConfig.pk);
        Resource observation = observation(a, sa, ca, scopeA, now.minusMinutes(2), "inbound");
        Resource decision = decision(a, sa, fixture.bundle, now.minusMinutes(2), "dos_slow", "alert");
        Resource action = action(a, ea, aa, fixture.bundle, decision, analyst.id(), "manual", "pending");
        Resource ownAction = action(a, ea, aa, fixture.bundle, decision, reviewer.id(), "manual", "pending");
        Resource autoAction = action(a, ea, aa, fixture.bundle, decision, analyst.id(), "auto", "pending");
        String lab = lab(fixture.bundle, operator.id(), true), ownLab = lab(fixture.bundle, reviewer.id(), true);
        String qualificationOnly = lab(fixture.bundle, operator.id(), false);
        String feedback = feedback(observation, analyst.id()), ownFeedback = feedback(observation, evidence.id());
        String event = event(a, "open", null, now), assigned = event(a, "investigating", analyst.id(), now.plusSeconds(1));
        String otherAssigned = event(a, "investigating", reviewer.id(), now.plusSeconds(2));
        String closed = event(a, "closed", null, now.plusSeconds(3));
        jdbc.update("UPDATE guard_release_bundle SET status='evaluated' WHERE id IN (?,?)", fixture.bundle.pk, otherFixture.bundle.pk);
        var activation = catalog(operator.id());
        jdbc.update("UPDATE guard_release_bundle SET status='approved' WHERE id=?", activation.bundle.pk);
        var candidate = catalog(operator.id());

        var adminTodos = data(admin, "todos");
        assertThat(itemKinds(adminTodos)).containsExactlyInAnyOrder("expiring_authorization", "device");
        var analystTodos = data(analyst, "todos");
        assertThat(itemKinds(analystTodos)).containsExactly("event");
        assertThat(todoItems(analystTodos).stream().map(n -> n.path("id").asText()))
                .contains(event, assigned).doesNotContain(otherAssigned, closed);
        var reviewerTodos = data(reviewer, "todos");
        assertThat(itemKinds(reviewerTodos)).containsExactlyInAnyOrder("authorization", "sensor_config", "action", "lab", "policy", "bundle_approval", "device");
        assertThat(todoItems(reviewerTodos).stream().map(n -> n.path("id").asText()))
                .contains(auth, ca.id, action.id, lab, fixture.policy.id, fixture.bundle.id, activation.bundle.id)
                .doesNotContain(ownAuth, ownConfig.id, ownAction.id, autoAction.id, ownLab, qualificationOnly, otherFixture.policy.id, otherFixture.bundle.id);
        assertThat(itemKinds(data(operator, "todos"))).containsExactlyInAnyOrder("model", "bundle_sealing");
        assertThat(todoItems(data(operator, "todos")).stream().map(n -> n.path("id").asText())).contains(candidate.bundle.id);
        assertThat(itemKinds(data(evidence, "todos"))).containsExactly("feedback");
        assertThat(todoItems(data(evidence, "todos")).stream().map(n -> n.path("id").asText())).contains(feedback).doesNotContain(ownFeedback);
        assertThat(itemKinds(data(auditor, "todos"))).containsExactly("device");
        for (var user : List.of(admin, analyst, reviewer, operator, evidence, auditor)) {
            var todos = data(user, "todos");
            assertThat(todos.toString()).doesNotContain("sentinel-private", "requestedBy", "createdBy", "payload", "credential");
            for (var group : todos.path("groups")) {
                List<java.time.Instant> times = new ArrayList<>();
                for (var item : group.path("items")) {
                    times.add(java.time.Instant.parse(item.path("createdAt").asText()));
                    assertThat(item.path("route").asText()).startsWith("/console/");
                }
                assertThat(times).isSortedAccordingTo(java.util.Comparator.reverseOrder());
            }
        }
    }

    @Test
    void todosEnforcePerPermissionAssetScopesAndExactTruncation() throws Exception {
        var creator = identity(List.of(), "global", "*");
        var scoped = identity(List.of("authorization.approve", "event.manage", "ops.read"), "asset", Long.toString(a.pk));
        addRole(scoped, List.of("resource.read", "policy.approve", "bundle.approve", "model.validate", "bundle.request"), "asset", Long.toString(b.pk));
        pendingAuthorization(b, creator.id());
        String foreign = event(b, "open", null, TIME), mine = event(a, "open", scoped.id(), TIME);
        String assignedElsewhere = event(a, "investigating", creator.id(), TIME);
        List<String> auths = new ArrayList<>();
        for (int i = 0; i < 100; i++) auths.add(pendingAuthorization(a, creator.id()));
        var onlyApproval = identity(List.of("authorization.approve"), "asset", Long.toString(a.pk));
        var hundred = data(onlyApproval, "todos");
        assertThat(hundred.path("truncated").asBoolean()).isFalse();
        assertThat(todoItems(hundred)).hasSize(100);
        String latest = pendingAuthorization(a, creator.id());
        jdbc.update("UPDATE asset_authorization SET created_at=? WHERE public_id=?", workbench.now().plusSeconds(1), latest);
        var todos = data(scoped, "todos");
        assertThat(todos.path("truncated").asBoolean()).isTrue();
        assertThat(todos.at("/groups/0/count").asLong()).isEqualTo(101);
        assertThat(todoItems(todos)).hasSize(100);
        assertThat(todos.at("/groups/0/items/0/id").asText()).isEqualTo(latest);
        assertThat(todoItems(todos).stream().map(n -> n.path("assetId").asText())).containsOnly(a.id);
        assertThat(todoItems(todos).stream().map(n -> n.path("id").asText())).doesNotContain(foreign, assignedElsewhere, mine);
        assertThat(todos.at("/groups/1/count").asLong()).isEqualTo(1);
        assertThat(todos.at("/groups/1/items")).isEmpty();
        assertThat(itemKinds(todos)).doesNotContain("policy", "bundle_approval", "model", "bundle_sealing");
    }

    private static List<JsonNode> todoItems(JsonNode result) {
        List<JsonNode> items = new ArrayList<>();
        result.path("groups").forEach(group -> group.path("items").forEach(items::add));
        return items;
    }

    @Test
    void todosRequireHumanSessionRejectParametersAndDoNotWriteBusinessFacts() throws Exception {
        assertThat(mvc.perform(get("/api/v2/todos")).andReturn().getResponse().getStatus()).isEqualTo(401);
        // 人工路由不接受机器 bearer 建立身份；不能靠测试注入绕过真实会话过滤器。
        var machineResult = mvc.perform(get("/api/v2/todos")
                .header("Authorization", "Bearer mch_1." + "f".repeat(43))).andReturn().getResponse();
        assertThat(machineResult.getStatus()).isEqualTo(401);
        var none = identity(List.of(), "global", "*");
        assertThat(data(none, "todos")).isEqualTo(object("groups", List.of(), "truncated", false));
        error(reader, "todos", 400, "INVALID_QUERY", "limit", "5");
        error(reader, "todos", 400, "INVALID_QUERY", "assetId", b.id);
        login(reader);
        var before = snapshot();
        var result = data(reader, "todos");
        assertThat(itemKinds(result)).containsExactly("device");
        assertThat(todoItems(result).stream().map(n -> n.path("id").asText())).containsExactly(ea.id);
        assertThat(snapshot()).isEqualTo(before);
    }

    @Test
    void expiringAuthorizationsUseCurrentValidityAndSevenDayBoundary() throws Exception {
        var requester = identity(List.of("authorization.request"), "asset", Long.toString(a.pk));
        LocalDateTime now = workbench.now().withNano(0);
        jdbc.update("UPDATE asset_authorization SET valid_from=?,valid_until=? WHERE id=?", now.minusDays(1), now.plusDays(7), aa.pk);
        assertThat(workbench.todoCount(requester.id(), GuardTodoMapper.TodoKind.EXPIRING_AUTHORIZATION, now)).isEqualTo(1);
        assertThat(workbench.todoCount(requester.id(), GuardTodoMapper.TodoKind.EXPIRING_AUTHORIZATION, now.minusSeconds(1))).isZero();
        assertThat(workbench.todoCount(requester.id(), GuardTodoMapper.TodoKind.EXPIRING_AUTHORIZATION, now.plusDays(7))).isZero();
        jdbc.update("UPDATE asset_authorization SET valid_from=? WHERE id=?", now.plusSeconds(1), aa.pk);
        assertThat(workbench.todoCount(requester.id(), GuardTodoMapper.TodoKind.EXPIRING_AUTHORIZATION, now)).isZero();
    }

    private static java.util.Set<String> itemKinds(JsonNode result) {
        return todoItems(result).stream().map(n -> n.path("kind").asText()).collect(java.util.stream.Collectors.toSet());
    }

    /** 仅为当前随机隔离库构造最小完整外键链；不启动推理、回放、broker 或执行器。 */
    private Resource insert(String table, Object... fields) {
        var values = new LinkedHashMap<String, Object>();
        String external = id(); values.put("public_id", external);
        for (int i = 0; i < fields.length; i += 2) values.put((String) fields[i], fields[i + 1]);
        jdbc.update("INSERT INTO " + table + "(" + String.join(",", values.keySet()) + ") VALUES ("
                + String.join(",", java.util.Collections.nCopies(values.size(), "?")) + ")", values.values().toArray());
        return new Resource(pk(table, external), external);
    }

    record Catalog(Resource model, Resource policy, Resource bundle) { }
    private Catalog catalog(long creator) {
        String hash = id().replace("-", "").repeat(2);
        var contract = insert("guard_contract", "contract_version", CONTRACT, "profile_sha256", hash,
                "schema_set_sha256", hash, "extractor_sha256", hash, "status", "active");
        var model = insert("guard_model", "model_key", id(), "version", "1", "manifest_ref", "fixture/model.json",
                "manifest_sha256", hash, "artifact_sha256", hash, "contract_id", contract.pk,
                "manifest_json", "{\"candidateOnly\":true}", "created_by", creator);
        var plan = insert("guard_evaluation_plan", "plan_key", id(), "version", "1", "plan_sha256", hash, "payload_json", "{}", "created_by", creator);
        var policy = insert("guard_decision_policy", "policy_key", id(), "version", "1", "model_id", model.pk, "plan_id", plan.pk,
                "decision_contract_version", DECISION, "definition_json", "{}", "definition_sha256", hash, "created_by", creator);
        var bundle = insert("guard_release_bundle", "bundle_key", id(), "version", "1", "model_id", model.pk, "policy_id", policy.pk,
                "contract_id", contract.pk, "plan_id", plan.pk, "environment", "lab", "subject_sha256", hash, "subject_json", "{}", "requested_by", creator);
        return new Catalog(model, policy, bundle);
    }

    private String pendingAuthorization(Resource asset, long creator) {
        return insert("asset_authorization", "asset_id", asset.pk, "authorization_ref", "fixture", "scope_json", "{}",
                "valid_from", TIME, "valid_until", workbench.now().plusDays(1), "status", "pending", "requested_by", creator).id;
    }

    private Resource observation(Resource asset, Resource sensor, Resource config, Resource scope, LocalDateTime time, String direction) {
        String boot = id();
        var batch = insert("guard_observation_batch", "sensor_id", sensor.pk, "asset_id", asset.pk, "boot_id", boot,
                "sequence_no", 1, "config_id", config.pk, "request_sha256", "a".repeat(64), "result_json", "{}");
        return insert("guard_observation", "batch_id", batch.pk, "sensor_id", sensor.pk, "asset_id", asset.pk, "boot_id", boot,
                "capture_scope_id", scope.pk, "flow_id", id(), "parent_connection_id", id(), "snapshot_index", 1,
                "profile", "prefix", "as_of", time, "last_packet_at", time, "peer_key", "a".repeat(64), "key_epoch", 1,
                "direction", direction, "transport", "tcp", "environment", "lab", "payload_json", "{}", "content_sha256", "b".repeat(64));
    }

    private Resource decision(Resource asset, Resource sensor, Resource bundle, LocalDateTime time, String family, String decision) {
        var episode = insert("guard_episode", "asset_id", asset.pk, "sensor_id", sensor.pk, "boot_id", id(), "peer_key", "a".repeat(64),
                "key_epoch", 1, "direction", "inbound", "transport", "tcp", "service_port", 443, "family", family,
                "bundle_id", bundle.pk, "bucket_start", time);
        return insert("guard_decision", "episode_id", episode.pk, "asset_id", asset.pk, "bundle_id", bundle.pk, "decision_revision", 1,
                "decision_contract_version", DECISION, "decision", decision, "evidence_sha256", "c".repeat(64), "evidence_json", "{}", "decided_at", time);
    }

    private Resource action(Resource asset, Resource executor, Resource auth, Resource bundle, Resource decision, long creator, String mode, String state) {
        String hash = id().replace("-", "").repeat(2);
        var target = insert("guard_budget_target", "asset_id", asset.pk, "environment", "lab", "stable_target_token", hash,
                "resolver_executor_id", executor.pk, "scope_digest", hash);
        return insert("guard_action", "decision_id", decision.pk, "asset_id", asset.pk, "executor_id", executor.pk,
                "budget_target_id", target.pk, "budget_revision", 1, "bundle_id", bundle.pk, "authorization_id", auth.pk,
                "authorization_revision", 1, "mode", mode, "observed_state", state, "idempotency_key", id(),
                "target_snapshot", "{}", "block_until", workbench.now().plusMinutes(5), "created_by", creator);
    }

    private String lab(Resource bundle, long creator, boolean withRun) {
        var session = insert("guard_validation_session", "asset_id", a.pk, "bundle_id", bundle.pk, "authorization_id", aa.pk,
                "requested_by", creator, "payload_json", "{}", "content_sha256", "f".repeat(64), "valid_until", workbench.now().plusDays(1));
        if (withRun) jdbc.update("INSERT INTO guard_lab_run(session_id,sensor_id,boot_id,manifest_ref,manifest_sha256,manifest_jcs,scenarios_jcs,mapping_jcs) VALUES (?,?,?,'fixture',?,'{}','[]','{}')",
                session.pk, sa.pk, id(), "f".repeat(64));
        return session.id;
    }

    private String feedback(Resource observation, long creator) {
        return insert("guard_feedback", "asset_id", a.pk, "observation_id", observation.pk, "label", "benign", "evidence_ref", "fixture", "created_by", creator).id;
    }

    private String event(Resource asset, String status, Long assignee, LocalDateTime time) {
        return insert("security_event", "guard_asset_id", asset.pk, "event_key", id(), "title", "待研判测试事件", "category", "dos_slow",
                "severity", "high", "status", status, "risk_score", 80, "risk_rule_version", "v5", "assignee_id", assignee,
                "first_seen_at", time, "last_seen_at", time, "created_at", time).id;
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
