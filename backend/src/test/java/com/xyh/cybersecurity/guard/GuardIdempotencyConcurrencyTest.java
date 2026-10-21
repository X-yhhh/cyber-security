package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.audit.AuditMapper;
import com.xyh.cybersecurity.database.IsolatedDatabaseSchemas;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 隔离 MySQL 确定性并发回归：同时读到缺失键后再插入，验证独立键不死锁、同键只执行一次。 */
@SpringBootTest(properties = {"cyber.ingest.consumer.enabled=false", "cyber.ingest.outbox-relay.enabled=false",
        "cyber.guard.automation-enabled=false", "cyber.security.local-admin-bootstrap.enabled=false",
        "spring.rabbitmq.listener.simple.auto-startup=false", "spring.rabbitmq.listener.direct.auto-startup=false"})
@EnabledIfEnvironmentVariable(named = "DB_TEST_BASE_URL", matches = ".+")
@ExtendWith(IsolatedDatabaseSchemas.class)
class GuardIdempotencyConcurrencyTest {
    private static final String SCHEMA = IsolatedDatabaseSchemas.name(GuardIdempotencyConcurrencyTest.class, "idem_race");
    @Autowired GuardMapper mapper;
    @Autowired AuditMapper audit;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> System.getenv("DB_TEST_BASE_URL").replaceFirst("/+$", "")
                + "/" + SCHEMA + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true");
        registry.add("spring.datasource.username", () -> System.getenv("DB_TEST_USERNAME"));
        registry.add("spring.datasource.password", () -> System.getenv("DB_TEST_PASSWORD"));
        registry.add("cyber.security.login-throttle.hmac-key", () -> "isolated-idempotency-test-only-key-32-characters");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void concurrentAbsentKeysCommitWithoutDuplicatingWork(boolean sharedKey) throws Exception {
        var bothRead = new CyclicBarrier(2);
        var reads = new AtomicInteger();
        // 只在两笔事务各自首次读到不存在的幂等键后协调；保留真实 mapper、事务与唯一索引。
        var coordinatedStore = new GuardStore(mapper, audit) {
            @Override public Map<String, Object> one(String table, Map<String, Object> where, boolean lock) {
                var row = super.one(table, where, lock);
                if (table.equals("guard_idempotency") && reads.incrementAndGet() <= 2) {
                    try { bothRead.await(10, TimeUnit.SECONDS); }
                    catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new AssertionError(e); }
                    catch (Exception e) { throw new AssertionError("幂等并发协调超时", e); }
                }
                return row;
            }
        };
        var access = mock(GuardAccess.class);
        when(access.subject()).thenReturn("human:isolated-idempotency");
        var service = new GuardIdempotency(coordinatedStore, access, manager);
        String key1 = id(), key2 = sharedKey ? key1 : id();
        var calls = new AtomicInteger();
        var authorizations = new AtomicInteger();
        JsonNode body = object("value", 1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var first = pool.submit(() -> service.executeAuthorized("fixture/metadata", key1, body, 200,
                    old -> authorizations.incrementAndGet(), () -> object("call", calls.incrementAndGet())));
            var second = pool.submit(() -> service.executeAuthorized("fixture/metadata", key2, body, 200,
                    old -> authorizations.incrementAndGet(), () -> object("call", calls.incrementAndGet())));
            var a = first.get(20, TimeUnit.SECONDS);
            var b = second.get(20, TimeUnit.SECONDS);
            if (sharedKey) assertThat(a).isEqualTo(b);
            else assertThat(a).isNotEqualTo(b);
        }
        assertThat(calls.get()).isEqualTo(sharedKey ? 1 : 2);
        assertThat(authorizations.get()).isEqualTo(sharedKey ? 3 : 2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_idempotency WHERE idempotency_key IN (?,?)",
                Long.class, key1, key2)).isEqualTo(sharedKey ? 1L : 2L);
        // 不同载荷不能借已成功的幂等键重放，且冲突请求仍须经过授权回调。
        assertThatThrownBy(() -> service.executeAuthorized("fixture/metadata", key1, object("value", 2), 200,
                old -> authorizations.incrementAndGet(), () -> object("call", calls.incrementAndGet())))
                .hasMessageContaining("IDEMPOTENCY_CONFLICT");
        assertThat(calls.get()).isEqualTo(sharedKey ? 1 : 2);
        assertThat(authorizations.get()).isEqualTo(sharedKey ? 4 : 3);
    }
}
