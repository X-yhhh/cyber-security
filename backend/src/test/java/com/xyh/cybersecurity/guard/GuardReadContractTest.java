package com.xyh.cybersecurity.guard;

import com.xyh.cybersecurity.common.api.ApiRequestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.util.LinkedMultiValueMap;

import java.time.LocalDateTime;
import static com.xyh.cybersecurity.guard.GuardJson.canonical;
import static com.xyh.cybersecurity.guard.GuardJson.id;
import static com.xyh.cybersecurity.guard.GuardJson.map;
import static com.xyh.cybersecurity.guard.GuardJson.object;
import static com.xyh.cybersecurity.guard.GuardJson.uuid;
import static com.xyh.cybersecurity.guard.GuardReadMapper.Kind.*;
import static org.assertj.core.api.Assertions.*;

/** 游标绑定、严格参数和嵌套类型白名单，不依赖数据库或运行服务。 */
class GuardReadContractTest {
    @Test
    void cursorAuthenticatesAllContextAndDoesNotExposeInternalIds() {
        var codec = new GuardReadCursor();
        var position = new GuardReadCursor.Position(103, 99, LocalDateTime.parse("2026-10-11T01:02:03.123456"),
                LocalDateTime.parse("2026-10-11T01:03:00"));
        String encoded = codec.encode(position, "actor:1|asset:a");
        assertThat(codec.decode(encoded, "actor:1|asset:a")).isEqualTo(position);
        for (String wrong : new String[]{"actor:2|asset:a", "actor:1|asset:b", "audit"}) {
            assertThatThrownBy(() -> codec.decode(encoded, wrong)).isInstanceOf(ApiRequestException.class)
                    .hasMessageContaining("INVALID_CURSOR");
        }
        assertThatThrownBy(() -> new GuardReadCursor().decode(encoded, "actor:1|asset:a"))
                .hasMessageContaining("INVALID_CURSOR");
        String changed = (encoded.startsWith("A") ? "B" : "A") + encoded.substring(1);
        assertThatThrownBy(() -> codec.decode(changed, "actor:1|asset:a")).hasMessageContaining("INVALID_CURSOR");
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "201", "-1", "1.5", "9999999999999", "limit", "+1"})
    void invalidLimitsFailClosed(String limit) {
        var p = new LinkedMultiValueMap<String, String>();
        p.add("limit", limit);
        assertThatThrownBy(() -> GuardReadRequest.parse(AUTHORIZATIONS, p)).hasMessageContaining("INVALID_PAGE_SIZE");
    }

    @Test
    void filtersAreStrictAndCanonicalButPageSizeMayChange() {
        var p = new LinkedMultiValueMap<String, String>();
        p.add("from", "2026-10-11T00:00:00.000Z");
        p.add("until", "2026-10-12T00:00:00Z");
        var first = GuardReadRequest.parse(HEALTH, p);
        p.set("from", "2026-10-11T00:00:00Z");
        p.add("limit", "200");
        var second = GuardReadRequest.parse(HEALTH, p);
        assertThat(first.limit()).isEqualTo(50);
        assertThat(first.binding(HEALTH, 1)).isEqualTo(second.binding(HEALTH, 1));
        assertThat(first.binding(HEALTH, 1)).isNotEqualTo(first.binding(SENSORS, 1));
        p.add("limit", "1");
        assertThatThrownBy(() -> GuardReadRequest.parse(HEALTH, p)).hasMessageContaining("INVALID_QUERY");
        p.remove("limit");
        p.add("misspelledAsset", id());
        assertThatThrownBy(() -> GuardReadRequest.parse(HEALTH, p)).hasMessageContaining("INVALID_QUERY");
    }

    @ParameterizedTest
    @ValueSource(strings = {"2026-10-11", "2026-10-11T00:00:00+08:00", "2026-10-11T00:00:00.0000001Z", "invalid"})
    void invalidTimesAreNotSilentlyRounded(String time) {
        var p = new LinkedMultiValueMap<String, String>();
        p.add("from", time);
        assertThatThrownBy(() -> GuardReadRequest.parse(AUDIT, p)).hasMessageContaining("INVALID_TIME_RANGE");
    }

    @Test
    void scalarWhitelistCannotBeUsedToSmuggleNestedSecrets() {
        var payload = object("contractVersion", object("credential", "sentinel-secret"),
                "interfaceIds", java.util.List.of("fixture0", object("privateKey", "sentinel-secret")),
                "limits", object("maxBatchSize", object("token", "sentinel-secret")),
                "captureScopeId", object("rawTarget", "sentinel-secret"), "unknown", "sentinel-secret");
        var row = map("guard_definition_json", canonical(payload));
        var view = GuardReadViews.view(CONFIGS, row, LocalDateTime.now());
        assertThat(view.toString()).doesNotContain("sentinel-secret");
        assertThat(view.at("/definition/contractVersion").isNull()).isTrue();
        assertThat(view.at("/definition/limits/maxBatchSize").isNull()).isTrue();
        assertThat(view.at("/definition/interfaceIds")).hasSize(1);
    }

    @Test
    void missingCountersAndHealthStatusAreNotInvented() {
        LocalDateTime time = LocalDateTime.parse("2026-10-11T00:00:00");
        var row = map("verification_status", "COUNTER_UNKNOWN", "interval_end", time,
                "payload_json", canonical(object("counterEnd", object("kernelDrops", null))));
        var view = GuardReadViews.view(HEALTH, row, time.plusSeconds(11));
        assertThat(view.at("/counterEnd/kernelDrops").isNull()).isTrue();
        assertThat(view.at("/counterEnd/packetsSeen").isNull()).isTrue();
        assertThat(view.path("serverVerifiedHealthy").asBoolean()).isFalse();
        assertThat(view.path("freshness").asText()).isEqualTo("stale");
        assertThat(view.path("healthState").asText()).isEqualTo("unknown");
        assertThat(view.path("healthBasis").asText()).isEqualTo("server_verified_window");
        assertThat(GuardReadViews.freshness(null, time)).isEqualTo("no_record");
        assertThat(GuardReadViews.freshness(time.plusNanos(1000), time)).isEqualTo("unknown");
        assertThat(GuardReadViews.freshness(time.minusSeconds(10), time)).isEqualTo("fresh");
    }

    @Test
    void healthWindowStatesNeverShowUnknownAsHealthy() {
        LocalDateTime now = LocalDateTime.parse("2026-10-11T00:00:10");
        LocalDateTime recent = now.minusSeconds(1), old = now.minusSeconds(11), future = now.plusSeconds(1);
        assertThat(GuardReadViews.windowState("healthy", recent, recent, now)).isEqualTo("healthy");
        assertThat(GuardReadViews.windowState("healthy", now.minusSeconds(10), now, now)).isEqualTo("healthy");
        assertThat(GuardReadViews.windowState("healthy", old, old, now)).isEqualTo("stale");
        assertThat(GuardReadViews.windowState("healthy", future, recent, now)).isEqualTo("unknown");
        assertThat(GuardReadViews.windowState("healthy", null, recent, now)).isEqualTo("unknown");
        assertThat(GuardReadViews.windowState(null, recent, recent, now)).isEqualTo("unknown");
        for (String unknown : new String[]{"COUNTER_UNKNOWN", "CLOCK_UNTRUSTED"}) {
            assertThat(GuardReadViews.windowState(unknown, recent, recent, now)).isEqualTo("unknown");
        }
        assertThat(GuardReadViews.windowState("HEALTH_DELAY_EXCEEDED", old, recent, now)).isEqualTo("stale");
        assertThat(GuardReadViews.windowState("HEALTH_DELAY_EXCEEDED", future, recent, now)).isEqualTo("unknown");
        for (String failed : new String[]{"CAPTURE_GAP", "CAPTURE_DROPS", "HEALTH_CHAIN_INCOMPLETE",
                "HEALTH_IDENTITY_CHANGED", "SOME_FUTURE_CODE"}) {
            assertThat(GuardReadViews.windowState(failed, recent, recent, now)).isEqualTo("unhealthy");
        }
    }

    @Test
    void heartbeatStatesSeparateNoRecordStaleUnconfirmedAndStopped() {
        LocalDateTime now = LocalDateTime.parse("2026-10-11T00:00:10");
        assertThat(GuardReadViews.heartbeatState("active", null, now)).isEqualTo("unknown");
        assertThat(GuardReadViews.heartbeatState("active", now.plusSeconds(1), now)).isEqualTo("unknown");
        assertThat(GuardReadViews.heartbeatState("active", now.minusSeconds(11), now)).isEqualTo("stale");
        assertThat(GuardReadViews.heartbeatState("active", now.minusSeconds(1), now)).isEqualTo("healthy");
        assertThat(GuardReadViews.heartbeatState("pending", now.minusSeconds(1), now)).isEqualTo("unknown");
        assertThat(GuardReadViews.heartbeatState(null, now.minusSeconds(1), now)).isEqualTo("unknown");
        for (String stopped : new String[]{"offline", "revoked", "suspended"}) {
            assertThat(GuardReadViews.heartbeatState(stopped, now.minusSeconds(1), now)).isEqualTo("unhealthy");
            assertThat(GuardReadViews.heartbeatState(stopped, null, now)).isEqualTo("unhealthy");
        }
        var executor = GuardReadViews.view(EXECUTORS, map("status", "pending", "received_at", now.minusSeconds(1),
                "health_json", canonical(object("pendingRecovery", true, "privateKey", "sentinel-secret"))), now);
        assertThat(executor.path("healthState").asText()).isEqualTo("unknown");
        assertThat(executor.path("healthBasis").asText()).isEqualTo("heartbeat_and_status");
        assertThat(executor.path("serverVerifiedHealthy").isNull()).isTrue();
        assertThat(executor.toString()).doesNotContain("sentinel-secret", "privateKey");
        var sensor = GuardReadViews.view(SENSORS, map("status", "active"), now);
        assertThat(sensor.path("freshness").asText()).isEqualTo("no_record");
        assertThat(sensor.path("healthState").asText()).isEqualTo("unknown");
    }

    @Test
    void legacyAuditResourceValuesBecomeReferences() {
        var row = map("internal_id", 1L, "resource_type", "legacy", "resource_id", "sentinel-private-address");
        var first = GuardReadViews.view(AUDIT, row, LocalDateTime.now());
        var second = GuardReadViews.view(AUDIT, row, LocalDateTime.now());
        assertThat(first).isEqualTo(second);
        assertThat(first.toString()).doesNotContain("sentinel-private-address");
        assertThatCode(() -> uuid(first.path("id").asText())).doesNotThrowAnyException();
    }
}
