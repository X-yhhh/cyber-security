package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.util.LinkedMultiValueMap;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/** B5.2 实时态势：范围与步长校验、覆盖与 null 语义（不需要数据库）。 */
class GuardLiveStatsTest {
    /** 服务器自然日只是展示口径，查询边界必须转回 UTC，包含夏令时切换当天。 */
    @ParameterizedTest
    @CsvSource({
            "Asia/Shanghai,2026-10-14T16:30:00,2026-10-14T16:00:00",
            "UTC,2026-10-14T16:30:00,2026-10-14T00:00:00",
            "America/New_York,2026-03-08T12:00:00,2026-03-08T05:00:00",
            "America/New_York,2026-11-01T12:00:00,2026-11-01T04:00:00"})
    void serverCalendarDayIsConvertedBackToUtcForEveryTodayQuery(String zone, String utcNow, String utcStart) {
        var mapper = mock(GuardReadMapper.class);
        var access = mock(GuardAccess.class);
        when(access.human()).thenReturn(7L);
        when(mapper.now()).thenReturn(java.time.LocalDateTime.parse(utcNow));
        when(mapper.hasPermission(7, "detection.read")).thenReturn(true);
        when(mapper.hasPermission(7, "action.read")).thenReturn(true);
        new GuardLiveStats(mapper, access, java.time.ZoneId.of(zone)).live(null);
        var expected = java.time.LocalDateTime.parse(utcStart);
        verify(mapper).liveTodayInbound(7, expected);
        verify(mapper).liveTodayAlerts(7, expected);
        verify(mapper).liveTodayBlocked(7, expected);
    }

    private static LinkedMultiValueMap<String, String> q(String... kv) {
        var m = new LinkedMultiValueMap<String, String>();
        for (int i = 0; i < kv.length; i += 2) m.add(kv[i], kv[i + 1]);
        return m;
    }

    @ParameterizedTest
    @CsvSource({"15m,10,90", "1h,60,60", "24h,900,96", "7d,3600,168"})
    void defaultStepPerRange(String range, int step, int points) {
        var w = GuardLiveStats.window(q("range", range));
        assertThat(w.step()).isEqualTo(step);
        assertThat(w.points()).isEqualTo(points);
    }

    @Test
    void defaultsTo15MinutesAndAcceptsExplicitStep() {
        assertThat(GuardLiveStats.window(q()).range()).isEqualTo("15m");
        assertThat(GuardLiveStats.window(null).points()).isEqualTo(90);
        assertThat(GuardLiveStats.window(q("range", "1h", "step", "10")).points()).isEqualTo(360);
    }

    @ParameterizedTest
    @CsvSource(value = {
            "range,5m", "range,7D", "range,''", "step,9", "step,3601", "step,7", "step,abc", "step,-10",
            "window,15m", "assetId,x"}, nullValues = "NULL")
    void invalidParametersFailClosed(String key, String value) {
        assertThatThrownBy(() -> GuardLiveStats.window(q(key, value))).hasMessageContaining("INVALID_QUERY");
    }

    @Test
    void tooManyPointsAndDuplicatesAreRejected() {
        // 7 天按 10 秒 = 60480 点，超过 500 点上限。
        assertThatThrownBy(() -> GuardLiveStats.window(q("range", "7d", "step", "10"))).hasMessageContaining("INVALID_QUERY");
        assertThatThrownBy(() -> GuardLiveStats.window(q("range", "1h", "range", "15m"))).hasMessageContaining("INVALID_QUERY");
    }

    @Test
    void uncoveredBucketsAreNullAndCoveredEmptyBucketsAreZero() {
        boolean[] covered = GuardLiveStats.coverage(List.of(Map.of("s", 1L, "e", 2L), Map.of("s", -3L, "e", 0L), Map.of("s", 4L, "e", 99L)), 5);
        assertThat(covered).containsExactly(true, true, true, false, true);
        JsonNode s = GuardLiveStats.series(List.of(Map.of("b", 1L, "n", 3L), Map.of("b", 3L, "n", 2L), Map.of("b", 9L, "n", 1L)), covered);
        // 桶 0、2 有覆盖无事件为 0；桶 3 无覆盖但确有事件，如实给出计数而不是吞掉；越界桶忽略。
        assertThat(s.toString()).isEqualTo("[0,3,0,2,0]");
        JsonNode empty = GuardLiveStats.series(List.of(), new boolean[]{false, true, false});
        assertThat(empty.toString()).isEqualTo("[null,0,null]");
    }
}
