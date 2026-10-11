package com.xyh.cybersecurity.guard;

import java.time.LocalDateTime;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import static com.xyh.cybersecurity.guard.GuardJson.map;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** 批量案件投影须与逐条路径保持相同的最新链接和合并案件更新时间。 */
class GuardCasesBatchTest {
    @Test void mergedEpisodesUseLatestLinkAndLastDecisionTime() {
        var store=mock(GuardStore.class);
        var cases=new GuardCases(store,mock(GuardAccess.class));
        var at=LocalDateTime.of(2026,10,11,0,0);
        var episodes=Map.of(1L,map("id",1L,"public_id","episode-1"),2L,map("id",2L,"public_id","episode-2"));
        var decisions=List.of(map("public_id","decision-1","episode_id",1L,"decision","alert","reason_code",null,"decided_at",at),
                map("public_id","decision-2","episode_id",2L,"decision","alert","reason_code",null,"decided_at",at.plusSeconds(1)));
        when(store.byKeys(eq("guard_event_episode"),anyList(),eq(false))).thenReturn(List.of(
                map("id",10L,"episode_id",1L,"event_id",90L),
                map("id",11L,"episode_id",1L,"event_id",91L),
                map("id",12L,"episode_id",2L,"event_id",91L)));
        when(store.now()).thenReturn(at.toInstant(java.time.ZoneOffset.UTC));

        cases.detectedBatch(episodes,decisions);

        @SuppressWarnings("unchecked") ArgumentCaptor<List<Map<String,Object>>> updates=ArgumentCaptor.forClass(List.class);
        verify(store).updateAll(eq("security_event"),updates.capture());
        assertThat(updates.getValue()).containsExactly(map("id",91L,"last_seen_at",at.plusSeconds(1)));
        @SuppressWarnings("unchecked") ArgumentCaptor<List<Map<String,Object>>> timeline=ArgumentCaptor.forClass(List.class);
        verify(store).insertAll(eq("event_timeline"),timeline.capture());
        assertThat(timeline.getValue()).hasSize(2).allSatisfy(row->assertThat(row.get("event_id")).isEqualTo(91L));
        verify(store,never()).addAllReturning(eq("security_event"),anyList());
    }
}
