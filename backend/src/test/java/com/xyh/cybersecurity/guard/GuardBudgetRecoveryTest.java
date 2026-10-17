package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** 断采重启只允许新的完整健康链恢复旧稳定预算，不能拼接、提前恢复或采用回放。 */
class GuardBudgetRecoveryTest {
    final Instant now=Instant.parse("2026-10-17T00:10:00Z");
    final GuardStore store=mock(GuardStore.class);
    final GuardBudget budget=spy(new GuardBudget(store,mock(GuardAccess.class),new GuardHealth(store,mock(GuardAccess.class))));
    final Map<String,Object> state=map("id",1L,"public_id",id(),"budget_target_id",2L,"revision",3L,"charged_ms",60000L,
            "last_block_end_at",db(now.minusSeconds(600)),"cycle_started_at",db(now.minusSeconds(660)));
    GuardBudgetRecoveryTest(){doReturn(state).when(budget).lock(1,2);doReturn(false).when(budget).revoked(2);
        when(store.one(eq("guard_asset_binding"),anyMap(),eq(false))).thenReturn(map("bundle_id",3L));
        when(store.get("guard_release_bundle",3L)).thenReturn(map("status","active","environment","lab","policy_id",4L));
        policy(GuardBudget.DEMO_POLICY_VERSION);
    }
    void policy(String version){when(store.get("guard_decision_policy",4L)).thenReturn(map("public_id",id(),"definition_sha256","a".repeat(64),"definition_json",canonical(object("policyVersion",version))));}
    void chain(int seconds,String status,boolean gap){
        var rows=new ArrayList<Map<String,Object>>();ObjectNode previous=null;
        for(int offset=seconds;offset>0;offset-=5){
            var b=GuardDomainTest.health(now.minusSeconds(offset-5),seconds-offset+1,previous==null?null:hash(previous));
            if(previous!=null){b.put("observerSessionId",previous.path("observerSessionId").asText());b.put("captureScopeId",previous.path("captureScopeId").asText());}
            if(gap&&offset==60)b.put("observerSessionId",id());
            rows.add(map("public_id",b.path("healthWindowId").asText(),"content_sha256",hash(b),"payload_json",canonical(b),"verification_status",status));previous=b;
        }
        Collections.reverse(rows);when(store.rows(eq("guard_capture_health_window"),anyMap(),eq(false),eq(10000))).thenReturn(rows);
    }
    @Test void newCompleteChainRecoversAfterEarlierInterruption(){
        chain(135,"healthy",false);assertThat(budget.recover(1,2,now)).isTrue();
        verify(store).update(eq("guard_target_budget"),eq(1L),argThat(v->v.get("charged_ms").equals(0)));
        verify(store).add(eq("guard_budget_event"),argThat(v->"reset".equals(v.get("event_kind"))&&GuardBudget.RECOVERY_VERSION.equals(json(v,"proof_json").path("recoveryVersion").asText())));
    }
    @Test void legacyPolicyKeepsOriginalAnchorAndProof(){
        chain(135,"healthy",false);policy(DECISION);assertThat(budget.recover(1,2,now)).isFalse();
        chain(600,"healthy",false);assertThat(budget.recover(1,2,now)).isTrue();
        verify(store).add(eq("guard_budget_event"),argThat(v->!json(v,"proof_json").has("recoveryVersion")));
    }
    @Test void missingSuspendedAndNonLabBindingsCannotOptIntoRecovery(){
        chain(135,"healthy",false);
        when(store.get("guard_release_bundle",3L)).thenReturn(map("status","active","environment","authorized","policy_id",4L));
        assertThat(budget.recover(1,2,now)).isFalse();
        when(store.get("guard_release_bundle",3L)).thenReturn(map("status","suspended","environment","lab","policy_id",4L));
        assertThat(budget.recover(1,2,now)).isFalse();
        when(store.one(eq("guard_asset_binding"),anyMap(),eq(false))).thenReturn(null);
        assertThat(budget.recover(1,2,now)).isFalse();
    }
    @Test void shortChainReplayAndBrokenSessionCannotRecover(){
        chain(115,"healthy",false);assertThat(budget.recover(1,2,now)).isFalse();
        chain(135,"replay_healthy",false);assertThat(budget.recover(1,2,now)).isFalse();
        chain(135,"healthy",true);assertThat(budget.recover(1,2,now)).isFalse();
        verify(store,never()).update(eq("guard_target_budget"),anyLong(),anyMap());
    }
    @Test void staleChainCannotRecover(){
        chain(135,"healthy",false);assertThat(budget.recover(1,2,now.plusSeconds(11))).isFalse();
    }
    @Test void recentEvidenceAndUnfinishedActionPreventRecovery(){
        chain(135,"healthy",false);state.put("last_evidence_at",db(now.minusSeconds(119)));
        assertThat(budget.recover(1,2,now)).isFalse();state.remove("last_evidence_at");
        when(store.rows(eq("guard_action"),anyMap(),eq(true),eq(10000))).thenReturn(List.of(map("observed_state","applied")));
        assertThat(budget.recover(1,2,now)).isFalse();
    }
}
