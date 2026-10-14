package com.xyh.cybersecurity.guard;

import com.xyh.cybersecurity.common.api.ApiRequestException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Q5：只改变封存所需的报告组合；final、报告归属与通过状态仍必须满足。 */
class GuardCatalogSealingTest {
    @ParameterizedTest
    @CsvSource({
        "alert_only,authorized,final,ok", "alert_only,lab,final,ok",
        "alert_only,research,final,ok", "auto,research,final,ok",
        "alert_only,authorized,platform+canary,FINAL_EVALUATION_REQUIRED",
        "auto,authorized,final,JOINT_EVALUATION_REQUIRED",
        "auto,authorized,final+platform,JOINT_EVALUATION_REQUIRED",
        "auto,authorized,final+canary,JOINT_EVALUATION_REQUIRED",
        "auto,lab,final+platform,JOINT_EVALUATION_REQUIRED",
        "auto,lab,final+canary,JOINT_EVALUATION_REQUIRED",
        "auto,lab,final+platform+canary,ok", "auto,authorized,final+platform+canary,ok",
        "unknown,authorized,final,JOINT_EVALUATION_REQUIRED"
    })
    void sealRequiresEvidenceForTheBoundPolicyMode(String mode,String environment,String kinds,String expected) {
        var store=mock(GuardStore.class);var access=mock(GuardAccess.class);
        var catalog=new GuardCatalog(store,access,null,null,null,null,false);
        String bundleId=id();
        when(store.external("guard_release_bundle",bundleId,true)).thenReturn(map("id",1L,"status","candidate",
                "environment",environment,"policy_id",2L,"subject_sha256","a".repeat(64),"revision",1L));
        when(store.get("guard_decision_policy",2L)).thenReturn(map("definition_json",canonical(object("mode",mode))));
        var ids=new ArrayList<String>();
        for(String kind:kinds.split("\\+")) {
            String reportId=id();ids.add(reportId);
            when(store.external("guard_evaluation_run",reportId,false)).thenReturn(map("public_id",reportId,
                    "bundle_id",1L,"status","passed","run_kind",kind,"report_sha256","b".repeat(64)));
        }
        if(expected.equals("ok")) {
            var result=catalog.seal(bundleId,object("evaluationIds",ids),"1");
            assertThat(result.path("status").asText()).isEqualTo("evaluated");
            assertThat(result.path("sealedManifestSha256").asText()).matches("[0-9a-f]{64}");
            verify(store).update(eq("guard_release_bundle"),eq(1L),argThat(v->v.get("status").equals("evaluated")));
        } else {
            assertThatThrownBy(()->catalog.seal(bundleId,object("evaluationIds",ids),"1"))
                    .isInstanceOfSatisfying(ApiRequestException.class,e->assertThat(e.code()).isEqualTo(expected));
            verify(store,never()).update(anyString(),anyLong(),anyMap());
        }
    }

    @ParameterizedTest
    @CsvSource({"2,passed", "1,failed"})
    void alertOnlyStillRejectsForeignOrFailedFinal(long reportBundle,String reportStatus) {
        var store=mock(GuardStore.class);var access=mock(GuardAccess.class);
        var catalog=new GuardCatalog(store,access,null,null,null,null,false);
        String bundleId=id(),reportId=id();
        when(store.external("guard_release_bundle",bundleId,true)).thenReturn(map("id",1L,"status","candidate",
                "environment","authorized","policy_id",2L,"revision",1L));
        when(store.external("guard_evaluation_run",reportId,false)).thenReturn(map("bundle_id",reportBundle,
                "status",reportStatus,"run_kind","final"));
        assertThatThrownBy(()->catalog.seal(bundleId,object("evaluationIds",List.of(reportId)),"1"))
                .isInstanceOfSatisfying(ApiRequestException.class,e->assertThat(e.code()).isEqualTo("EVALUATION_PLAN_MISMATCH"));
        verify(store,never()).update(anyString(),anyLong(),anyMap());
    }
}
