package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** D5：用干净、新鲜、高分的同目标证据隔离验证策略关闭门，不改变运行中的质量门或冻结策略。 */
class GuardAutoDisabledTest {
    private static final Instant NOW=Instant.parse("2030-01-01T00:00:00Z");
    private static final GuardDecisionEngine.Gates OPEN=new GuardDecisionEngine.Gates(true,true,true,true,null);

    @Test void familyDisabledAlwaysAlertsWithCleanHighScoreEvidence()throws Exception{
        ObjectNode p=GuardDomainTest.autoPolicy(1);var fp=(ObjectNode)GuardDecisionEngine.familyPolicy(p,"dos_flood");
        fp.put("autoEligible",false).put("modelAutoEligible",false);
        assertFamilyDisabled(p);
    }

    @Test void disabledRuleCannotCreateCandidateEvenWhenFamilyAndModelAreEnabled()throws Exception{
        var p=GuardDomainTest.autoPolicy(1);p.put("minEvidenceSpanMs",0);
        p.set("rulePolicies",node(List.of(object("ruleId","disabled-rule","family","dos_slow","autoEligible",false))));
        var o=GuardDomainTest.observation(NOW);
        var result=GuardDecisionEngine.evaluate(p,List.of(new GuardDecisionEngine.Evidence(o,null,"dos_slow","rule","disabled-rule",true,hash(o))),NOW,OPEN,"dos_slow","rule","disabled-rule");
        assertThat(result.decision()).isEqualTo("alert");assertThat(result.reason()).isEqualTo("SCORE_BELOW_AUTO");
    }

    /** 门禁专用：输入必须来自本轮克隆的组合关联策略，摘要通过独立系统属性传入；普通构建不读本机私有证据。 */
    @Test
    @EnabledIfSystemProperty(named="guard.frozenPolicy",matches=".+")
    void cloneBoundFrozenPolicyDisablesFlood()throws Exception{
        var policy=parse(Files.readString(Path.of(System.getProperty("guard.frozenPolicy"))));
        assertThat(hash(policy)).isEqualTo(System.getProperty("guard.frozenPolicySha256"));
        new GuardContracts().policy(policy);
        var fp=GuardDecisionEngine.familyPolicy(policy,"dos_flood");
        assertThat(fp.path("autoEligible").asBoolean(true)).isFalse();
        assertThat(fp.path("modelAutoEligible").asBoolean(true)).isFalse();
        assertFamilyDisabled(policy);
    }

    private void assertFamilyDisabled(JsonNode policy)throws Exception{
        var evidence=new ArrayList<GuardDecisionEngine.Evidence>();
        int flows=Math.max(2,GuardDecisionEngine.familyPolicy(policy,"dos_flood").path("minDistinctFlows").asInt());
        var prototype=GuardDomainTest.observation(NOW);
        for(int i=0;i<flows;i++){
            var o=prototype.deepCopy().put("observationId",id()).put("parentConnectionId",id());
            assertThat(GuardDecisionEngine.badQuality(o)).isFalse();
            evidence.add(new GuardDecisionEngine.Evidence(o,1d,"dos_flood","model","",false,hash(o)));
        }
        var result=GuardDecisionEngine.evaluate(policy,evidence,NOW,OPEN,"dos_flood","model","");
        assertThat(result.reason()).isEqualTo("FAMILY_AUTO_DISABLED");assertThat(result.decision()).isEqualTo("alert");
        assertThat(result.qualifiedEvidence()).isFalse();
    }
}
