package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.Instant;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/**
 * J1 的证据准备度旁路。只在内存副本上按已登记 P6 来源资格打开假想开关，
 * 保留模型、阈值、规则、profile、连接数和时间窗。它不检查/制造真实目标、
 * 现场健康、执行授权或预算，不得用于签发、激活或领取命令。
 */
public final class GuardReplayReadiness {
    private GuardReplayReadiness() {}

    public static JsonNode policy(JsonNode frozen,JsonNode closeout) {
        require(closeout.path("completed").asBoolean()&&closeout.at("/gates/G1").asBoolean()
                &&closeout.at("/gates/G2").asBoolean(),"REPLAY_ELIGIBILITY_UNVERIFIED");
        ObjectNode copy=frozen.deepCopy();
        for(JsonNode entry:copy.path("familyPolicies")) {
            ObjectNode fp=(ObjectNode)entry;JsonNode eligibility=closeout.path("classEligibility").path(fp.path("family").asText());
            require(eligibility.isObject()&&eligibility.path("modelOnly").isObject(),"REPLAY_ELIGIBILITY_UNVERIFIED");
            fp.put("autoEligible",eligibility.path("offlineEligible").asBoolean());
            fp.put("modelAutoEligible",eligibility.at("/modelOnly/offlineEligible").asBoolean());
        }
        for(JsonNode entry:copy.path("rulePolicies")) {
            ObjectNode rule=(ObjectNode)entry;
            JsonNode eligible=closeout.path("classEligibility").path(rule.path("family").asText())
                    .path("ruleOnly").path(rule.path("ruleId").asText());
            require(eligible.isObject(),"REPLAY_ELIGIBILITY_UNVERIFIED");
            rule.put("autoEligible",eligible.path("offlineEligible").asBoolean());
        }
        return copy;
    }

    /** 整组检查与正式路径相同：final 替换 prefix 后不能回退旧高分快照凑数。 */
    public static GuardDecisionEngine.Outcome evaluate(JsonNode policy,JsonNode manifest,
            List<GuardDecisionEngine.Evidence> evidence,Instant now,String family,String source,String ruleId) {
        return evaluate(policy,manifest,evidence,now,family,source,ruleId,true);
    }

    /** 推理失败或不适用也阻止规则自动准备度；规则告警仍由原判定器保留。 */
    public static GuardDecisionEngine.Outcome evaluate(JsonNode policy,JsonNode manifest,
            List<GuardDecisionEngine.Evidence> evidence,Instant now,String family,String source,String ruleId,boolean modelAvailable) {
        boolean capability=modelAvailable&&evidence.stream().allMatch(e->GuardEligibility.profileAccepted(policy,e.observation())
                &&GuardModelRuntime.applicable(manifest,e.observation())==null);
        return GuardDecisionEngine.evaluate(policy,evidence,now,
                new GuardDecisionEngine.Gates(capability,true,true,true,null),family,source,ruleId);
    }

    public static JsonNode proof(GuardDecisionEngine.Outcome outcome) {
        return object("kind","hypothetical_evidence_readiness","decision",outcome.decision(),
                "reasonCode",outcome.reason(),"detailCode",outcome.detail(),"qualifiedEvidence",outcome.qualifiedEvidence(),
                "distinctParents",outcome.selected().stream().map(e->e.observation().path("parentConnectionId").asText()).distinct().count(),
                "excludedDeploymentGates",List.of("liveCaptureHealth","targetBinding","executionAuthorization","protectionAndBudget"),
                "actionable",false);
    }
}
