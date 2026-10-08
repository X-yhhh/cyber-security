package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 固定 T1—T9 的纯判定；输入必须由事务服务从可信事实组装，调用方不能指定审批/分数。 */
public final class GuardDecisionEngine {
    private GuardDecisionEngine(){}
    /** 单条来源证据；旧调用方未提供来源时按 model 兼容。 */
    public record Evidence(JsonNode observation,Double score,String family,String source,String ruleId,boolean ruleMatched,String contentHash){
        public Evidence(JsonNode observation,Double score,String contentHash){this(observation,score,null,"model","",false,contentHash);}
        public String effectiveFamily(JsonNode policy){return family==null||family.isBlank()?policy.path("family").asText():family;}
    }
    public record Gates(boolean capability,boolean health,boolean target,boolean authorization,String budgetReason){}
    public record Outcome(String decision,String reason,String detail,boolean qualifiedEvidence,List<Evidence> selected){}
    public static Outcome evaluate(JsonNode policy,List<Evidence> latest,Instant now,Gates gates){
        String family=latest.stream().map(e->e.effectiveFamily(policy)).findFirst().orElse(policy.path("family").asText());
        return evaluate(policy,latest,now,gates,family,"model","");
    }
    /** 每次只判定一条类别/来源/规则路径；混合输入拒绝自动化，规则 T6 使用独立命中事实。 */
    public static Outcome evaluate(JsonNode policy,List<Evidence> latest,Instant now,Gates gates,String family,String source,String ruleId){
        var chosen=latest.stream().sorted(Comparator.comparing(e->e.observation.path("observationId").asText())).toList();
        var fp=familyPolicy(policy,family);double alertThreshold=fp.path("alertThreshold").asDouble(policy.path("alertThreshold").asDouble());
        boolean alert=chosen.stream().filter(e->family.equals(e.effectiveFamily(policy))&&source.equals(e.source())&&Objects.equals(ruleId,e.ruleId())).anyMatch(e->source.equals("rule")?e.ruleMatched():e.score()!=null&&e.score()>=alertThreshold);String fallback=alert?"alert":"observe";
        if(!gates.capability||chosen.stream().anyMatch(e->!source.equals(e.source())||!Objects.equals(ruleId,e.ruleId())))return reject(fallback,"CAPABILITY_NOT_SUPPORTED",null,false,chosen);
        if(!gates.health||chosen.stream().anyMatch(e->badQuality(e.observation)))return reject(fallback,"QUALITY_UNSUPPORTED",null,false,chosen);
        if(chosen.stream().anyMatch(e->!e.observation.at("/quality/clockSkewMs").isNumber()||Math.abs(e.observation.at("/quality/clockSkewMs").asDouble())>1000))return reject(fallback,"CLOCK_UNTRUSTED",null,false,chosen);
        if(!gates.target)return reject(fallback,"TARGET_REF_STALE",null,false,chosen);
        long age=Math.min(10000,policy.path("maxEvidenceAgeMs").asLong());
        var fresh=chosen.stream().filter(e->family.equals(e.effectiveFamily(policy))).filter(e->{long ms=Duration.between(time(e.observation(),"asOf"),now).toMillis();return ms>=0&&ms<=age;}).toList();
        if(fresh.isEmpty())return reject(fallback,"EVIDENCE_STALE",null,false,chosen);
        if(!fp.path("autoEligible").asBoolean(true))return reject(fallback,"FAMILY_AUTO_DISABLED",family,false,fresh);
        // 类别可自动不代表每个来源可自动：模型来源单独由 modelAutoEligible 开启，缺失按关闭处理。
        if(source.equals("model")&&!fp.path("modelAutoEligible").asBoolean(false))return reject(fallback,"MODEL_AUTO_DISABLED",family,false,fresh);
        double autoThreshold=fp.path("autoThreshold").asDouble(policy.path("autoThreshold").asDouble());
        var scoring=fresh.stream().filter(e->e.source().equals("rule")?e.ruleMatched()&&ruleAutoEligible(policy,e):e.score()!=null&&e.score()>=autoThreshold).toList();
        if(scoring.isEmpty())return reject(fallback,"SCORE_BELOW_AUTO",null,false,fresh);
        Instant min=scoring.stream().map(e->time(e.observation(),"asOf")).min(Comparator.naturalOrder()).orElseThrow(),max=scoring.stream().map(e->time(e.observation(),"asOf")).max(Comparator.naturalOrder()).orElseThrow();
        int minFlows=fp.path("minDistinctFlows").asInt(policy.path("minDistinctFlows").asInt());
        long distinctParents=scoring.stream().map(e->e.observation().path("parentConnectionId").asText()).filter(s->!s.isBlank()).distinct().count();
        if(source.equals("model")&&(distinctParents<minFlows||Duration.between(min,max).toMillis()<policy.path("minEvidenceSpanMs").asLong()))return reject(fallback,"EVIDENCE_INSUFFICIENT",null,false,scoring);
        for(var e:scoring){JsonNode context=null;for(var c:e.observation.path("contexts"))if(c.path("windowSeconds").asInt()==policy.path("contextWindowSeconds").asInt())context=c;
            if(context==null||context.path("coverageMs").asLong()<policy.path("contextWindowSeconds").asLong()*1000||context.path("peerFlowStarts").asLong()<policy.path("minPeerFlowStarts").asLong())return reject(fallback,"CONTEXT_CONDITION_UNMET",null,false,scoring);}
        if(!gates.authorization)return reject(fallback,"AUTHORIZATION_INACTIVE",null,true,scoring);
        if(gates.budgetReason!=null)return reject(fallback,"PROTECTION_OR_BUDGET_BLOCKED",gates.budgetReason,true,scoring);
        return new Outcome("block_candidate",null,null,true,scoring);
    }
    public static JsonNode familyPolicy(JsonNode policy,String family){for(JsonNode p:policy.path("familyPolicies"))if(Objects.equals(family,p.path("family").asText()))return p;return policy;}
    private static boolean ruleAutoEligible(JsonNode policy,Evidence e){for(JsonNode p:policy.path("rulePolicies"))if(e.ruleId()!=null&&e.ruleId().equals(p.path("ruleId").asText()))return p.path("autoEligible").asBoolean(false);return false;}
    public static boolean badQuality(JsonNode o){for(String k:List.of("captureGap","latePacket","truncated","offloadSuspected","capacityDrop"))if(o.path("quality").path(k).asBoolean())return true;return false;}
    private static Outcome reject(String decision,String reason,String detail,boolean qualified,List<Evidence> evidence){return new Outcome(decision,reason,detail,qualified,evidence);}
}
