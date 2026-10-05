package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 固定 T1—T9 的纯判定；输入必须由事务服务从可信事实组装，调用方不能指定审批/分数。 */
public final class GuardDecisionEngine {
    private GuardDecisionEngine(){}
    public record Evidence(JsonNode observation,Double score,String contentHash){}
    public record Gates(boolean capability,boolean health,boolean target,boolean authorization,String budgetReason){}
    public record Outcome(String decision,String reason,String detail,boolean qualifiedEvidence,List<Evidence> selected){}
    public static Outcome evaluate(JsonNode policy,List<Evidence> latest,Instant now,Gates gates){
        var chosen=latest.stream().sorted(Comparator.comparing(e->e.observation.path("observationId").asText())).toList();
        boolean alert=chosen.stream().anyMatch(e->e.score!=null&&e.score>=policy.path("alertThreshold").asDouble());String fallback=alert?"alert":"observe";
        if(!gates.capability)return reject(fallback,"CAPABILITY_NOT_SUPPORTED",null,false,chosen);
        if(!gates.health||chosen.stream().anyMatch(e->badQuality(e.observation)))return reject(fallback,"QUALITY_UNSUPPORTED",null,false,chosen);
        if(chosen.stream().anyMatch(e->!e.observation.at("/quality/clockSkewMs").isNumber()||Math.abs(e.observation.at("/quality/clockSkewMs").asDouble())>1000))return reject(fallback,"CLOCK_UNTRUSTED",null,false,chosen);
        if(!gates.target)return reject(fallback,"TARGET_REF_STALE",null,false,chosen);
        long age=Math.min(10000,policy.path("maxEvidenceAgeMs").asLong());
        var fresh=chosen.stream().filter(e->{long ms=Duration.between(time(e.observation,"asOf"),now).toMillis();return ms>=0&&ms<=age;}).toList();
        if(fresh.isEmpty())return reject(fallback,"EVIDENCE_STALE",null,false,chosen);
        var scoring=fresh.stream().filter(e->e.score!=null&&e.score>=policy.path("autoThreshold").asDouble()).toList();
        if(scoring.isEmpty())return reject(fallback,"SCORE_BELOW_AUTO",null,false,fresh);
        Instant min=scoring.stream().map(e->time(e.observation,"asOf")).min(Comparator.naturalOrder()).orElseThrow(),max=scoring.stream().map(e->time(e.observation,"asOf")).max(Comparator.naturalOrder()).orElseThrow();
        if(scoring.size()<policy.path("minDistinctFlows").asInt()||Duration.between(min,max).toMillis()<policy.path("minEvidenceSpanMs").asLong())return reject(fallback,"EVIDENCE_INSUFFICIENT",null,false,scoring);
        for(var e:scoring){JsonNode context=null;for(var c:e.observation.path("contexts"))if(c.path("windowSeconds").asInt()==policy.path("contextWindowSeconds").asInt())context=c;
            if(context==null||context.path("coverageMs").asLong()<policy.path("contextWindowSeconds").asLong()*1000||context.path("peerFlowStarts").asLong()<policy.path("minPeerFlowStarts").asLong())return reject(fallback,"CONTEXT_CONDITION_UNMET",null,false,scoring);}
        if(!gates.authorization)return reject(fallback,"AUTHORIZATION_INACTIVE",null,true,scoring);
        if(gates.budgetReason!=null)return reject(fallback,"PROTECTION_OR_BUDGET_BLOCKED",gates.budgetReason,true,scoring);
        return new Outcome("block_candidate",null,null,true,scoring);
    }
    public static boolean badQuality(JsonNode o){for(String k:List.of("captureGap","latePacket","truncated","offloadSuspected","capacityDrop"))if(o.path("quality").path(k).asBoolean())return true;return false;}
    private static Outcome reject(String decision,String reason,String detail,boolean qualified,List<Evidence> evidence){return new Outcome(decision,reason,detail,qualified,evidence);}
}
