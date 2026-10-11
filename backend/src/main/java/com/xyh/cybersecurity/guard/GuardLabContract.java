package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.*;
import java.time.temporal.ChronoUnit;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** lab v1 的纯结构与时钟规则；不授予执行权，不改写观察或历史评价版本。 */
public final class GuardLabContract {
    public static final String VERSION="host-guard-lab/1.0";
    public static final String REPORT="host-guard-g3-report/1.0";
    public static final Set<String> FAMILIES=Set.of("port_scan","brute_force","dos_flood","dos_slow");
    public static final Set<String> TERMINAL=Set.of("completed","failed","cancelled","expired");
    public static final List<String> PROVENANCE=List.of("datasetSha256","splitSha256","labelRulesSha256","codeSha256",
            "modelSha256","policySha256","extractorSha256","executorSha256");
    private GuardLabContract() { }

    public static void manifest(JsonNode p) {
        fields(p,"contractVersion sessionId assetId bundleId authorizationId authorizationRevision environment runnerIdentity evidenceKind "
                +"validFrom validUntil timeoutSeconds protocolVersions subjectSha256 evaluationPlanSha256 sensorId bootId executorId executorBootId "
                +"mappingRef mappingSha256 mappingId scenarioRef scenarioSha256 provenance proofs time speed","");
        require(VERSION.equals(text(p,"contractVersion"))&&"lab".equals(text(p,"environment")),"LAB_CONTRACT_INVALID");
        for(String f:List.of("sessionId","assetId","bundleId","authorizationId","sensorId","bootId","executorId","executorBootId","mappingId"))uuid(p,f);
        require(Set.of("synthetic","lab").contains(text(p,"evidenceKind")),"LAB_CONTRACT_INVALID");
        require(text(p,"runnerIdentity").matches("[A-Za-z0-9_.:-]{1,96}"),"LAB_RUNNER_INVALID");
        integer(p,"authorizationRevision",1,Long.MAX_VALUE);integer(p,"timeoutSeconds",10,86400);integer(p,"speed",1,1);
        versions(p.get("protocolVersions"));
        for(String f:List.of("subjectSha256","evaluationPlanSha256","mappingSha256","scenarioSha256"))digest(p,f);
        text(p,"mappingRef");text(p,"scenarioRef");
        fields(p.get("provenance"),String.join(" ",PROVENANCE),"");for(String f:PROVENANCE)digest(p.get("provenance"),f);
        fields(p.get("proofs"),"p5 p6 isolation admission","");
        for(var proof:p.get("proofs")){fields(proof,"ref sha256 runnerIdentity","");text(proof,"ref");digest(proof,"sha256");text(proof,"runnerIdentity");}
        require(time(p,"validUntil").isAfter(time(p,"validFrom")),"LAB_TIME_INVALID");
        var t=p.get("time");fields(t,"sourceStart labStart offsetMicros warmupStart scoringStart scoringEnd","");
        long offset=integer(t,"offsetMicros",-9007199254740991L,9007199254740991L);
        require(time(t,"sourceStart").plus(offset,ChronoUnit.MICROS).equals(time(t,"labStart")),"LAB_OFFSET_INVALID");
        require(!time(t,"warmupStart").isBefore(time(t,"sourceStart"))&&!time(t,"scoringStart").isBefore(time(t,"warmupStart"))
                &&time(t,"scoringEnd").isAfter(time(t,"scoringStart")),"LAB_TIME_INVALID");
        require(!shift(p,time(t,"warmupStart")).isBefore(time(p,"validFrom"))
                &&shift(p,time(t,"scoringEnd")).isBefore(time(p,"validUntil")),"LAB_TIME_INVALID");
    }

    public static void scenarios(JsonNode p,JsonNode file) {
        fields(file,"contractVersion scenarios","");require(VERSION.equals(text(file,"contractVersion")),"LAB_CONTRACT_INVALID");
        var list=file.path("scenarios");require(list.isArray()&&!list.isEmpty()&&list.size()<=64,"LAB_SCENARIO_INVALID");
        Set<String> names=new HashSet<>();
        for(var s:list) {
            fields(s,"scenarioId family source ruleId trialAutoEligible autoIneligibleReason pcapRef pcapSha256 sourceStart sourceEnd","");
            require(text(s,"scenarioId").matches("[A-Za-z0-9_.-]{1,96}")&&names.add(text(s,"scenarioId")),"LAB_SCENARIO_INVALID");
            require(FAMILIES.contains(text(s,"family"))||"normal".equals(text(s,"family")),"LAB_SCENARIO_INVALID");
            String source=text(s,"source");require(Set.of("model","rule").contains(source),"LAB_SCENARIO_INVALID");
            if(source.equals("rule"))require(text(s,"ruleId").matches("[A-Za-z0-9_.-]{1,96}"),"LAB_SCENARIO_INVALID");
            else require(s.get("ruleId").isNull(),"LAB_SCENARIO_INVALID");
            boolean auto=bool(s,"trialAutoEligible");require(!auto||FAMILIES.contains(text(s,"family")),"LAB_SCENARIO_INVALID");
            if(!auto)text(s,"autoIneligibleReason");else require(s.get("autoIneligibleReason").isNull(),"LAB_SCENARIO_INVALID");
            text(s,"pcapRef");digest(s,"pcapSha256");
            require(time(s,"sourceEnd").isAfter(time(s,"sourceStart"))&&!time(s,"sourceStart").isBefore(time(p.get("time"),"scoringStart"))
                    &&!time(s,"sourceEnd").isAfter(time(p.get("time"),"scoringEnd")),"LAB_TIME_INVALID");
        }
    }

    public static void mapping(JsonNode p,JsonNode scenarios,JsonNode file) {
        fields(file,"contractVersion mappingId sessionId entries","");
        require(VERSION.equals(text(file,"contractVersion"))&&uuid(file,"mappingId").equals(text(p,"mappingId"))
                &&uuid(file,"sessionId").equals(text(p,"sessionId")),"LAB_MAPPING_MISMATCH");
        var entries=file.path("entries");require(entries.isArray()&&entries.size()==scenarios.path("scenarios").size(),"LAB_MAPPING_MISMATCH");
        Set<String> names=new HashSet<>(),targets=new HashSet<>();
        for(var e:entries) {
            fields(e,"scenarioId targetBindingId peerKey keyEpoch captureScopeId targetRef","");
            String name=text(e,"scenarioId");scenario(scenarios,name);require(names.add(name)&&targets.add(uuid(e,"targetRef")),"LAB_MAPPING_MISMATCH");
            uuid(e,"targetBindingId");uuid(e,"captureScopeId");digest(e,"peerKey");integer(e,"keyEpoch",1,9007199254740991L);
        }
    }

    public static JsonNode scenario(JsonNode file,String id) { return named(file.path("scenarios"),id); }
    public static JsonNode entry(JsonNode file,String id) { return named(file.path("entries"),id); }
    private static JsonNode named(JsonNode list,String id) {
        for(var s:list)if(id.equals(s.path("scenarioId").asText()))return s;
        throw error(422,"LAB_SCENARIO_UNKNOWN");
    }
    public static Instant shift(JsonNode p,Instant time) {return time.plus(p.path("time").path("offsetMicros").longValue(),ChronoUnit.MICROS);}
    public static String sourceKey(JsonNode s) {return s.path("family").asText()+":"+s.path("source").asText()+":"+s.path("ruleId").asText("");}
    public static boolean truth(Object v) {return Boolean.TRUE.equals(v)||(v instanceof Number n&&n.intValue()==1);}
}
