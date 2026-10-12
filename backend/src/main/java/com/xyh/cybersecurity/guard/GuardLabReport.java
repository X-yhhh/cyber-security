package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.guard.GuardLabContract.*;

/** G3 纯报告计算，与 Python 工具使用同一输入及对拍向量；时延只报告，不创造新门槛。 */
public final class GuardLabReport {
    private GuardLabReport() { }
    public static JsonNode generate(JsonNode input) {
        fields(input,"contractVersion session sessionSha256 runStatus scenarios events unlinkedCommandIds unlinkedDecisionIds outsideScoringDecisionIds","");
        var p=input.path("session");manifest(p);
        require(Set.of(VERSION_1_0,VERSION_1_1).contains(text(input,"contractVersion"))
                &&text(input,"contractVersion").equals(text(p,"contractVersion"))&&hash(p).equals(text(input,"sessionSha256")),"LAB_REPORT_MISMATCH");
        require(input.path("scenarios").isArray()&&input.path("events").isArray()&&input.path("unlinkedCommandIds").isArray()&&input.path("unlinkedDecisionIds").isArray()&&input.path("outsideScoringDecisionIds").isArray(),"LAB_REPORT_MISMATCH");
        for(String f:List.of("unlinkedCommandIds","unlinkedDecisionIds","outsideScoringDecisionIds"))for(var v:input.path(f))require(v.isTextual(),"LAB_REPORT_MISMATCH");
        var rows=new ArrayList<JsonNode>();var represented=new HashSet<String>();var normalCommands=new HashSet<String>();var normalExpired=new HashSet<String>();
        var intervals=new ArrayList<List<Instant>>();long normalMs=0;boolean uncertain=!input.path("unlinkedCommandIds").isEmpty()||!input.path("unlinkedDecisionIds").isEmpty();
        boolean failed=false,notEvaluated=false;
        for(var s:input.path("scenarios")) {
            String sid=text(s,"scenarioId"),family=text(s,"family");boolean normal=family.equals("normal");
            var events=new ArrayList<JsonNode>();for(var e:input.path("events"))if(sid.equals(e.path("scenarioId").asText()))events.add(e);
            boolean complete=events.stream().anyMatch(e->"scenario_result".equals(e.path("kind").asText())&&e.path("completed").asBoolean());
            Instant start=shift(p,sid,time(s,"sourceStart")),end=shift(p,sid,time(s,"sourceEnd"));
            Instant alert=first(events,e->"decision".equals(e.path("kind").asText())&&Set.of("alert","block_candidate").contains(e.path("decision").asText()));
            for(var e:events)if(e.path("decisionAt").isTextual()&&Set.of("alert","block_candidate").contains(e.path("decision").asText()))alert=min(alert,time(e,"decisionAt"));
            var ids=new TreeSet<String>();for(var e:events)if(e.path("commandId").isTextual())ids.add(text(e,"commandId"));
            var commands=new ArrayList<JsonNode>();boolean cleanupMissing=false,unknownInstall=false,hasApplied=false;
            Instant firstApplied=null,finalCleared=null,firstIssued=null;
            for(String id:ids) {
                var ce=events.stream().filter(e->id.equals(e.path("commandId").asText())).toList();
                Instant issued=first(ce,e->"command".equals(e.path("kind").asText()));
                for(var e:ce)if(e.path("issuedAt").isTextual())issued=min(issued,time(e,"issuedAt"));
                if(issued!=null)firstIssued=min(firstIssued,issued);
                Instant applied=first(ce,e->verified(e,"applied"));
                Instant cleared=first(ce,e->verified(e,"expired")||verified(e,"revoked")||verified(e,"rejected"));
                boolean rejected=ce.stream().anyMatch(e->verified(e,"rejected"));
                if(applied!=null){hasApplied=true;firstApplied=min(firstApplied,applied);if(normal)normalCommands.add(id);}
                if(normal&&ce.stream().anyMatch(e->verified(e,"expired")))normalExpired.add(id);
                if(cleared==null||issued==null)cleanupMissing=true;
                if(applied==null&&!rejected)unknownInstall=true;
                if(cleared!=null)finalCleared=max(finalCleared,cleared);
                if((issued!=null&&applied!=null&&applied.isBefore(issued))||(applied!=null&&cleared!=null&&cleared.isBefore(applied)))cleanupMissing=true;
                commands.add(object("commandId",id,"issuedAt",iso(issued),"appliedAt",iso(applied),"clearedAt",iso(cleared),
                        "installation",applied!=null?"verified":rejected?"rejected":"unverified","cleanup",cleared==null?"unverified":"verified"));
            }
            JsonNode q=s.path("quality");long count=integer(q,"snapshots",0,100000),qualified=integer(q,"qualified",0,count);
            integer(q,"offloadSuspected",0,count);integer(q,"unknown",0,count);integer(q,"indeterminate",0,count);
            long executable=integer(q,"executionQualified",0,qualified);
            boolean qualityUnknown=count==0;
            boolean qualityBlocks=s.path("trialAutoEligible").asBoolean()&&executable==0;
            String status;
            if(cleanupMissing||unknownInstall||qualityUnknown)status="unverified";
            else if(!complete)status="not_evaluated";
            else if(!normal&&(alert==null||(s.path("trialAutoEligible").asBoolean()&&!hasApplied)||qualityBlocks))status="failed";
            else status="passed";
            if(!normal)represented.add(family);
            if(normal&&complete){long ms=Duration.between(start,end).toMillis();normalMs+=ms;intervals.add(List.of(start,end));}
            var reasons=new TreeSet<String>();for(var e:events)if(e.path("reasonCode").isTextual())reasons.add(text(e,"reasonCode"));
            var missing=new ArrayList<String>();if(!complete)missing.add("scenario_result");if(!normal&&alert==null)missing.add("qualified_alert");
            if(s.path("trialAutoEligible").asBoolean()&&!hasApplied)missing.add("verified_application");
            if(qualityBlocks)missing.add("executable_observation");
            if(cleanupMissing)missing.add("verified_cleanup");if(unknownInstall)missing.add("installation_history");if(qualityUnknown)missing.add("quality_population");
            rows.add(object("scenarioId",sid,"family",family,"source",s.get("source"),"ruleId",s.get("ruleId"),"trialAutoEligible",s.get("trialAutoEligible"),
                    "autoIneligibleReason",s.get("autoIneligibleReason"),"status",status,"completed",complete,"originalStart",text(s,"sourceStart"),
                    "labStart",start.toString(),"firstAlertAt",iso(alert),"firstIssuedAt",iso(firstIssued),"firstAppliedAt",iso(firstApplied),"lastClearedAt",iso(finalCleared),
                    "alertLatencyMs",millis(start,alert),"issueLatencyMs",millis(start,firstIssued),"applicationLatencyMs",millis(start,firstApplied),
                    "cleanupLatencyMs",millis(start,finalCleared),"commands",commands,"quality",q,
                    "qualifiedCoverage",count==0?null:(double)qualified/count,
                    "executionQualifiedCoverage",count==0?null:(double)executable/count,
                    "missing",missing,"rejectionReasons",reasons));
            uncertain|=status.equals("unverified");failed|=status.equals("failed");notEvaluated|=status.equals("not_evaluated");
        }
        var missingClasses=new TreeSet<>(FAMILIES);missingClasses.removeAll(represented);notEvaluated|=!missingClasses.isEmpty();
        long unionMs=union(intervals);long falseBlocks=normalCommands.size();
        boolean ttlRestored=normalExpired.containsAll(normalCommands);
        boolean normalPassed=normalMs>=1800000&&falseBlocks*3600000<=normalMs&&ttlRestored;
        if(normalMs>0&&!normalPassed)failed=true;else if(normalMs==0)notEvaluated=true;
        if(!"completed".equals(input.path("runStatus").asText()))notEvaluated=true;
        String computed=failed?"failed":uncertain?"unverified":notEvaluated?"not_evaluated":"passed";
        String status="synthetic".equals(text(p,"evidenceKind"))?"unverified":computed;
        // 第 9 节逐类结果：四个攻击类各一行（按名称排序），状态取该类场景的最差结果；无场景即 not_evaluated。
        var classes=new ArrayList<JsonNode>();
        for(String family:new TreeSet<>(FAMILIES)) {
            var ids=new ArrayList<String>();var sources=new TreeSet<String>();var statuses=new HashSet<String>();
            boolean auto=false;Long alertMs=null,applyMs=null;
            for(var r:rows) {
                if(!family.equals(r.path("family").asText()))continue;
                ids.add(r.path("scenarioId").asText());statuses.add(r.path("status").asText());auto|=r.path("trialAutoEligible").asBoolean();
                sources.add("rule".equals(r.path("source").asText())?"rule:"+r.path("ruleId").asText():"model");
                alertMs=minMs(alertMs,r.path("alertLatencyMs"));applyMs=minMs(applyMs,r.path("applicationLatencyMs"));
            }
            classes.add(object("family",family,"scenarioIds",ids,"sources",sources,"status",aggregate(statuses),"trialAutoEligible",auto,
                    "firstAlertLatencyMs",alertMs,"firstApplicationLatencyMs",applyMs));
        }
        // 第 9 节未验证项：只汇总已计算的缺口，顺序固定以便与 Python 工具逐字节对拍。
        var unverifiedItems=new ArrayList<String>();
        for(var r:rows)for(var m:r.path("missing"))unverifiedItems.add("scenario:"+r.path("scenarioId").asText()+":"+m.asText());
        for(String c:missingClasses)unverifiedItems.add("class:"+c+":no_scenario");
        for(var c:input.path("unlinkedCommandIds"))unverifiedItems.add("command:"+c.asText()+":unlinked");
        for(var d:input.path("unlinkedDecisionIds"))unverifiedItems.add("decision:"+d.asText()+":unlinked");
        if(normalMs==0)unverifiedItems.add("normal:not_evaluated");
        if(!"completed".equals(input.path("runStatus").asText()))unverifiedItems.add("run:"+input.path("runStatus").asText());
        if("synthetic".equals(text(p,"evidenceKind")))unverifiedItems.add("evidence:synthetic");
        return object("reportVersion",REPORT,"runKind","canary","protocolVersions",p.get("protocolVersions"),"subjectSha256",p.get("subjectSha256"),
                "evaluationPlanSha256",p.get("evaluationPlanSha256"),"sessionId",p.get("sessionId"),"sessionSha256",input.get("sessionSha256"),
                "inputSha256",hash(input),"evidenceKind",p.get("evidenceKind"),"runStatus",input.get("runStatus"),"provenance",p.get("provenance"),
                "mappingSha256",p.get("mappingSha256"),"scenarioSha256",p.get("scenarioSha256"),"time",p.get("time"),"scenarios",rows,
                "classes",classes,"unverifiedItems",unverifiedItems,
                "missingClasses",missingClasses,"unlinkedCommandIds",input.get("unlinkedCommandIds"),"unlinkedDecisionIds",input.get("unlinkedDecisionIds"),"normal",object("cumulativeMs",normalMs,
                        "singleAssetUnionMs",unionMs,"verifiedFalseBlocks",falseBlocks,"perHour",normalMs==0?null:(double)falseBlocks*3600000/normalMs,
                        "falseBlocksTtlRestored",ttlRestored,"passed",normalPassed),
                "outsideScoringDecisionIds",input.get("outsideScoringDecisionIds"),
                "computedStatus",computed,"status",status,"passed",status.equals("passed"),"latencyIsReportOnly",true,
                "limitations",List.of("L3 slow attacks detected 0/29; difficult benign false alerts 0/42; historical results unchanged",
                        "L2 not evaluated; L1 shares dataset and tools across splits", "Cumulative concurrent scenario time is not continuous single-host time",
                        "No class qualification, release approval or activation is granted by this report"));
    }
    private static boolean verified(JsonNode e,String status) {return "verified_receipt".equals(e.path("kind").asText())&&"verified".equals(e.path("verification").asText())&&status.equals(e.path("status").asText());}
    /** 取已有毫秒值与新节点的较小者；null/非数值节点表示该场景没有此时刻，不参与比较。 */
    private static Long minMs(Long current,JsonNode value) {
        if(!value.isIntegralNumber())return current;
        long candidate=value.longValue();
        if(current==null||candidate<current)return candidate;
        return current;
    }
    /** 类别状态取最差：failed > unverified > not_evaluated > passed，与整体状态优先级一致。 */
    private static String aggregate(Set<String> statuses) {
        if(statuses.isEmpty())return "not_evaluated";
        if(statuses.contains("failed"))return "failed";
        if(statuses.contains("unverified"))return "unverified";
        if(statuses.contains("not_evaluated"))return "not_evaluated";
        return "passed";
    }
    private static Instant first(List<JsonNode> events,java.util.function.Predicate<JsonNode> test) {return events.stream().filter(test).filter(e->e.path("occurredAt").isTextual()).map(e->time(e,"occurredAt")).min(Comparator.naturalOrder()).orElse(null);}
    private static Instant min(Instant a,Instant b) {return a==null||b.isBefore(a)?b:a;}
    private static Instant max(Instant a,Instant b) {return a==null||b.isAfter(a)?b:a;}
    private static String iso(Instant t) {return t==null?null:t.toString();}
    private static Long millis(Instant a,Instant b) {return b==null?null:Duration.between(a,b).toMillis();}
    private static long union(List<List<Instant>> spans) {
        spans.sort(Comparator.comparing(s->s.getFirst()));long result=0;Instant start=null,end=null;
        for(var span:spans)if(start==null){start=span.getFirst();end=span.getLast();}
        else if(!span.getFirst().isAfter(end))end=max(end,span.getLast());
        else {result+=Duration.between(start,end).toMillis();start=span.getFirst();end=span.getLast();}
        return result+(start==null?0:Duration.between(start,end).toMillis());
    }
}
