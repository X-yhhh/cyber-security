package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.guard.GuardLabContract.*;

/** 把既有后端事实适配为 lab 时间线；调用方不能传入成功标志或伪造执行时间。 */
@Service
public class GuardLabFacts {
    private final GuardStore store;
    private final GuardArtifacts artifacts;
    private final GuardSignatures signatures;
    private final GuardLabMapper mapper;
    public GuardLabFacts(GuardStore store,GuardArtifacts artifacts,GuardSignatures signatures,GuardLabMapper mapper) {
        this.store=store;this.artifacts=artifacts;this.signatures=signatures;this.mapper=mapper;
    }

    public ObjectNode resolve(JsonNode p,JsonNode scenario,JsonNode mapping,JsonNode request) {
        String kind=text(request,"kind");
        var out=object("scenarioId",text(scenario,"scenarioId"),"family",text(scenario,"family"),"source",text(scenario,"source"),
                "ruleId",scenario.get("ruleId"),"kind",kind,"verification","verified","occurredAt",null,"reasonCode",null);
        if(kind.equals("scenario_result")) {
            fields(request,"eventId scenarioId kind reportRef sha256","");
            var proof=signatures.report(artifacts.json(text(request,"reportRef"),digest(request,"sha256")),text(p,"runnerIdentity"));
            fields(proof,"contractVersion sessionId sessionSha256 scenarioId mappingSha256 startedAt endedAt completed","");
            require(VERSION.equals(text(proof,"contractVersion"))&&p.path("sessionId").equals(proof.path("sessionId"))
                    &&hash(p).equals(text(proof,"sessionSha256"))&&scenario.path("scenarioId").equals(proof.path("scenarioId"))
                    &&p.path("mappingSha256").equals(proof.path("mappingSha256")),"LAB_RESULT_MISMATCH");
            Instant from=time(proof,"startedAt"),until=time(proof,"endedAt");
            require(!until.isAfter(store.now())&&!from.isAfter(until)&&!from.isBefore(time(p,"validFrom"))
                    &&!until.isAfter(time(p,"validUntil")),"LAB_TIME_INVALID");
            boolean complete=bool(proof,"completed");
            if(complete)require(!from.isAfter(shift(p,time(scenario,"sourceStart")))
                    &&!until.isBefore(shift(p,time(scenario,"sourceEnd"))),"LAB_RESULT_INCOMPLETE");
            out.put("occurredAt",until.toString());out.put("completed",complete);out.put("startedAt",from.toString());out.put("endedAt",until.toString());
            out.put("reportSha256",text(request,"sha256"));return out;
        }
        fields(request,"eventId scenarioId kind referenceId","");String ref=uuid(request,"referenceId");
        out.put("referenceId",ref);
        switch(kind) {
            case "observation" -> {
                var o=store.external("guard_observation",ref,false);observation(p,scenario,mapping,o);
                out.put("observationId",ref);out.put("occurredAt",instant(o.get("as_of")).toString());
            }
            case "decision" -> decision(p,scenario,mapping,store.external("guard_decision",ref,false),out);
            case "command" -> command(p,scenario,mapping,store.external("guard_command",ref,false),out);
            case "receipt", "verified_receipt" -> {
                var r=store.external("guard_action_receipt",ref,false);var c=store.get("guard_command",number(r,"command_id"));
                command(p,scenario,mapping,c,out);out.put("kind",kind);out.put("receiptId",ref);
                var executor=store.external("guard_executor",text(p,"executorId"),false);
                require(number(r,"executor_id")==number(executor,"id"),"LAB_FACT_MISMATCH");
                out.put("status",str(r,"status"));out.put("occurredAt",instant(r.get("observed_at")).toString());
                out.set("reasonCode",json(r,"payload_json").path("errorCode"));
                out.put("verification","unverified");
                if(kind.equals("verified_receipt")) {
                    require(truth(r.get("projected")),"LAB_RECEIPT_UNVERIFIED");
                    var rec=store.one("guard_reconciliation",map("executor_id",executor.get("id"),"owned_state_sha256",r.get("state_digest"),"boot_id",text(p,"executorBootId")),false);
                    require(rec!=null&&number(rec,"error_count")==0&&!instant(rec.get("observed_at")).isBefore(instant(r.get("observed_at"))),"LAB_RECEIPT_UNVERIFIED");
                    out.put("verification","verified");out.put("occurredAt",instant(rec.get("observed_at")).toString());
                    out.put("reconciliationId",str(rec,"public_id"));out.put("stateDigest",str(r,"state_digest"));
                }
            }
            default -> throw error(422,"LAB_EVENT_KIND_INVALID");
        }
        require(!time(out,"occurredAt").isAfter(store.now()),"LAB_TIME_INVALID");return out;
    }

    private void observation(JsonNode p,JsonNode scenario,JsonNode mapping,Map<String,Object> row) {
        var o=json(row,"payload_json");
        identity(p,mapping,o);
        lease(p,mapping,text(o,"targetRef"),instant(row.get("as_of")));
        Instant at=instant(row.get("as_of"));
        require(!at.isBefore(shift(p,time(scenario,"sourceStart")))&&!at.isAfter(shift(p,time(scenario,"sourceEnd"))),"LAB_FACT_MISMATCH");
        require(hash(o).equals(str(row,"content_sha256")),"LAB_FACT_DIGEST_INVALID");
    }

    private void decision(JsonNode p,JsonNode scenario,JsonNode mapping,Map<String,Object> row,ObjectNode out) {
        var proof=json(row,"evidence_json");
        require(text(p,"bundleId").equals(text(proof,"bundleId"))&&text(p,"subjectSha256").equals(text(proof,"bundleSubjectSha256"))
                &&"lab".equals(proof.path("environment").asText())&&hash(proof).equals(str(row,"evidence_sha256")),"LAB_FACT_MISMATCH");
        // 正常场景允许记录误报的任一攻击来源；攻击场景必须匹配登记的来源及类别。
        if(!"normal".equals(scenario.path("family").asText()))for(String f:List.of("family","source","ruleId"))
            require(scenario.path(f).equals(proof.path(f)),"LAB_FACT_MISMATCH");
        var trigger=store.external("guard_observation",uuid(proof,"triggerObservationId"),false);observation(p,scenario,mapping,trigger);
        for(var selected:proof.path("selectedObservations"))observation(p,scenario,mapping,store.external("guard_observation",uuid(selected,"observationId"),false));
        out.put("decisionId",str(row,"public_id"));out.put("observationId",str(trigger,"public_id"));
        out.put("decision",str(row,"decision"));out.put("reasonCode",str(row,"reason_code"));
        out.put("occurredAt",instant(row.get("decided_at")).toString());
        out.put("decisionAt",instant(row.get("decided_at")).toString());
        out.set("source",proof.path("source"));out.set("ruleId",proof.path("ruleId"));out.set("detectedFamily",proof.path("family"));
    }

    private void command(JsonNode p,JsonNode scenario,JsonNode mapping,Map<String,Object> c,ObjectNode out) {
        var a=store.get("guard_action",number(c,"action_id"));
        decision(p,scenario,mapping,store.get("guard_decision",number(a,"decision_id")),out);
        var cmd=json(c,"payload_json");
        require(text(p,"executorBootId").equals(str(c,"executor_boot_id"))
                &&text(p,"executorId").equals(cmd.path("executorId").asText())
                &&text(p,"authorizationId").equals(cmd.path("authorizationId").asText())
                &&p.path("authorizationRevision").asLong()==cmd.path("authorizationRevision").asLong()
                &&hash(cmd).equals(str(c,"payload_sha256")),"LAB_FACT_MISMATCH");
        lease(p,mapping,text(cmd,"targetRef"),instant(c.get("issued_at")));
        out.put("commandId",str(c,"public_id"));out.put("actionId",str(a,"public_id"));
        out.put("occurredAt",instant(c.get("issued_at")).toString());out.put("blockUntil",instant(a.get("block_until")).toString());
        out.put("issuedAt",instant(c.get("issued_at")).toString());
    }

    /**
     * 采集质量与可执行性分别计数：空/过期引用不删样本，也不补造租约。
     * 时效基于不可变入库时间，不能拿生成报告的当前时间把全部历史样本判过期。
     * warmup/评分窗外数据单列，只有评分窗内合格且引用、时效有效的观察计入 executionQualified。
     */
    public JsonNode quality(JsonNode p,JsonNode scenario,JsonNode mapping,long asset,long sensor) {
        var rows=mapper.observations(map("asset",asset,"sensor",sensor,"boot",text(p,"bootId"),"peer",text(mapping,"peerKey"),"epoch",mapping.path("keyEpoch").longValue(),
                "start",db(shift(p,time(p.path("time"),"warmupStart"))),"end",db(shift(p,time(p.path("time"),"scoringEnd")))));
        require(rows.size()<=100000,"LAB_REPORT_TOO_LARGE");
        QualityCounts scoring=new QualityCounts(),outside=new QualityCounts();
        Instant start=shift(p,time(scenario,"sourceStart")),end=shift(p,time(scenario,"sourceEnd"));
        Map<String,Map<String,Object>> leases=new HashMap<>();
        for(var row:rows) {
            JsonNode o=json(row,"payload_json"),q=o.path("quality");boolean known=true,good=true;
            identity(p,mapping,o);
            for(String f:List.of("captureGap","latePacket","truncated","offloadSuspected","capacityDrop")) {known&=q.path(f).isBoolean();good&=q.path(f).isBoolean()&&!q.path(f).asBoolean();}
            known&=q.path("clockSkewMs").isNumber();good&=q.path("clockSkewMs").isNumber()&&Math.abs(q.path("clockSkewMs").doubleValue())<=1000;
            Instant at=time(o,"asOf"),received=instant(row.get("created_at"));
            boolean inWindow=!at.isBefore(start)&&!at.isAfter(end);
            boolean invalidTime=received==null||(received!=null&&received.isBefore(at));
            boolean stale=received!=null&&Duration.between(at,received).toMillis()>10000;
            boolean missing=o.path("targetRef").isNull()||o.path("targetRef").isMissingNode(),expired=false;
            if(!missing) {
                String ref=uuid(o,"targetRef");
                var binding=leases.computeIfAbsent(ref,key->leaseIdentity(p,mapping,key));
                Instant actualUntil=instant(binding.get("expires_at"));
                if(!o.path("targetExpiresAt").isTextual())invalidTime=true;
                else {
                    Instant claimedUntil=time(o,"targetExpiresAt");
                    expired=!actualUntil.isAfter(at)||!claimedUntil.isAfter(at)
                            ||received!=null&&(!actualUntil.isAfter(received)||!claimedUntil.isAfter(received));
                }
            }
            (inWindow?scoring:outside).add(good,known,q.path("offloadSuspected").asBoolean(),missing,expired,stale,invalidTime,inWindow);
        }
        var result=scoring.json();result.set("outsideScoringWindow",outside.json());return result;
    }

    private static void identity(JsonNode p,JsonNode mapping,JsonNode o) {
        for(String f:List.of("assetId","sensorId","bootId","environment"))require(p.path(f).equals(o.path(f)),"LAB_FACT_MISMATCH");
        for(String f:List.of("peerKey","keyEpoch","captureScopeId"))require(mapping.path(f).equals(o.path(f)),"LAB_FACT_MISMATCH");
    }

    private static final class QualityCounts {
        int snapshots,qualified,offload,unknown,executionQualified,missing,expired,stale,invalidTime;
        void add(boolean good,boolean known,boolean offloadFlag,boolean missingRef,boolean expiredRef,boolean staleEvidence,boolean invalidTiming,boolean inWindow) {
            snapshots++;if(good)qualified++;if(!known)unknown++;if(offloadFlag)offload++;
            if(missingRef)missing++;if(expiredRef)expired++;if(staleEvidence)stale++;if(invalidTiming)invalidTime++;
            if(inWindow&&good&&!missingRef&&!expiredRef&&!staleEvidence&&!invalidTiming)executionQualified++;
        }
        ObjectNode json() {return object("snapshots",snapshots,"qualified",qualified,"offloadSuspected",offload,"unknown",unknown,"indeterminate",snapshots-qualified,
                "executionQualified",executionQualified,"nonExecutable",snapshots-executionQualified,"missingTargetRef",missing,"expiredTargetRef",expired,
                "staleEvidence",stale,"invalidTiming",invalidTime);}
    }

    /** 每个实际引用仍校验短租约；允许续租换 targetRef，不允许换稳定目标、boot 或协议作用域。 */
    private void lease(JsonNode p,JsonNode mapping,String ref,Instant at) {
        var actual=leaseIdentity(p,mapping,ref);
        require(instant(actual.get("expires_at")).isAfter(at),"LAB_LEASE_MISMATCH");
    }

    private Map<String,Object> leaseIdentity(JsonNode p,JsonNode mapping,String ref) {
        var initial=store.external("guard_target_binding",text(mapping,"targetBindingId"),false);
        var actual=store.one("guard_target_binding",map("target_ref",uuid(ref)),false);
        require(actual!=null&&Objects.equals(actual.get("budget_target_id"),initial.get("budget_target_id"))
                &&Objects.equals(actual.get("scope_digest"),initial.get("scope_digest"))
                &&Objects.equals(actual.get("sensor_id"),initial.get("sensor_id"))&&Objects.equals(actual.get("executor_id"),initial.get("executor_id"))
                &&text(p,"bootId").equals(str(actual,"collector_boot_id"))&&text(p,"executorBootId").equals(str(actual,"executor_boot_id")),"LAB_LEASE_MISMATCH");
        return actual;
    }
}
