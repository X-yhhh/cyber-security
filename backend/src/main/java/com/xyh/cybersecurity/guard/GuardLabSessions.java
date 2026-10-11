package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.guard.GuardLabContract.*;

/** lab 会话应用服务。事务固定先锁资产再锁资格和运行行；所有执行操作仍由原 T1—T9 路径负责。 */
@Service
public class GuardLabSessions {
    private final GuardStore store;
    private final GuardAccess access;
    private final GuardLabMapper mapper;
    private final GuardLabAdmission admission;
    private final GuardLabFacts facts;
    private final GuardArtifacts artifacts;
    private final GuardSignatures signatures;
    public GuardLabSessions(GuardStore store,GuardAccess access,GuardLabMapper mapper,GuardLabAdmission admission,
                            GuardLabFacts facts,GuardArtifacts artifacts,GuardSignatures signatures) {
        this.store=store;this.access=access;this.mapper=mapper;this.admission=admission;this.facts=facts;this.artifacts=artifacts;this.signatures=signatures;
    }

    public void authorizeCreate(JsonNode b) {
        access.human();fields(b,"sessionRef sha256 runnerIdentity","");
        JsonNode p=signatures.report(artifacts.json(text(b,"sessionRef"),digest(b,"sha256")),text(b,"runnerIdentity"));
        var asset=store.external("asset",uuid(p,"assetId"),false);access.permission("evaluation.run",number(asset,"id"));
    }
    public void authorize(String id,String operation) {
        var row=store.external("guard_validation_session",uuid(id),false);
        String permission=switch(operation) {
            case "decisions" -> "authorization.approve";
            case "revocations" -> "automation.stop";
            case "starts","interruptions","resumptions","completions","reconciliations","events","reports" -> "evaluation.run";
            default -> throw error(404,"RESOURCE_NOT_FOUND");
        };
        access.permission(permission,number(row,"asset_id"));
        // 幂等缓存只重放响应，不可让已撤销/过期的资格看起来仍允许运行。
        if(Set.of("starts","resumptions").contains(operation)) {
            var run=mapper.run(number(row,"id"));require(run!=null&&"active".equals(str(row,"status")),"AUTHORIZATION_INACTIVE");
            var p=json(run,"manifest_jcs");var a=store.get("asset_authorization",number(row,"authorization_id"));var now=store.now();
            require("active".equals(str(a,"status"))&&number(a,"revision")==p.path("authorizationRevision").asLong()
                    &&!now.isBefore(time(p,"validFrom"))&&now.isBefore(time(p,"validUntil"))
                    &&!now.isBefore(instant(a.get("valid_from")))&&now.isBefore(instant(a.get("valid_until"))),"AUTHORIZATION_INACTIVE");
        }
    }

    @Transactional
    public JsonNode create(JsonNode b) {
        authorizeCreate(b);var in=admission.read(text(b,"sessionRef"),text(b,"sha256"),text(b,"runnerIdentity"));
        var p=in.manifest();long aid=number(in.asset(),"id");store.lockAsset(aid);
        var old=store.one("guard_validation_session",map("public_id",text(p,"sessionId")),true);
        if(old!=null) {
            if(!hash(p).equals(str(old,"content_sha256")))throw error(409,"IDEMPOTENCY_CONFLICT");
            return view(old,mapper.run(number(old,"id")));
        }
        if(mapper.owner(number(in.sensor(),"id"),text(p,"bootId"))!=null)throw error(409,"LAB_SENSOR_ALREADY_BOUND");
        var row=store.insert("guard_validation_session",map("public_id",text(p,"sessionId"),"asset_id",aid,
                "bundle_id",in.bundle().get("id"),"authorization_id",in.authorization().get("id"),"requested_by",access.human(),
                "payload_json",canonical(p),"content_sha256",hash(p),"valid_until",db(time(p,"validUntil"))));
        mapper.insertRun(map("session",row.get("id"),"sensor",in.sensor().get("id"),"boot",text(p,"bootId"),"ref",text(b,"sessionRef"),"sha",text(b,"sha256"),
                "manifest",canonical(p),"scenarios",canonical(in.scenarios()),"mapping",canonical(in.mapping())));
        row=store.external("guard_validation_session",text(p,"sessionId"),true);
        lifecycle(row,"created",null);return view(row,mapper.run(number(row,"id")));
    }

    @Transactional
    public JsonNode operate(String id,String operation,JsonNode b,String revision) {
        authorize(id,operation);var row=store.external("guard_validation_session",id,false);store.lockAsset(number(row,"asset_id"));
        row=store.external("guard_validation_session",id,true);access.revision(row,revision);
        var run=mapper.lock(number(row,"id"));require(run!=null,"LAB_SESSION_UNAVAILABLE");
        var p=json(run,"manifest_jcs");String state=str(run,"status");Instant now=store.now();
        switch(operation) {
            case "events" -> {return event(row,run,b);}
            case "reports" -> {return report(row,run,b);}
            case "decisions" -> {
                GuardAdministration.decisionBody(b);access.different(row,"requested_by");require("pending".equals(str(row,"status")),"STATE_CONFLICT");
                boolean approve="approve".equals(text(b,"decision"));
                if(approve)recheck(run,p);
                store.update("guard_validation_session",number(row,"id"),map("status",approve?"active":"revoked","approved_by",access.human()));
                row.put("status",approve?"active":"revoked");
                if(!approve){run.put("status","cancelled");run.put("ended_at",db(now));run.put("stop_requested_at",db(now));}
            }
            case "starts","resumptions" -> {
                fields(b,"","");require((operation.equals("starts")?"registered":"interrupted").equals(state)&&"active".equals(str(row,"status")),"STATE_CONFLICT");
                recheck(run,p);require(!now.isBefore(time(p,"validFrom")),"AUTHORIZATION_INACTIVE");
                if(operation.equals("starts")) {
                    require(!now.isAfter(shift(p,time(p.path("time"),"warmupStart"))),"LAB_START_TOO_LATE");run.put("started_at",db(now));
                }
                run.put("status","running");run.put("last_activity_at",db(now));
            }
            case "interruptions" -> {
                fields(b,"reason","");text(b,"reason");require("running".equals(state),"STATE_CONFLICT");run.put("status","interrupted");
            }
            case "completions" -> {
                fields(b,"outcome reason","");text(b,"reason");String outcome=text(b,"outcome");
                require(Set.of("completed","failed").contains(outcome)&&Set.of("running","interrupted").contains(state),"STATE_CONFLICT");
                if(outcome.equals("completed"))require(now.isBefore(time(p,"validUntil"))&&"active".equals(str(row,"status")),"AUTHORIZATION_INACTIVE");
                run.put("status",outcome);run.put("ended_at",db(now));
            }
            case "revocations" -> {
                fields(b,"reason","");text(b,"reason");require(!"revoked".equals(str(row,"status")),"STATE_CONFLICT");
                store.update("guard_validation_session",number(row,"id"),map("status","revoked"));row.put("status","revoked");
                run.put("stop_requested_at",db(now));
                if(!TERMINAL.contains(state)){run.put("status","cancelled");run.put("ended_at",db(now));}
            }
            case "reconciliations" -> {
                fields(b,"","");
                if(!now.isBefore(time(p,"validUntil"))&&!TERMINAL.contains(state)) {
                    run.put("status","expired");run.put("ended_at",db(now));run.put("stop_requested_at",db(now));
                } else if("running".equals(state)&&run.get("last_activity_at")!=null
                        &&!now.isBefore(instant(run.get("last_activity_at")).plusSeconds(p.path("timeoutSeconds").asLong())))run.put("status","interrupted");
                else return view(row,run);
            }
            default -> throw error(404,"RESOURCE_NOT_FOUND");
        }
        updateRun(row,run);bump(row);lifecycle(row,operation,b);return view(row,run);
    }

    private void recheck(Map<String,Object> run,JsonNode p) {
        var in=admission.read(str(run,"manifest_ref"),str(run,"manifest_sha256"),text(p,"runnerIdentity"));
        require(in.manifest().equals(p),"LAB_MANIFEST_CHANGED");
    }
    private void updateRun(Map<String,Object> row,Map<String,Object> run) {
        mapper.updateRun(map("session",row.get("id"),"status",run.get("status"),"started",run.get("started_at"),"ended",run.get("ended_at"),
                "activity",run.get("last_activity_at"),"stop",run.get("stop_requested_at")));
    }
    private void bump(Map<String,Object> row) {
        long next=number(row,"revision")+1;store.update("guard_validation_session",number(row,"id"),map("revision",next));row.put("revision",next);
    }
    private void lifecycle(Map<String,Object> row,String kind,JsonNode body) {
        var payload=object("kind","lifecycle","operation",kind,"actor",access.subject(),"occurredAt",store.now().toString(),
                "revision",row.get("revision"),"reason",body==null?null:body.path("reason").asText(null));
        append(row,id(),"lifecycle:"+row.get("revision"),null,"lifecycle",payload,hash(payload));
        store.audit(access.human(),"guard.lab."+kind,str(row,"public_id"),number(row,"asset_id"),null,payload);
    }

    private JsonNode event(Map<String,Object> row,Map<String,Object> run,JsonNode b) {
        String eventId=uuid(b,"eventId"),kind=text(b,"kind"),scenarioId=text(b,"scenarioId");
        String key=kind+":"+(kind.equals("scenario_result")?scenarioId:uuid(b,"referenceId"));
        ObjectNode request=b.deepCopy();request.remove("eventId");String requestHash=hash(request);
        var old=mapper.event(eventId);if(old==null)old=mapper.fact(number(row,"id"),key);
        if(old!=null) {
            if(number(old,"session_id")!=number(row,"id")||!str(old,"request_sha256").equals(requestHash))throw error(409,"IDEMPOTENCY_CONFLICT");
            return object("eventId",old.get("public_id"),"revision",row.get("revision"),"duplicate",true);
        }
        require(run.get("started_at")!=null,"STATE_CONFLICT");
        var p=json(run,"manifest_jcs");var scenario=scenario(json(run,"scenarios_jcs"),scenarioId);var mapping=entry(json(run,"mapping_jcs"),scenarioId);
        var payload=facts.resolve(p,scenario,mapping,b);payload.put("sessionId",str(row,"public_id"));payload.put("mappingSha256",text(p,"mappingSha256"));
        payload.put("receivedAt",store.now().toString());
        append(row,eventId,key,scenarioId,kind,payload,requestHash);
        if("running".equals(str(run,"status"))){run.put("last_activity_at",db(store.now()));updateRun(row,run);}
        bump(row);store.audit(access.human(),"guard.lab.fact",eventId,number(row,"asset_id"),null,payload);
        return object("eventId",eventId,"revision",row.get("revision"),"duplicate",false,"fact",payload);
    }
    private void append(Map<String,Object> row,String eventId,String key,String scenario,String kind,JsonNode payload,String requestHash) {
        mapper.insertEvent(map("public_id",eventId,"session",row.get("id"),"fact",key,"scenario",scenario,"kind",kind,
                "occurred",payload.path("occurredAt").isTextual()?db(time(payload,"occurredAt")):null,
                "payload",canonical(payload),"sha",hash(payload),"request",requestHash));
    }

    @Transactional(readOnly=true)
    public JsonNode get(String id) {
        var row=readable(id);return view(row,mapper.run(number(row,"id")));
    }

    /** 运行状态的合法取值，与 V25 guard_lab_run 的 CHECK 一致。 */
    static final Set<String> RUN_STATES=Set.of("registered","running","interrupted","completed","failed","cancelled","expired");

    /**
     * 列表与详情同一口径：evaluation.read 且资产范围可见；SQL 在 LIMIT 前过滤范围，不可见的游标按 404 处理。
     * 只读、不写库，不返回场景/映射原文；status 只按运行状态过滤，不改变资格语义。
     */
    @Transactional(readOnly=true)
    public JsonNode list(String cursor,String status,int limit) {
        require(limit>=1&&limit<=200,"INVALID_PAGE");
        require(status==null||RUN_STATES.contains(status),"INVALID_RUN_STATUS");
        long actor=access.human();long before=Long.MAX_VALUE;
        if(cursor!=null)before=number(readable(cursor),"id");
        var rows=mapper.visibleSessions(actor,before,status==null?"":status,limit+1);
        var items=new ArrayList<JsonNode>();
        for(int i=0;i<Math.min(limit,rows.size());i++){var row=rows.get(i);items.add(view(row,mapper.run(number(row,"id"))));}
        return object("items",items,"nextCursor",rows.size()>limit?str(rows.get(limit-1),"public_id"):null);
    }
    private Map<String,Object> readable(String id) {
        var row=store.external("guard_validation_session",uuid(id),false);access.visible("evaluation.read",number(row,"asset_id"));
        require(mapper.run(number(row,"id"))!=null,"LAB_SESSION_UNAVAILABLE");return row;
    }
    private JsonNode view(Map<String,Object> row,Map<String,Object> run) {
        var p=json(run,"manifest_jcs");Instant now=store.now();String eligibility=str(row,"status");
        if(!"revoked".equals(eligibility)&&!now.isBefore(instant(row.get("valid_until"))))eligibility="expired";
        String blockedReason=null;
        if(!Set.of("revoked","expired").contains(eligibility)) {
            var authorization=store.get("asset_authorization",number(row,"authorization_id"));
            if(!"active".equals(str(authorization,"status"))||number(authorization,"revision")!=p.path("authorizationRevision").asLong()
                    ||now.isBefore(instant(authorization.get("valid_from")))||!now.isBefore(instant(authorization.get("valid_until")))) {
                eligibility="blocked";blockedReason="AUTHORIZATION_INACTIVE";
            }
        }
        boolean timedOut="running".equals(str(run,"status"))&&run.get("last_activity_at")!=null
                &&!now.isBefore(instant(run.get("last_activity_at")).plusSeconds(p.path("timeoutSeconds").asLong()));
        return object("id",row.get("public_id"),"eligibilityStatus",row.get("status"),"effectiveEligibility",eligibility,
                "blockedReason",blockedReason,
                "runStatus",run.get("status"),"timedOut",timedOut,"revision",row.get("revision"),"assetId",p.get("assetId"),"bundleId",p.get("bundleId"),
                "sessionSha256",row.get("content_sha256"),"manifestSha256",run.get("manifest_sha256"),"evidenceKind",p.get("evidenceKind"),
                "validUntil",time(p,"validUntil").toString(),"startedAt",iso(run.get("started_at")),"endedAt",iso(run.get("ended_at")),
                "stopRequestedAt",iso(run.get("stop_requested_at")),"cleanupStatus","not_asserted","executionAuthority",false);
    }
    private static String iso(Object time) {return time==null?null:instant(time).toString();}

    @Transactional(readOnly=true)
    public JsonNode events(String id,long after,int limit) {
        require(after>=0&&limit>=1&&limit<=200,"INVALID_PAGE");var row=readable(id);
        var list=mapper.events(number(row,"id"),after,limit+1);boolean more=list.size()>limit;
        var page=list.subList(0,Math.min(limit,list.size()));var items=new ArrayList<JsonNode>();
        for(var e:page)items.add(object("eventId",e.get("public_id"),"sequence",e.get("id"),"sha256",e.get("content_sha256"),"fact",json(e,"payload_jcs")));
        return object("items",items,"nextAfter",more?page.getLast().get("id"):null);
    }

    @Transactional(readOnly=true)
    public JsonNode reportInput(String id) {var row=readable(id);return snapshot(row,mapper.run(number(row,"id")));}
    private JsonNode snapshot(Map<String,Object> row,Map<String,Object> run) {
        var p=json(run,"manifest_jcs");var all=mapper.events(number(row,"id"),0,20001);require(all.size()<=20000,"LAB_REPORT_TOO_LARGE");
        var events=new ArrayList<JsonNode>();var commands=new HashSet<String>();var decisions=new HashSet<String>();
        for(var e:all)if(!Set.of("lifecycle","report").contains(str(e,"kind"))) {
            JsonNode fact=json(e,"payload_jcs");require(hash(fact).equals(str(e,"content_sha256")),"LAB_FACT_DIGEST_INVALID");events.add(fact);
            if(fact.path("commandId").isTextual())commands.add(text(fact,"commandId"));
            if(fact.path("decisionId").isTextual())decisions.add(text(fact,"decisionId"));
        }
        var expected=mapper.commands(number(run,"sensor_id"),text(p,"bootId"));require(expected.size()<=20000,"LAB_REPORT_TOO_LARGE");
        var unlinked=expected.stream().filter(c->!commands.contains(c)).sorted().toList();
        var expectedDecisions=mapper.decisions(number(run,"sensor_id"),text(p,"bootId"));require(expectedDecisions.size()<=20000,"LAB_REPORT_TOO_LARGE");
        var unlinkedDecisions=new TreeSet<String>();var outsideDecisions=new TreeSet<String>();
        for(var decision:expectedDecisions) {
            String id=str(decision,"public_id");
            if(outsideScoring(p,json(run,"scenarios_jcs"),json(run,"mapping_jcs"),decision))outsideDecisions.add(id);
            else if(!decisions.contains(id))unlinkedDecisions.add(id);
        }
        var scenarios=new ArrayList<JsonNode>();
        for(var s:json(run,"scenarios_jcs").path("scenarios")) {
            ObjectNode result=s.deepCopy();result.set("quality",facts.quality(p,s,entry(json(run,"mapping_jcs"),text(s,"scenarioId")),number(row,"asset_id"),number(run,"sensor_id")));scenarios.add(result);
        }
        return object("contractVersion",VERSION,"session",p,"sessionSha256",row.get("content_sha256"),"runStatus",run.get("status"),
                "scenarios",scenarios,"events",events,"unlinkedCommandIds",unlinked,"unlinkedDecisionIds",unlinkedDecisions,
                "outsideScoringDecisionIds",outsideDecisions);
    }

    /** 只排除身份已匹配且时刻明确在评分窗外的决策；身份/时刻缺失仍须关联，不能静默丢失。 */
    static boolean outsideScoring(JsonNode p,JsonNode scenarios,JsonNode mappings,Map<String,Object> decision) {
        Instant at=instant(decision.get("as_of"));
        if(at==null||decision.get("peer_key")==null||decision.get("key_epoch")==null)return false;
        boolean known=false;
        for(var mapping:mappings.path("entries")) {
            if(!mapping.path("peerKey").asText().equals(str(decision,"peer_key"))||mapping.path("keyEpoch").asLong()!=number(decision,"key_epoch"))continue;
            known=true;
            var scenario=scenario(scenarios,text(mapping,"scenarioId"));
            if(!at.isBefore(shift(p,time(scenario,"sourceStart")))&&!at.isAfter(shift(p,time(scenario,"sourceEnd"))))return false;
        }
        return known;
    }

    private JsonNode report(Map<String,Object> row,Map<String,Object> run,JsonNode b) {
        fields(b,"reportRef sha256 runnerIdentity","");require(TERMINAL.contains(str(run,"status")),"STATE_CONFLICT");
        var p=json(run,"manifest_jcs");require(text(p,"runnerIdentity").equals(text(b,"runnerIdentity")),"LAB_RUNNER_INVALID");
        JsonNode signed=signatures.report(artifacts.json(text(b,"reportRef"),digest(b,"sha256")),text(b,"runnerIdentity"));
        // JSON 解析可能用 IntNode 表示相同的 LongNode；完整性按跨语言 JCS 字节比较，不能依赖 Java 节点类型。
        JsonNode expected=GuardLabReport.generate(snapshot(row,run));require(hash(expected).equals(hash(signed)),"LAB_REPORT_MISMATCH");
        String key="report:"+text(b,"sha256");var old=mapper.fact(number(row,"id"),key);
        if(old!=null)return json(old,"payload_jcs");
        var bundle=store.get("guard_release_bundle",number(row,"bundle_id"));
        var report=store.add("guard_evaluation_run",map("plan_id",bundle.get("plan_id"),"bundle_id",bundle.get("id"),"run_kind","canary",
                "runner_identity",text(b,"runnerIdentity"),"status",signed.path("passed").asBoolean()?"passed":"failed",
                "report_ref",text(b,"reportRef"),"report_sha256",text(b,"sha256"),"payload_json",canonical(signed)));
        var result=object("evaluationId",report.get("public_id"),"sessionId",row.get("public_id"),"status",signed.get("status"),"passed",signed.get("passed"),
                "rawSha256",text(b,"sha256"),"contentSha256",hash(signed),"signatureVerified",true,"occurredAt",store.now().toString());
        append(row,id(),key,null,"report",result,hash(b));bump(row);store.audit(access.human(),"guard.lab.report_imported",str(row,"public_id"),number(row,"asset_id"),null,result);
        return result;
    }

    @Transactional(readOnly=true)
    public JsonNode machine(String sensorId,String id) {
        var sensor=access.sensor(uuid(sensorId),"machine.sensor.read");var row=store.external("guard_validation_session",uuid(id),false);
        var run=mapper.run(number(row,"id"));require(run!=null&&number(run,"sensor_id")==number(sensor,"id")&&number(row,"asset_id")==number(sensor,"asset_id"),"LAB_SENSOR_MISMATCH");
        var p=json(run,"manifest_jcs");require(text(p,"bootId").equals(str(sensor,"guard_boot_id")),"LAB_SENSOR_MISMATCH");
        ObjectNode state=(ObjectNode)view(row,run);var reasons=new TreeSet<String>();
        if(!"active".equals(state.path("effectiveEligibility").asText()))reasons.add(state.path("blockedReason").asText("LAB_ELIGIBILITY_INACTIVE"));
        if(!"running".equals(str(run,"status")))reasons.add("LAB_RUN_NOT_RUNNING");
        if(state.path("timedOut").asBoolean())reasons.add("LAB_RUN_TIMED_OUT");
        if(!"lab".equals(p.path("evidenceKind").asText()))reasons.add("LAB_SYNTHETIC_ONLY");
        try {admission.machineCurrent(run);}
        catch(com.xyh.cybersecurity.common.api.ApiRequestException unavailable) {reasons.add(unavailable.code());}
        state.put("runnable",reasons.isEmpty());state.set("reasonCodes",node(reasons));
        return object("state",state,"manifest",p,"mapping",json(run,"mapping_jcs"),"scenarios",json(run,"scenarios_jcs"));
    }
}
