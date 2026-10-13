package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.util.Objects;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 已纳入 lab 会话的传感器，在判定和命令领取时复核资格；清理回执不受此门控制。 */
@Service
public class GuardLabExecutionGate {
    private final GuardStore store;
    private final GuardLabMapper mapper;
    public GuardLabExecutionGate(GuardStore store,GuardLabMapper mapper) {this.store=store;this.mapper=mapper;}

    /** T2 的回放口径只对同组合、同资产的 running 正式 lab 会话开放，不依赖目标或攻击标签。 */
    public boolean replayAllowed(JsonNode observation,java.util.Map<String,Object> bundle){
        if(!"lab".equals(observation.path("environment").asText())||!HEALTH_REPLAY.equals(json(bundle,"subject_json").path("protocolVersions").path("health").asText()))return false;
        var sensor=store.external("sensor_agent",uuid(observation,"sensorId"),false);
        long sid=number(sensor,"id");String boot=uuid(observation,"bootId");
        Long owner=GuardStore.scoped("lab-owner:"+sid+":"+boot,()->mapper.owner(sid,boot));
        if(owner==null)return false;
        var session=store.get("guard_validation_session",owner);var run=GuardStore.scoped("lab-run:"+owner,()->mapper.run(owner));
        return run!=null&&"running".equals(str(run,"status"))&&"lab".equals(json(run,"manifest_jcs").path("evidenceKind").asText())
                &&number(session,"asset_id")==number(sensor,"asset_id")&&number(session,"bundle_id")==number(bundle,"id");
    }

    /** 不读取标签或场景类别来屏蔽误报；这里只检查授权、运行状态和稳定目标身份。 */
    public boolean permits(JsonNode observation,java.util.Map<String,Object> bundle,Instant now) {
        if(!"lab".equals(observation.path("environment").asText()))return true;
        var sensor=store.external("sensor_agent",uuid(observation,"sensorId"),false);
        long sid=number(sensor,"id");String boot=uuid(observation,"bootId");
        // 批内判定作用域中复用会话归属与运行行（写入方都先锁同一资产）；作用域外每次查询。
        Long owner=GuardStore.scoped("lab-owner:"+sid+":"+boot,()->mapper.owner(sid,boot));
        // 原 P5 平台验证入口兼容；一旦登记过会话，不允许换 boot 退回无会话路径。
        if(owner==null)return GuardStore.<Integer>scoped("lab-managed:"+sid,()->mapper.managedSensor(sid))==0;
        var session=store.get("guard_validation_session",owner);var run=GuardStore.scoped("lab-run:"+owner,()->mapper.run(owner));
        if(!"active".equals(str(session,"status"))||run==null||!"running".equals(str(run,"status"))
                ||number(session,"asset_id")!=number(sensor,"asset_id")||number(session,"bundle_id")!=number(bundle,"id"))return false;
        var p=json(run,"manifest_jcs");
        if(!"lab".equals(p.path("evidenceKind").asText()))return false;
        if(now.isBefore(time(p,"validFrom"))||!now.isBefore(time(p,"validUntil"))||run.get("last_activity_at")==null
                ||!now.isBefore(instant(run.get("last_activity_at")).plusSeconds(p.path("timeoutSeconds").asLong())))return false;
        var auth=store.get("asset_authorization",number(session,"authorization_id"));
        if(!"active".equals(str(auth,"status"))||number(auth,"revision")!=p.path("authorizationRevision").asLong()
                ||now.isBefore(instant(auth.get("valid_from")))||!now.isBefore(instant(auth.get("valid_until"))))return false;
        if(!observation.path("targetRef").isTextual())return false;
        var target=store.one("guard_target_binding",map("target_ref",observation.path("targetRef").asText()),false);
        if(target==null)return false;
        for(var mapping:json(run,"mapping_jcs").path("entries")) {
            if(!mapping.path("peerKey").equals(observation.path("peerKey"))||!mapping.path("keyEpoch").equals(observation.path("keyEpoch"))
                    ||!mapping.path("captureScopeId").equals(observation.path("captureScopeId")))continue;
            var initial=store.external("guard_target_binding",uuid(mapping,"targetBindingId"),false);
            return Objects.equals(initial.get("budget_target_id"),target.get("budget_target_id"))&&Objects.equals(initial.get("scope_digest"),target.get("scope_digest"));
        }
        return false;
    }
}
