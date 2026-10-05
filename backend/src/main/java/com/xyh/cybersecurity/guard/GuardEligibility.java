package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.*;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 领取与判定复用同一发布、范围和保护规则；默认关闭自动签发，没有隐式真实资产启用。 */
@Service
public class GuardEligibility {
    private final GuardStore store;private final boolean automation;
    private final JsonNode protection;
    public GuardEligibility(GuardStore store,@Value("${cyber.guard.automation-enabled:false}") boolean automation,@Value("${cyber.guard.protection-file:}") String protectionFile){this.store=store;this.automation=automation;
        JsonNode p=null;if(!protectionFile.isBlank())try{p=parse(java.nio.file.Files.readString(java.nio.file.Path.of(protectionFile)));fields(p,"protectedBudgetTargetIds protectedServicePorts","");}catch(java.io.IOException e){throw new IllegalStateException("保护配置不可读");}this.protection=p;}
    public boolean capability(Map<String,Object> bundle,JsonNode policy,JsonNode o){
        if(!CONTRACT.equals(o.path("contractVersion").asText())||!policy.path("profile").equals(o.path("profile")))return false;
        var p=store.get("guard_decision_policy",number(bundle,"policy_id"));var m=store.get("guard_model",number(bundle,"model_id"));
        if(!DECISION.equals(str(p,"decision_contract_version"))||number(p,"model_id")!=number(m,"id")||!"validated".equals(str(m,"validation_status"))||GuardModelRuntime.applicable(json(m,"manifest_json"),o)!=null)return false;
        String env=o.path("environment").asText();if(env.equals("research"))return false;
        return matchingCapability(bundle,policy,o)!=null;
    }
    public Map<String,Object> matchingCapability(Map<String,Object> bundle,JsonNode policy,JsonNode o){
        for(var link:store.rows("guard_bundle_capability",map("bundle_id",bundle.get("id")),false,100)){
            var c=store.get("guard_capability",number(link,"capability_id"));var d=json(c,"payload_json");String env=o.path("environment").asText();
            boolean level=env.equals("authorized")?"authorized_auto".equals(str(c,"level")):env.equals("lab")&&Set.of("lab_auto","authorized_auto").contains(str(c,"level"));
            if(!level||!GuardAdministration.contains(policy.path("supportedCapabilityIds"),str(c,"public_id")))continue;
            boolean match=true;for(String key:List.of("addressFamily","transport","direction","profile"))match&=d.path(key).equals(o.path(key));match&=d.path("family").equals(policy.path("family"));
            if(match)return c;
        }return null;
    }
    public boolean authorized(Map<String,Object> asset,Map<String,Object> bundle,Map<String,Object> binding,JsonNode policy,JsonNode o,Map<String,Object> executor,Instant now){
        if(!automation||"alert_only".equals(policy.path("mode").asText())||!"active".equals(str(asset,"status"))||!"active".equals(str(bundle,"status"))||binding==null||!"active".equals(str(binding,"status"))||executor==null||!"active".equals(str(executor,"status")))return false;
        if(!str(asset,"environment").equals(str(bundle,"environment"))||number(binding,"bundle_id")!=number(bundle,"id"))return false;
        var p=store.get("guard_decision_policy",number(bundle,"policy_id"));if(!"reviewed".equals(str(p,"status")))return false;
        var auth=store.get("asset_authorization",number(binding,"authorization_id"));if(number(auth,"revision")!=number(binding,"authorization_revision")||!"active".equals(str(auth,"status"))||now.isBefore(instant(auth.get("valid_from")))||!now.plusSeconds(policy.path("maxTtlSeconds").asLong()).isBefore(instant(auth.get("valid_until"))))return false;
        if(executor.get("last_heartbeat")==null||Duration.between(instant(executor.get("last_heartbeat")),now).toMillis()>10000||json(executor,"health_json").path("pendingRecovery").asBoolean(true))return false;
        var capability=matchingCapability(bundle,policy,o);if(capability==null||!str(capability,"platform").equals(str(executor,"platform"))||!json(capability,"payload_json").path("adapterVersion").asText().equals(str(executor,"adapter_version")))return false;
        for(var scope:json(auth,"scope_json").path("executionScopes")){
            boolean match=str(capability,"public_id").equals(scope.path("capabilityId").asText());for(String key:List.of("direction","transport","servicePort","addressFamily"))match&=scope.path(key).equals(o.path(key));if(match)return true;
        }return false;
    }
    public boolean target(Map<String,Object> target,JsonNode o,Instant now){
        if(target==null||o.path("targetRef").isNull()||!str(target,"target_ref").equals(o.path("targetRef").asText())||!instant(target.get("expires_at")).isAfter(now))return false;
        if(!time(o,"targetExpiresAt").isAfter(now)||!time(o,"lastPacketAt").plusSeconds(15).isAfter(now))return false;
        var b=json(target,"payload_json");for(String key:List.of("sensorId","captureScopeId","peerKey","keyEpoch","direction","transport","servicePort","addressFamily"))if(!b.path(key).equals(o.path(key)))return false;
        var sensor=store.get("sensor_agent",number(target,"sensor_id"));var executor=store.get("guard_executor",number(target,"executor_id"));var stable=store.get("guard_budget_target",number(target,"budget_target_id"));
        return o.path("bootId").asText().equals(str(sensor,"guard_boot_id"))&&o.path("bootId").asText().equals(str(target,"collector_boot_id"))&&Objects.equals(str(target,"executor_boot_id"),str(executor,"boot_id"))&&"verified".equals(str(stable,"identity_status"))&&o.path("environment").asText().equals(str(stable,"environment"));
    }
    public String protection(JsonNode policy,Map<String,Object> target,JsonNode observation){if(protection==null||!hash(protection).equals(policy.path("protectionSetSha256").asText()))return "PROTECTION_SET_UNVERIFIED";
        var identity=store.get("guard_budget_target",number(target,"budget_target_id"));if(GuardAdministration.contains(protection.path("protectedBudgetTargetIds"),str(identity,"public_id")))return "PROTECTED_TARGET";
        for(var port:protection.path("protectedServicePorts"))if(port.asInt()==observation.path("servicePort").asInt())return "PROTECTED_SERVICE";return null;}
}
