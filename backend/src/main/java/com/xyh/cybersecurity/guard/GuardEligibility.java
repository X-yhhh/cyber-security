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
    private GuardLabExecutionGate labGate;
    /** Spring 运行路径追加会话有效性检查；原三参构造保留给纯领域测试。 */
    @org.springframework.beans.factory.annotation.Autowired
    void labGate(GuardLabExecutionGate gate){this.labGate=gate;}
    public GuardEligibility(GuardStore store,@Value("${cyber.guard.automation-enabled:false}") boolean automation,@Value("${cyber.guard.protection-file:}") String protectionFile){this.store=store;this.automation=automation;
        JsonNode p=null;if(!protectionFile.isBlank())try{p=parse(java.nio.file.Files.readString(java.nio.file.Path.of(protectionFile)));fields(p,"protectedBudgetTargetIds protectedServicePorts","");}catch(java.io.IOException e){throw new IllegalStateException("保护配置不可读");}
        // 启动即按执行器同一规则校验端口，运行中不再因保护文件格式在判定路径抛错。
        if(p!=null)try{require(p.path("protectedServicePorts").isArray(),"PROTECTION_SET_UNVERIFIED");protectedPorts(p.path("protectedServicePorts"));}catch(com.xyh.cybersecurity.common.api.ApiRequestException e){throw new IllegalStateException("保护配置端口非法");}this.protection=p;}
    /** 与执行器 contract.IMPLICIT_PROTECTED_PORTS 一致：管理、解析与远程桌面端口始终保护。 */
    static final List<Integer> IMPLICIT_PROTECTED_PORTS=List.of(22,53,3389);
    /** 保护端口有效集合：并入隐式端口后去重升序，不超过 128 个；非整数或越界端口拒绝。 */
    public static List<Integer> protectedPorts(JsonNode ports){var set=new TreeSet<Integer>(IMPLICIT_PROTECTED_PORTS);
        for(var port:ports){require(port.isInt()&&port.asInt()>=1&&port.asInt()<=65535,"PROTECTION_SET_UNVERIFIED");set.add(port.asInt());}
        require(set.size()<=128,"PROTECTION_SET_UNVERIFIED");return List.copyOf(set);}
    /** 保护端口清单摘要：有效集合的 JCS SHA-256，执行器按本机配置独立重算。 */
    public static String protectedPortsSha256(JsonNode ports){return hash(node(protectedPorts(ports)));}
    /** 全入站可封禁闭区间：从 1—65535 扣除保护端口，算法与执行器 unprotected_ranges 对拍。 */
    public static List<List<Integer>> unprotectedRanges(JsonNode ports){var ranges=new ArrayList<List<Integer>>();int start=1;
        for(int port:protectedPorts(ports)){if(start<port)ranges.add(List.of(start,port-1));start=port+1;}if(start<=65535)ranges.add(List.of(start,65535));return ranges;}
    /** 能力集合摘要：各项按 capabilityId 升序后取 JCS 摘要，与执行器 capability_items_sha256 一致。 */
    public static String capabilitySetSha256(Collection<JsonNode> items){var sorted=new ArrayList<>(items);sorted.sort(Comparator.comparing(i->i.path("capabilityId").asText()));return hash(node(sorted));}
    /**
     * 控制面对某执行器的期望 capabilityHash：取其资产 active 绑定且组合 active 的同平台、等级适配环境的能力。
     * 全入站项附带当前保护端口摘要，仅当能力保护集等于当前保护文件时给出，否则为空使摘要必然不符。
     * 结果只用于领取比对，不改变任何事实；执行器须按登记更新配置后重报心跳。
     */
    public String executorCapabilityHash(Map<String,Object> executor){
        String env=str(store.get("asset",number(executor,"asset_id")),"environment");var levels=env.equals("authorized")?Set.of("authorized_auto"):Set.of("lab_auto","authorized_auto");var items=new TreeMap<String,JsonNode>();
        for(var binding:store.rows("guard_asset_binding",map("asset_id",executor.get("asset_id"),"status","active"),false,100)){
            var bundle=store.get("guard_release_bundle",number(binding,"bundle_id"));if(!"active".equals(str(bundle,"status")))continue;
            for(var link:store.rows("guard_bundle_capability",map("bundle_id",bundle.get("id")),false,100)){var c=store.get("guard_capability",number(link,"capability_id"));
                if(!str(c,"platform").equals(str(executor,"platform"))||!levels.contains(str(c,"level")))continue;
                boolean inbound="peer_inbound".equals(str(c,"scope"));String ports=inbound&&protection!=null&&hash(protection).equals(str(c,"protection_set_sha256"))?protectedPortsSha256(protection.path("protectedServicePorts")):null;
                items.put(str(c,"public_id"),object("capabilityId",c.get("public_id"),"scope",inbound?"peer_inbound":"peer_service","protectionSetSha256",c.get("protection_set_sha256"),"protectedPortsSha256",ports));}
        }return capabilitySetSha256(items.values());}
    /** P4 侧预期全入站封禁区间；审计只存摘要，P5 用同一保护端口独立重算后可逐项复核。 */
    public JsonNode inboundRanges(String commandId,Map<String,Object> capability){var ports=protection.path("protectedServicePorts");
        return object("commandId",commandId,"capabilityId",capability.get("public_id"),"protectionSetSha256",capability.get("protection_set_sha256"),"protectedPortsSha256",protectedPortsSha256(ports),"ranges",unprotectedRanges(ports));}
    public boolean capability(Map<String,Object> bundle,JsonNode policy,JsonNode o){
        return capability(bundle,policy,o,policy.path("family").asText());
    }
    public boolean capability(Map<String,Object> bundle,JsonNode policy,JsonNode o,String family){
        if(!CONTRACT.equals(o.path("contractVersion").asText())||!profileAccepted(policy,o)||o.path("environment").asText().equals("research"))return false;
        var p=store.get("guard_decision_policy",number(bundle,"policy_id"));var m=store.get("guard_model",number(bundle,"model_id"));
        if(!DECISION.equals(str(p,"decision_contract_version"))||number(p,"model_id")!=number(m,"id")||!"validated".equals(str(m,"validation_status"))||GuardModelRuntime.applicable(json(m,"manifest_json"),o)!=null)return false;
        String env=o.path("environment").asText();if(env.equals("research"))return false;
        return matchingCapability(bundle,policy,o,family)!=null;
    }
    /** 策略接受的快照 profile：有 acceptedProfiles 时按集合判定，否则只接受 profile（旧策略语义不变）。 */
    public static boolean profileAccepted(JsonNode policy,JsonNode o){
        return policy.has("acceptedProfiles")?GuardAdministration.contains(policy.get("acceptedProfiles"),o.path("profile").asText()):policy.path("profile").equals(o.path("profile"));
    }
    public Map<String,Object> matchingCapability(Map<String,Object> bundle,JsonNode policy,JsonNode o){
        return matchingCapability(bundle,policy,o,policy.path("family").asText());
    }
    public Map<String,Object> matchingCapability(Map<String,Object> bundle,JsonNode policy,JsonNode o,String family){
        // research 不具备任何执行等级；在读取、解析能力事实前返回既有的无匹配结果。
        if("research".equals(o.path("environment").asText()))return null;
        for(var link:store.rows("guard_bundle_capability",map("bundle_id",bundle.get("id")),false,100)){
            var c=store.get("guard_capability",number(link,"capability_id"));var d=json(c,"payload_json");String env=o.path("environment").asText();
            boolean level=env.equals("authorized")?"authorized_auto".equals(str(c,"level")):env.equals("lab")&&Set.of("lab_auto","authorized_auto").contains(str(c,"level"));
            if(!level||!GuardAdministration.contains(policy.path("supportedCapabilityIds"),str(c,"public_id")))continue;
            boolean match=true;for(String key:List.of("addressFamily","transport","direction","profile"))match&=d.path(key).equals(o.path(key));match&=d.path("family").asText().equals(family);
            if(match)return c;
        }return null;
    }
    public boolean authorized(Map<String,Object> asset,Map<String,Object> bundle,Map<String,Object> binding,JsonNode policy,JsonNode o,Map<String,Object> executor,Instant now){
        return authorized(asset,bundle,binding,policy,o,executor,now,policy.path("family").asText());
    }
    public boolean authorized(Map<String,Object> asset,Map<String,Object> bundle,Map<String,Object> binding,JsonNode policy,JsonNode o,Map<String,Object> executor,Instant now,String family){
        if(labGate!=null&&!labGate.permits(o,bundle,now))return false;
        if(!automation||"alert_only".equals(policy.path("mode").asText())||!"active".equals(str(asset,"status"))||!"active".equals(str(bundle,"status"))||binding==null||!"active".equals(str(binding,"status"))||executor==null||!"active".equals(str(executor,"status")))return false;
        if(!str(asset,"environment").equals(str(bundle,"environment"))||number(binding,"bundle_id")!=number(bundle,"id"))return false;
        var p=store.get("guard_decision_policy",number(bundle,"policy_id"));if(!"reviewed".equals(str(p,"status")))return false;
        var auth=store.get("asset_authorization",number(binding,"authorization_id"));if(number(auth,"revision")!=number(binding,"authorization_revision")||!"active".equals(str(auth,"status"))||now.isBefore(instant(auth.get("valid_from")))||!now.plusSeconds(policy.path("maxTtlSeconds").asLong()).isBefore(instant(auth.get("valid_until"))))return false;
        if(executor.get("last_heartbeat")==null||(instant(executor.get("last_heartbeat")).isAfter(now)||Duration.between(instant(executor.get("last_heartbeat")),now).toMillis()>10000)||json(executor,"health_json").path("pendingRecovery").asBoolean(true))return false;
        var capability=matchingCapability(bundle,policy,o,family);if(capability==null||!str(capability,"platform").equals(str(executor,"platform"))||!json(capability,"payload_json").path("adapterVersion").asText().equals(str(executor,"adapter_version")))return false;
        String scope=GuardDecisionEngine.familyPolicy(policy,family).path("scope").asText("peer_service");
        for(var executionScope:json(auth,"scope_json").path("executionScopes")){
            boolean match=str(capability,"public_id").equals(executionScope.path("capabilityId").asText());
            for(String key:List.of("direction","transport","addressFamily"))match&=executionScope.path(key).equals(o.path(key));
            match&=executionScope.path("scope").asText("peer_service").equals(scope);
            JsonNode expectedPort="peer_inbound".equals(scope)?com.fasterxml.jackson.databind.node.NullNode.instance:o.path("servicePort");match&=executionScope.path("servicePort").equals(expectedPort);
            if(match)return true;
        }return false;
    }
    public boolean target(Map<String,Object> target,JsonNode o,Instant now){
        return target(target,o,now,policyForTarget,"");
    }
    private static final JsonNode policyForTarget=com.fasterxml.jackson.databind.node.MissingNode.getInstance();
    public boolean target(Map<String,Object> target,JsonNode o,Instant now,JsonNode policy,String family){
        if(target==null||o.path("targetRef").isNull()||!str(target,"target_ref").equals(o.path("targetRef").asText())||!instant(target.get("expires_at")).isAfter(now))return false;
        if(!time(o,"targetExpiresAt").isAfter(now)||!time(o,"lastPacketAt").plusSeconds(15).isAfter(now))return false;
        var b=json(target,"payload_json");for(String key:List.of("sensorId","captureScopeId","peerKey","keyEpoch","direction","transport","addressFamily"))if(!b.path(key).equals(o.path(key)))return false;
        String scope=GuardDecisionEngine.familyPolicy(policy,family).path("scope").asText("peer_service");
        if(!b.path("scope").asText("peer_service").equals(scope))return false;
        if(scope.equals("peer_inbound")){if(!b.path("servicePort").isNull()||!o.path("direction").asText().equals("inbound"))return false;}
        else if(!b.path("servicePort").equals(o.path("servicePort")))return false;
        var sensor=store.get("sensor_agent",number(target,"sensor_id"));var executor=store.get("guard_executor",number(target,"executor_id"));var stable=store.get("guard_budget_target",number(target,"budget_target_id"));
        return o.path("bootId").asText().equals(str(sensor,"guard_boot_id"))&&o.path("bootId").asText().equals(str(target,"collector_boot_id"))&&Objects.equals(str(target,"executor_boot_id"),str(executor,"boot_id"))&&"verified".equals(str(stable,"identity_status"))&&o.path("environment").asText().equals(str(stable,"environment"));
    }
    public String protection(Map<String,Object> bundle,JsonNode policy,Map<String,Object> target,JsonNode observation){return protection(bundle,policy,target,observation,policy.path("family").asText());}
    /** 全入站动作覆盖保护端口以外的全部端口：未证明平台豁免时拒绝签发；单服务动作仍逐个核对观察端口。 */
    public String protection(Map<String,Object> bundle,JsonNode policy,Map<String,Object> target,JsonNode observation,String family){if(protection==null||!hash(protection).equals(policy.path("protectionSetSha256").asText()))return "PROTECTION_SET_UNVERIFIED";
        var identity=store.get("guard_budget_target",number(target,"budget_target_id"));if(GuardAdministration.contains(protection.path("protectedBudgetTargetIds"),str(identity,"public_id")))return "PROTECTED_TARGET";
        // 规则区间已扣除全部保护端口，扫描触及的观察端口不决定全入站动作，豁免条件才决定。
        if(GuardDecisionEngine.familyPolicy(policy,family).path("scope").asText().equals("peer_inbound"))return inboundExempt(bundle,policy,observation,family)?null:"PROTECTED_SERVICE";
        if(observation.path("servicePort").isNumber())for(var port:protection.path("protectedServicePorts"))if(port.asInt()==observation.path("servicePort").asInt())return "PROTECTED_SERVICE";return null;}
    /**
     * B1.3 五条件同时满足才放行全入站：①组合与策略登记的能力匹配本观察；②能力平台为 macOS（PF 适配器）且范围为 peer_inbound；
     * ③能力保护集摘要等于策略 protectionSetSha256 与当前保护文件摘要；④等级不低于 lab_auto 且带已验签的豁免证据；⑤观察与组合环境均为 lab。
     * authorized 环境即使有 authorized_auto 能力也继续拒绝，待单独验收后另行开放。
     */
    boolean inboundExempt(Map<String,Object> bundle,JsonNode policy,JsonNode observation,String family){
        if(bundle==null||!"lab".equals(observation.path("environment").asText())||!"lab".equals(str(bundle,"environment")))return false;
        var c=matchingCapability(bundle,policy,observation,family);if(c==null)return false;String set=str(c,"protection_set_sha256");
        return "macos".equals(str(c,"platform"))&&"peer_inbound".equals(str(c,"scope"))&&set!=null&&set.equals(hash(protection))&&set.equals(policy.path("protectionSetSha256").asText())
                &&Set.of("lab_auto","authorized_auto").contains(str(c,"level"))&&str(c,"exemption_evidence_sha256")!=null;}
}
