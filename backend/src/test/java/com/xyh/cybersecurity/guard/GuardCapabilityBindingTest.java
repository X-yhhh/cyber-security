package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** B1 能力绑定的纯判定回归：内存事实替身驱动真实 GuardEligibility，不连数据库、不签发命令。 */
class GuardCapabilityBindingTest {
    static final String CAPABILITY="0b6f3c2e-6d1a-4c55-9a51-2f1f8a0e9c11";
    static final JsonNode PROTECTION=object("protectedBudgetTargetIds",List.of(),"protectedServicePorts",List.of(22,3389));
    @TempDir Path temporary;

    /** 只读内存表：按列等值过滤，数值统一按 long 比较；更新与审计不应在判定路径出现。 */
    static final class Facts extends GuardStore {
        final Map<String,List<Map<String,Object>>> tables=new HashMap<>();
        int reads;
        Facts(){super(null,null);}
        Map<String,Object> put(String table,Object... kv){var row=map(kv);tables.computeIfAbsent(table,k->new ArrayList<>()).add(row);return row;}
        @Override public Instant now(){return Instant.parse("2026-10-08T08:00:00Z");}
        @Override public List<Map<String,Object>> rows(String t,Map<String,Object> w,boolean lock,int limit){
            reads++;
            return tables.getOrDefault(t,List.of()).stream().filter(r->w.entrySet().stream().allMatch(e->same(r.get(e.getKey()),e.getValue()))).limit(limit).toList();}
        static boolean same(Object a,Object b){return a instanceof Number x&&b instanceof Number y?x.longValue()==y.longValue():Objects.equals(a,b);}
    }

    Facts facts;GuardEligibility eligibility;ObjectNode policy;ObjectNode observation;Map<String,Object> bundle,capability,target,asset,binding,authorization,executor;

    @BeforeEach void lab()throws Exception{
        Path file=temporary.resolve("protection.json");Files.writeString(file,canonical(PROTECTION));
        facts=new Facts();eligibility=new GuardEligibility(facts,true,file.toString());
        policy=object("family","port_scan","mode","auto","maxTtlSeconds",30,"protectionSetSha256",hash(PROTECTION),"supportedCapabilityIds",List.of(CAPABILITY),
                "familyPolicies",List.of(object("family","port_scan","scope","peer_inbound"),object("family","dos_slow","scope","peer_service")));
        observation=object("environment","lab","addressFamily","ipv4","transport","tcp","direction","inbound","profile","flow-prefix-v1","servicePort",22);
        asset=facts.put("asset","id",1L,"status","active","environment","lab");
        facts.put("guard_decision_policy","id",2L,"status","reviewed");
        bundle=facts.put("guard_release_bundle","id",3L,"status","active","environment","lab","policy_id",2L);
        capability=facts.put("guard_capability","id",4L,"public_id",CAPABILITY,"platform","macos","level","lab_auto","scope","peer_inbound","protection_set_sha256",hash(PROTECTION),"exemption_evidence_sha256","e".repeat(64),
                "payload_json",canonical(object("addressFamily","ipv4","transport","tcp","direction","inbound","profile","flow-prefix-v1","family","port_scan","adapterVersion","pf-1")));
        facts.put("guard_bundle_capability","bundle_id",3L,"capability_id",4L);
        facts.put("guard_budget_target","id",5L,"public_id",id());target=map("budget_target_id",5L);
        authorization=facts.put("asset_authorization","id",6L,"revision",1L,"status","active","valid_from",db(facts.now().minusSeconds(60)),"valid_until",db(facts.now().plusSeconds(3600)),
                "scope_json",canonical(object("executionScopes",List.of(object("capabilityId",CAPABILITY,"scope","peer_inbound","direction","inbound","transport","tcp","addressFamily","ipv4","servicePort",null)))));
        binding=facts.put("guard_asset_binding","id",7L,"asset_id",1L,"bundle_id",3L,"authorization_id",6L,"authorization_revision",1L,"status","active");
        executor=facts.put("guard_executor","id",8L,"asset_id",1L,"platform","macos","adapter_version","pf-1","status","active","last_heartbeat",db(facts.now().minusSeconds(1)),"health_json",canonical(object("pendingRecovery",false)));
    }
    String inbound(){return eligibility.protection(bundle,policy,target,observation,"port_scan");}

    /** K9-B1：端口扫描只产生 final 快照；能力 profile 只在策略已审查接受两种快照时兼容，其余身份键仍逐字相等。 */
    @Test void capabilityProfileFollowsReviewedAcceptedProfiles(){
        observation.put("profile","flow-final-v1");
        assertThat(eligibility.matchingCapability(bundle,policy,observation,"port_scan")).isNull();
        policy.set("acceptedProfiles",node(List.of("flow-prefix-v1")));
        assertThat(eligibility.matchingCapability(bundle,policy,observation,"port_scan")).isNull();
        policy.set("acceptedProfiles",node(List.of("flow-prefix-v1","flow-final-v1")));
        assertThat(eligibility.matchingCapability(bundle,policy,observation,"port_scan")).isSameAs(capability);
        observation.put("direction","outbound");
        assertThat(eligibility.matchingCapability(bundle,policy,observation,"port_scan")).isNull();
        observation.put("direction","inbound");
        assertThat(eligibility.matchingCapability(bundle,policy,observation,"dos_slow")).isNull();
        capability.put("payload_json",canonical(object("addressFamily","ipv4","transport","tcp","direction","inbound","profile","flow-other-v1","family","port_scan","adapterVersion","pf-1")));
        assertThat(eligibility.matchingCapability(bundle,policy,observation,"port_scan")).isNull();
        observation.put("environment","research");
        assertThat(eligibility.matchingCapability(bundle,policy,observation,"port_scan")).isNull();
    }

    @Test void sharedVectorsMatchExecutorAlgorithm()throws Exception{
        var vectors=parse(Files.readString(Path.of("../docs/contracts/examples/capability-binding-vectors.json")));
        assertThat(node(GuardEligibility.IMPLICIT_PROTECTED_PORTS)).isEqualTo(vectors.get("implicitProtectedPorts"));
        for(var c:vectors.path("protectedPorts")){
            assertThat(node(GuardEligibility.protectedPorts(c.get("input")))).isEqualTo(c.get("effective"));
            assertThat(node(GuardEligibility.unprotectedRanges(c.get("input")))).isEqualTo(c.get("ranges"));
            assertThat(GuardEligibility.protectedPortsSha256(c.get("input"))).isEqualTo(c.path("protectedPortsSha256").asText());}
        for(var ports:vectors.path("invalidProtectedPorts"))assertThatThrownBy(()->GuardEligibility.protectedPorts(ports)).isInstanceOf(ApiRequestException.class);
        for(var c:vectors.path("capabilitySets")){var items=new ArrayList<JsonNode>();c.path("items").forEach(items::add);assertThat(GuardEligibility.capabilitySetSha256(items)).isEqualTo(c.path("capabilitySetSha256").asText());}
    }

    @Test void inboundPassesOnlyWhenAllFiveConditionsHoldInLab(){
        assertThat(inbound()).isNull();
        // 观察端口触及保护端口不影响全入站：规则区间已扣除保护端口。
        assertThat(eligibility.protection(bundle,policy,target,observation.deepCopy().put("servicePort",3389),"port_scan")).isNull();
        Map<String,Consumer<GuardCapabilityBindingTest>> denied=new LinkedHashMap<>();
        denied.put("能力缺失：组合未关联",t->t.facts.tables.get("guard_bundle_capability").clear());
        denied.put("能力缺失：策略未登记",t->t.policy.set("supportedCapabilityIds",node(List.of(id()))));
        denied.put("能力缺失：族不匹配",t->t.capability.put("payload_json",canonical(((ObjectNode)json(t.capability,"payload_json")).put("family","dos_slow"))));
        denied.put("能力缺失：无组合",t->t.bundle=null);
        denied.put("哈希不符：能力保护集",t->t.capability.put("protection_set_sha256","f".repeat(64)));
        denied.put("平台不符",t->t.capability.put("platform","windows"));
        denied.put("范围不符",t->t.capability.putAll(map("scope","peer_service","protection_set_sha256",null,"exemption_evidence_sha256",null)));
        denied.put("等级不足：alert_only",t->t.capability.put("level","alert_only"));
        denied.put("等级不足：research",t->t.capability.put("level","research"));
        denied.put("缺豁免证据",t->t.capability.put("exemption_evidence_sha256",null));
        denied.put("环境不符：authorized",t->{t.observation.put("environment","authorized");t.bundle.put("environment","authorized");t.capability.put("level","authorized_auto");});
        denied.put("环境不符：观察 research",t->t.observation.put("environment","research"));
        denied.put("环境不符：组合 authorized",t->t.bundle.put("environment","authorized"));
        for(var e:denied.entrySet()){var saved=snapshot();e.getValue().accept(this);assertThat(inbound()).as(e.getKey()).isEqualTo("PROTECTED_SERVICE");restore(saved);}
        assertThat(inbound()).isNull();
    }

    @Test void protectionSetMismatchAndServiceScopeKeepExistingReasons()throws Exception{
        policy.put("protectionSetSha256","f".repeat(64));assertThat(inbound()).isEqualTo("PROTECTION_SET_UNVERIFIED");
        policy.put("protectionSetSha256",hash(PROTECTION));policy.put("family","dos_slow");
        assertThat(eligibility.protection(bundle,policy,target,observation,"dos_slow")).isEqualTo("PROTECTED_SERVICE");
        assertThat(eligibility.protection(bundle,policy,target,observation.deepCopy().put("servicePort",443),"dos_slow")).isNull();
        var other=temporary.resolve("other.json");Files.writeString(other,canonical(object("protectedBudgetTargetIds",List.of(),"protectedServicePorts",List.of(22))));
        assertThat(new GuardEligibility(facts,true,other.toString()).protection(bundle,policy.put("family","port_scan"),target,observation,"port_scan")).isEqualTo("PROTECTION_SET_UNVERIFIED");
        var invalid=temporary.resolve("invalid.json");Files.writeString(invalid,canonical(object("protectedBudgetTargetIds",List.of(),"protectedServicePorts",List.of(0))));
        assertThatThrownBy(()->new GuardEligibility(facts,true,invalid.toString())).isInstanceOf(IllegalStateException.class);
    }

    @Test void inboundAuthorizationRejectsScopeEscalationAndExpiredGrant()throws Exception{
        assertThat(eligibility.authorized(asset,bundle,binding,policy,observation,executor,facts.now(),"port_scan")).isTrue();
        // 越权：授权只覆盖单服务范围，不能据此签发全入站。
        authorization.put("scope_json",canonical(object("executionScopes",List.of(object("capabilityId",CAPABILITY,"scope","peer_service","direction","inbound","transport","tcp","addressFamily","ipv4","servicePort",22)))));
        assertThat(eligibility.authorized(asset,bundle,binding,policy,observation,executor,facts.now(),"port_scan")).isFalse();
        authorization.put("scope_json",canonical(object("executionScopes",List.of(object("capabilityId",id(),"scope","peer_inbound","direction","inbound","transport","tcp","addressFamily","ipv4","servicePort",null)))));
        assertThat(eligibility.authorized(asset,bundle,binding,policy,observation,executor,facts.now(),"port_scan")).isFalse();
        lab();authorization.put("valid_until",db(facts.now().plusSeconds(10)));
        assertThat(eligibility.authorized(asset,bundle,binding,policy,observation,executor,facts.now(),"port_scan")).as("租约越过授权期").isFalse();
        authorization.put("valid_until",db(facts.now().minusSeconds(1)));
        assertThat(eligibility.authorized(asset,bundle,binding,policy,observation,executor,facts.now(),"port_scan")).as("过期授权").isFalse();
        lab();authorization.put("status","revoked");
        assertThat(eligibility.authorized(asset,bundle,binding,policy,observation,executor,facts.now(),"port_scan")).isFalse();
    }

    /** T3.8a 评价用绑定：research 级 peer_service 能力在任何环境都不匹配自动路径，授权判定 fail-closed。 */
    @Test void researchServiceCapabilityNeverMatchesAutomaticPaths(){
        capability.putAll(map("level","research","scope","peer_service","protection_set_sha256",null,"exemption_evidence_sha256",null,
                "payload_json",canonical(object("addressFamily","ipv4","transport","tcp","direction","inbound","profile","flow-prefix-v1","family","dos_slow","adapterVersion","pf-1"))));
        policy.put("family","dos_slow");
        authorization.put("scope_json",canonical(object("executionScopes",List.of(object("capabilityId",CAPABILITY,"scope","peer_service","direction","inbound","transport","tcp","addressFamily","ipv4","servicePort",80)))));
        var service=observation.deepCopy().put("servicePort",80);
        for(String env:List.of("lab","authorized","research")){
            bundle.put("environment",env);asset.put("environment",env);
            var o=service.deepCopy().put("environment",env);
            assertThat(eligibility.matchingCapability(bundle,policy,o,"dos_slow")).as(env).isNull();
            assertThat(eligibility.authorized(asset,bundle,binding,policy,o,executor,facts.now(),"dos_slow")).as(env).isFalse();
        }
        // 对照：同一能力升为 lab_auto 后在 lab 匹配，证明上面的拒绝来自等级而非夹具缺项。
        bundle.put("environment","lab");capability.put("level","lab_auto");
        assertThat(eligibility.matchingCapability(bundle,policy,service.deepCopy().put("environment","lab"),"dos_slow")).isNotNull();
    }

    /** research 无执行等级，拒绝无需读取能力表；正式环境仍检查能力事实而非共享这个短路。 */
    @Test void researchCapabilityRefusalDoesNotReadOrParseDeploymentFacts(){
        observation.put("environment","research");capability.put("payload_json","invalid-json");
        facts.reads=0;
        assertThat(eligibility.matchingCapability(bundle,policy,observation,"port_scan")).isNull();
        assertThat(facts.reads).isZero();
        observation.put("environment","lab");
        assertThatThrownBy(()->eligibility.matchingCapability(bundle,policy,observation,"port_scan"))
                .isInstanceOf(ApiRequestException.class).hasMessageContaining("INVALID_REQUEST");
        assertThat(facts.reads).isPositive();
    }

    @Test void executorCapabilityHashBindsActiveCapabilitiesAndCurrentProtection(){
        var inboundItem=object("capabilityId",CAPABILITY,"scope","peer_inbound","protectionSetSha256",hash(PROTECTION),"protectedPortsSha256",GuardEligibility.protectedPortsSha256(PROTECTION.get("protectedServicePorts")));
        assertThat(eligibility.executorCapabilityHash(executor)).isEqualTo(GuardEligibility.capabilitySetSha256(List.of(inboundItem)));
        capability.put("protection_set_sha256","f".repeat(64));
        assertThat(eligibility.executorCapabilityHash(executor)).as("保护集与当前文件不符时不给出端口摘要")
                .isEqualTo(GuardEligibility.capabilitySetSha256(List.of(inboundItem.deepCopy().put("protectionSetSha256","f".repeat(64)).putNull("protectedPortsSha256"))));
        capability.put("protection_set_sha256",hash(PROTECTION));
        for(Consumer<GuardCapabilityBindingTest> excluded:List.<Consumer<GuardCapabilityBindingTest>>of(t->t.capability.put("platform","windows"),t->t.capability.put("level","alert_only"),t->t.bundle.put("status","suspended"),t->t.binding.put("status","suspended"))){
            var saved=snapshot();excluded.accept(this);assertThat(eligibility.executorCapabilityHash(executor)).isEqualTo(GuardEligibility.capabilitySetSha256(List.of()));restore(saved);}
        var ranges=eligibility.inboundRanges("c0mmand",capability);
        assertThat(ranges.get("ranges")).isEqualTo(node(List.of(List.of(1,21),List.of(23,52),List.of(54,3388),List.of(3390,65535))));
        assertThat(ranges.path("protectedPortsSha256").asText()).isEqualTo(inboundItem.path("protectedPortsSha256").asText());
    }

    record Saved(Map<String,Object> bundle,Map<String,Object> capability,Map<String,Object> binding,String policy,String observation,List<Map<String,Object>> links){}
    Saved snapshot(){return new Saved(bundle==null?null:new HashMap<>(bundle),new HashMap<>(capability),new HashMap<>(binding),canonical(policy),canonical(observation),new ArrayList<>(facts.tables.get("guard_bundle_capability")));}
    void restore(Saved s){if(bundle==null)bundle=facts.tables.get("guard_release_bundle").getFirst();bundle.clear();bundle.putAll(s.bundle());capability.clear();capability.putAll(s.capability());binding.clear();binding.putAll(s.binding());
        policy=(ObjectNode)parse(s.policy());observation=(ObjectNode)parse(s.observation());var links=facts.tables.get("guard_bundle_capability");links.clear();links.addAll(s.links());}
}
