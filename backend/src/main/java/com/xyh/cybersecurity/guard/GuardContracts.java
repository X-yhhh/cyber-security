package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.*;
import org.springframework.stereotype.Component;
import java.time.Duration;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 按类型执行 rc.2 观测或 rc.3 模型/策略/命令 Schema，另核验时间与特征算术。 */
@Component
public class GuardContracts {
    private final Map<String,JsonSchema> schemas=new HashMap<>();
    private final JsonNode profile;
    private final String profileHash;
    private final String schemaHash;
    public GuardContracts() {
        var factory=JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
        var config=SchemaValidatorsConfig.builder().formatAssertionsEnabled(true).build();
        var hashes=JSON.createObjectNode();
        for(String name:List.of("observation","model-manifest","decision-policy","action-command","action-receipt")) {
            byte[] bytes=resource(name+".schema.json");hashes.put(name,sha(bytes));
            schemas.put(name,factory.getSchema(parse(new String(bytes,java.nio.charset.StandardCharsets.UTF_8)),config));
        }
        schemaHash=hash(hashes);byte[] bytes=resource("feature-profile.json");profileHash=sha(bytes);profile=parse(new String(bytes,java.nio.charset.StandardCharsets.UTF_8));
    }
    private byte[] resource(String name) {
        try(var in=getClass().getResourceAsStream("/guard-contract/"+name)){if(in==null)throw new IllegalStateException("Missing guard contract");return in.readAllBytes();}
        catch(java.io.IOException e){throw new IllegalStateException(e);}
    }
    public JsonNode profile(){return profile.deepCopy();}
    public String profileHash(){return profileHash;}
    public String schemaHash(){return schemaHash;}
    public void validate(String type,JsonNode n){require(schemas.get(type).validate(n).isEmpty(),"CONTRACT_INVALID");canonical(n);}
    public void observation(JsonNode n) {
        validate("observation",n);
        var first=time(n,"firstSeenAt");var last=time(n,"lastPacketAt");var asOf=time(n,"asOf");var emitted=time(n,"emittedAt");
        require(!first.isAfter(last)&&!last.isAfter(asOf)&&!asOf.isAfter(emitted),"INVALID_OBSERVATION_TIME");
        JsonNode f=n.get("features");
        require(Math.abs(Duration.between(first,asOf).toNanos()/1_000_000d-f.path("elapsedMs").asDouble())<0.000001,"INVALID_ELAPSED_TIME");
        long count=f.path("packetsInbound").asLong()+f.path("packetsOutbound").asLong();require(count>0,"EMPTY_OBSERVATION");
        require(f.path("lengthMin").asDouble()<=f.path("lengthMean").asDouble()&&f.path("lengthMean").asDouble()<=f.path("lengthMax").asDouble(),"INVALID_LENGTH_STATISTICS");
        require((count<2)==f.path("iatMeanUs").isNull()&&(count<2)==f.path("iatStdUs").isNull(),"INVALID_MISSING_FEATURE");
        int i=0;int[] windows={1,5,30};
        for(JsonNode c:n.get("contexts")){require(c.path("windowSeconds").asInt()==windows[i++]&&c.path("coverageMs").asLong()<=c.path("windowSeconds").asLong()*1000,"INVALID_CONTEXT_WINDOW");}
        if(!n.path("targetRef").isNull())require(!time(n,"targetExpiresAt").isAfter(last.plusSeconds(15))&&!time(n,"targetExpiresAt").isBefore(last),"TARGET_REF_STALE");
    }
    public void manifest(JsonNode n) {
        validate("model-manifest",n);
        require(profileHash.equals(n.path("featureProfileSha256").asText())&&profile.get("numericFeatures").equals(n.get("numericFeatures"))
                &&profile.get("categoricalFeatures").equals(n.get("categoricalFeatures")),"PROFILE_HASH_MISMATCH");
        JsonNode order=n.at("/outputContract/familyScoreOrder");
        require(order.isArray()&&order.size()==4,"CAPABILITY_NOT_SUPPORTED");
        List<String> expected=List.of("port_scan","brute_force","dos_flood","dos_slow");
        require(expected.equals(JSON.convertValue(order,List.class)),"CAPABILITY_NOT_SUPPORTED");
        for(JsonNode scope:n.get("supportedScope"))require(scope.path("minimumCoverageMs").asLong()<=scope.path("coverageWindowSeconds").asLong()*1000,"CONTEXT_CONDITION_UNMET");
    }
    /** 四类参数完整且唯一；规则只允许访问已冻结的观察数值字段，不能引用标签或身份。 */
    public void policy(JsonNode n){validate("decision-policy",n);require(POLICY_CONTRACT.equals(n.path("contractVersion").asText()),"CONTRACT_UNSUPPORTED");
        Set<String> families=new HashSet<>();for(JsonNode p:n.get("familyPolicies")){
            String family=p.path("family").asText();require(families.add(family),"INVALID_FAMILY_POLICIES");
            require(p.path("scope").asText().equals(family.equals("port_scan")?"peer_inbound":"peer_service"),"INVALID_FAMILY_SCOPE");
            require(p.path("autoThreshold").asDouble()>=p.path("alertThreshold").asDouble(),"INVALID_POLICY_THRESHOLDS");
            require(!p.path("modelAutoEligible").asBoolean()||p.path("autoEligible").asBoolean(),"INVALID_FAMILY_POLICIES");
        }
        require(families.equals(Set.of("port_scan","brute_force","dos_flood","dos_slow")),"INVALID_FAMILY_POLICIES");
        Set<String> ids=new HashSet<>();for(JsonNode r:n.path("rulePolicies")){
            require(ids.add(r.path("ruleId").asText()),"INVALID_RULE_POLICY");
            require(GuardAdministration.contains(profile.path("numericFeatures"),r.path("field").asText()),"INVALID_RULE_FIELD");
        }
        require(n.path("autoThreshold").asDouble()>=n.path("alertThreshold").asDouble()&&n.path("minEvidenceSpanMs").asLong()<=n.path("maxEvidenceAgeMs").asLong(),"INVALID_POLICY_THRESHOLDS");}
}
