package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import org.erdtman.jcs.JsonCanonicalizer;
import org.springframework.http.HttpStatus;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.regex.Pattern;

/** v2 的严格 JSON、UTC 时间和 RFC8785 摘要边界；异常只返回字段名/稳定码。 */
public final class GuardJson {
    public static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    /** 固定格式只编译一次；每次独立 matcher，保持严格全串匹配及原有失败码。 */
    private static final Pattern UUID_PATTERN=Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern DIGEST_PATTERN=Pattern.compile("[0-9a-f]{64}");
    private static final Pattern TIMESTAMP_PATTERN=Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,6})?Z");
    /** 观测结构保持 rc.2；模型与命令的多分类结构使用 rc.3；策略因按来源开关自动（modelAutoEligible）单独升至 rc.4。 */
    public static final String CONTRACT = "host-guard/5.0.0-rc.2";
    public static final String MODEL_CONTRACT = "host-guard/5.0.0-rc.3";
    public static final String ACTION_CONTRACT = MODEL_CONTRACT;
    public static final String POLICY_CONTRACT = "host-guard/5.0.0-rc.4";
    /** 2026-10-08.1：模型来源须 familyPolicies[].modelAutoEligible=true 才进入自动路径；旧版本策略不再可激活。 */
    public static final String DECISION = "host-guard-decision/2026-10-08.1";
    public static final String HEALTH = "host-guard-capture-health/1.0.0";
    /** 第二轮候选按 2026-10-08.1 评价（单对端准入、按来源资格）；2026-10-07.1 只解释 candidate-v2，仅平台能力报告仍可携带。 */
    public static final String EVALUATION = "host-guard-evaluation/2026-10-08.1";
    public static final String LEGACY_PLATFORM_EVALUATION = "host-guard-evaluation/2026-10-07.1";
    private GuardJson() { }
    public static ApiRequestException error(int status, String code) {
        return new ApiRequestException(HttpStatus.valueOf(status), code, "请求不满足 v2 契约：" + code);
    }
    public static void require(boolean ok, String code) { if (!ok) throw error(422, code); }
    public static JsonNode parse(String text) {
        try { return JSON.readTree(text); } catch (Exception e) { throw error(400,"INVALID_REQUEST"); }
    }
    public static JsonNode node(Object value) { return JSON.valueToTree(value); }
    public static ObjectNode object(Object... fields) {
        ObjectNode n=JSON.createObjectNode();
        for(int i=0;i<fields.length;i+=2)n.set((String)fields[i],node(fields[i+1]));
        return n;
    }
    public static String canonical(JsonNode value) {
        try { return new JsonCanonicalizer(JSON.writeValueAsString(value)).getEncodedString(); }
        catch(Exception e) { throw error(400,"INVALID_JSON_NUMBER_OR_UNICODE"); }
    }
    private static final long MAX_FACT_INTEGER=9_007_199_254_740_991L;
    /**
     * 仅供服务端已构造事实的窄范围编码，不能替代输入校验。
     * 标准节点中的无转义 ASCII、布尔、null 与安全整数可直接输出；对象键使用 JCS 的 UTF-16 自然序。
     * 任一节点、键或值不在该范围时，整份事实回退原 canonical，保留其数值、Unicode 及失败语义。
     */
    public static String canonicalFact(JsonNode value){
        // 当前 JCS 1.1 只接受 object/array 根；不能让本优化扩大原接口接受的根类型。
        if(value==null||(value.getClass()!=ObjectNode.class&&value.getClass()!=ArrayNode.class))return canonical(value);
        var encoded=new StringBuilder(512);
        return appendFact(value,encoded,0)?encoded.toString():canonical(value);
    }
    /** 只接纳标准 Jackson 节点；特殊子类与过深对象也回退，避免旁路其序列化规则。 */
    private static boolean appendFact(JsonNode value,StringBuilder encoded,int depth){
        if(value==null||depth>128)return false;
        Class<?> type=value.getClass();
        if(type==ObjectNode.class){
            var names=new ArrayList<String>(value.size());
            var fields=value.fieldNames();
            while(fields.hasNext()){String name=fields.next();if(!factText(name))return false;names.add(name);}
            Collections.sort(names);encoded.append('{');boolean first=true;
            for(String name:names){
                if(!first)encoded.append(',');first=false;
                encoded.append('"').append(name).append("\":");
                if(!appendFact(value.get(name),encoded,depth+1))return false;
            }
            encoded.append('}');return true;
        }
        if(type==ArrayNode.class){
            encoded.append('[');boolean first=true;
            for(JsonNode item:value){if(!first)encoded.append(',');first=false;if(!appendFact(item,encoded,depth+1))return false;}
            encoded.append(']');return true;
        }
        if(type==NullNode.class){encoded.append("null");return true;}
        if(type==BooleanNode.class){encoded.append(value.booleanValue());return true;}
        if(type==TextNode.class){
            String text=value.textValue();if(!factText(text))return false;
            encoded.append('"').append(text).append('"');return true;
        }
        if(type==IntNode.class||type==LongNode.class||type==ShortNode.class||type==BigIntegerNode.class){
            if(!value.canConvertToLong())return false;long integer=value.longValue();
            if(integer < -MAX_FACT_INTEGER||integer > MAX_FACT_INTEGER)return false;
            encoded.append(integer);return true;
        }
        return false;
    }
    /** JSON 中无需转义的可打印 ASCII；引号、反斜杠和所有控制/非 ASCII 字符交给原实现。 */
    private static boolean factText(String value){
        if(value==null)return false;
        for(int i=0;i<value.length();i++){char c=value.charAt(i);if(c<0x20||c>0x7e||c=='"'||c=='\\')return false;}
        return true;
    }
    public static String hash(JsonNode value) { return sha(canonical(value).getBytes(StandardCharsets.UTF_8)); }
    public static String sha(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch(Exception e) { throw new IllegalStateException(e); }
    }
    public static void fields(JsonNode n, String required, String optional) {
        if(n==null||!n.isObject())throw error(400,"INVALID_REQUEST");
        Set<String> allowed=new HashSet<>(Arrays.asList((required+" "+optional).split(" +")));
        n.fieldNames().forEachRemaining(f->{if(!allowed.contains(f))throw error(400,"UNKNOWN_FIELD");});
        for(String f:required.split(" +"))if(!f.isEmpty()&&!n.has(f))throw error(400,"MISSING_FIELD");
    }
    public static String text(JsonNode n,String field) {
        JsonNode v=n.path(field);if(!v.isTextual()||v.asText().isBlank()||v.asText().length()>1000)throw error(400,"INVALID_REQUEST");
        return v.asText();
    }
    public static String uuid(JsonNode n,String f) { return uuid(text(n,f)); }
    public static String uuid(String v) {
        if(v==null||!UUID_PATTERN.matcher(v).matches())throw error(400,"INVALID_UUID");
        return v;
    }
    public static String digest(JsonNode n,String f) {String v=text(n,f);require(DIGEST_PATTERN.matcher(v).matches(),"INVALID_HASH");return v;}
    public static long integer(JsonNode n,String f,long min,long max) {
        JsonNode v=n.path(f);if(!v.isIntegralNumber()||!v.canConvertToLong()||v.longValue()<min||v.longValue()>max)throw error(400,"INVALID_REQUEST");return v.longValue();
    }
    public static boolean bool(JsonNode n,String f) {if(!n.path(f).isBoolean())throw error(400,"INVALID_REQUEST");return n.get(f).booleanValue();}
    public static Instant time(JsonNode n,String f) { return time(text(n,f)); }
    public static Instant time(String v) {
        try {if(!TIMESTAMP_PATTERN.matcher(v).matches())throw new IllegalArgumentException(); return Instant.parse(v);}
        catch(Exception e) {throw error(400,"INVALID_TIMESTAMP");}
    }
    public static LocalDateTime db(Instant i) { return i==null?null:LocalDateTime.ofInstant(i,ZoneOffset.UTC); }
    public static Instant instant(Object o) {if(o==null)return null;if(o instanceof LocalDateTime d)return d.toInstant(ZoneOffset.UTC);if(o instanceof java.util.Date d)return d.toInstant();return time(o.toString());}
    public static String id() {return UUID.randomUUID().toString();}
    public static Map<String,Object> map(Object... kv) {Map<String,Object> m=new LinkedHashMap<>();for(int i=0;i<kv.length;i+=2)m.put((String)kv[i],kv[i+1]);return m;}
    public static long number(Map<String,Object> r,String k) {return ((Number)r.get(k)).longValue();}
    public static String str(Map<String,Object> r,String k) {Object v=r.get(k);return v==null?null:v.toString();}
    /** 判定只读作用域内按原字符串实例复用解析结果；作用域外每次解析，行为不变。调用方不得修改返回的节点。 */
    static final ThreadLocal<java.util.IdentityHashMap<Object,JsonNode>> PARSED=new ThreadLocal<>();
    public static JsonNode json(Map<String,Object> r,String k) {Object v=r.get(k);if(v==null)return NullNode.instance;
        var cache=PARSED.get();if(cache==null)return parse(v.toString());
        var hit=cache.get(v);if(hit==null){hit=parse(v.toString());cache.put(v,hit);}return hit;}
    public static void versions(JsonNode n) {
        fields(n,"observation decision evaluation health","");
        require(CONTRACT.equals(n.path("observation").asText())&&DECISION.equals(n.path("decision").asText())
                &&EVALUATION.equals(n.path("evaluation").asText())&&HEALTH.equals(n.path("health").asText()),"CONTRACT_UNSUPPORTED");
    }
    /** 平台能力报告只证明执行器在该平台的封禁/恢复，不承载评价口径；兼容 T3.8b 以旧评价版本签发的报告。 */
    public static void platformVersions(JsonNode n) {
        fields(n,"observation decision evaluation health","");
        require(CONTRACT.equals(n.path("observation").asText())&&DECISION.equals(n.path("decision").asText())
                &&Set.of(EVALUATION,LEGACY_PLATFORM_EVALUATION).contains(n.path("evaluation").asText())&&HEALTH.equals(n.path("health").asText()),"CONTRACT_UNSUPPORTED");
    }
    public static JsonNode versions() {return object("observation",CONTRACT,"decision",DECISION,"evaluation",EVALUATION,"health",HEALTH);}
}
