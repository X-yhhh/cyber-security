package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Arrays;

/** 只读取冻结数值特征；缺失或非有限值形成不适用事实，不补零、不依赖模型推理成功。 */
public final class GuardRules {
    private GuardRules(){}
    /** 策略版本以“+”分隔的标记显式选用：窗口规则只对 inbound 观察适用（BE-10 第 3 条 C1a）。旧版本策略行为不变。 */
    public static final String INBOUND_ONLY_TOKEN="rule-inbound-20261018";
    public static final String RULE_VERSION="host-guard-rules/1";
    public static final String INBOUND_ONLY_RULE_VERSION=RULE_VERSION+"+inbound-20261018";
    public static final String DIRECTION_NOT_APPLICABLE="RULE_DIRECTION_NOT_APPLICABLE";
    /** reason 仅在新口径的方向前置拒绝时给出；旧口径与缺值保持 null，旧规则事实字节不变。 */
    public record Result(boolean applicable,boolean matched,JsonNode value,String reason){
        public Result(boolean applicable,boolean matched,JsonNode value){this(applicable,matched,value,null);}
    }
    public static boolean inboundOnly(JsonNode policy){
        return Arrays.asList(policy.path("policyVersion").asText().split("\\+")).contains(INBOUND_ONLY_TOKEN);
    }
    public static String ruleVersion(JsonNode policy){return inboundOnly(policy)?INBOUND_ONLY_RULE_VERSION:RULE_VERSION;}
    /** 按策略口径判定：新口径下 unknown/outbound 观察的上下文混有本机发起的连接与下载，不能当作对端行为。 */
    public static Result evaluate(JsonNode policy,JsonNode rule,JsonNode observation){
        Result result=evaluate(rule,observation);
        if(inboundOnly(policy)&&!"inbound".equals(observation.path("direction").asText()))return new Result(false,false,result.value(),DIRECTION_NOT_APPLICABLE);
        return result;
    }
    public static Result evaluate(JsonNode rule,JsonNode observation){
        String[] parts=rule.path("field").asText().split("\\.");JsonNode value=observation;
        if(parts.length==3&&parts[0].equals("contexts")){
            value=null;for(JsonNode context:observation.path("contexts"))if(parts[1].equals(context.path("windowSeconds").asText()))value=context.path(parts[2]);
        }else for(String part:parts)value=value.path(part);
        if(value==null||(!value.isNumber()&&!value.isBoolean()))return new Result(false,false,value);
        double x=value.isBoolean()?(value.asBoolean()?1:0):value.asDouble(),t=rule.path("threshold").asDouble();
        if(!Double.isFinite(x))return new Result(false,false,value);
        boolean matched=switch(rule.path("operator").asText()){case "gte"->x>=t;case "gt"->x>t;case "lte"->x<=t;case "lt"->x<t;case "eq"->x==t;default->false;};
        return new Result(true,matched,value);
    }
}
