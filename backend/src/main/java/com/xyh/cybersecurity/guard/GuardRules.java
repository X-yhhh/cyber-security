package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;

/** 只读取冻结数值特征；缺失或非有限值形成不适用事实，不补零、不依赖模型推理成功。 */
public final class GuardRules {
    private GuardRules(){}
    public record Result(boolean applicable,boolean matched,JsonNode value){}
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
