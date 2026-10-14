package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 只允许资料列，显式 null 可清空；这些值不得用于冻结摘要、授权范围或执行判定。 */
final class GuardMetadata {
    private GuardMetadata() { }
    static Map<String,Object> values(JsonNode body) {
        var values=map();
        if(body.has("displayName"))values.put("display_name",optional(body,"displayName",128,false));
        if(body.has("notes"))values.put("notes",optional(body,"notes",1000,true));
        return values;
    }
    static String reason(JsonNode body) {
        String value=optional(body,"reason",1000,false);
        if(value==null)throw error(400,"INVALID_REQUEST");
        return value;
    }
    private static String optional(JsonNode body,String field,int max,boolean empty) {
        JsonNode value=body.get(field);
        if(value==null||value.isNull())return null;
        if(!value.isTextual())throw error(400,"INVALID_REQUEST");
        String text=value.asText().trim();
        if(text.length()>max||(!empty&&text.isEmpty()))throw error(400,"INVALID_REQUEST");
        return text;
    }
}
