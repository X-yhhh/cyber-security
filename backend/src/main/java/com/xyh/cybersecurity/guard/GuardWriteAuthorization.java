package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 幂等结果读取同样受当前权限约束，撤销角色/范围后不可重放以前成功的写响应。 */
@Service
public class GuardWriteAuthorization {
    private final GuardAccess access;private final GuardStore store;
    public GuardWriteAuthorization(GuardAccess access,GuardStore store){this.access=access;this.store=store;}
    public void create(String collection,JsonNode b){String permission=switch(collection){case "assets"->"asset.manage";case "sensors","executors"->"sensor.manage";case "datasets"->"dataset.manage";case "models"->"model.manage";case "evaluation-plans","replay-runs"->"evaluation.run";case "capabilities","release-bundles"->"bundle.request";case "decision-policies"->"policy.draft";case "actions"->"action.request";case "automation-stops"->"automation.stop";case "feedback"->"feedback.label";default->throw error(404,"RESOURCE_NOT_FOUND");};
        Long asset=null;if(Set.of("sensors","executors").contains(collection))asset=number(store.external("asset",uuid(b,"assetId"),false),"id");
        else if(collection.equals("actions"))asset=number(store.external("guard_episode",uuid(b,"episodeId"),false),"asset_id");else if(collection.equals("feedback"))asset=number(store.external("guard_observation",uuid(b,"observationId"),false),"asset_id");
        if(collection.equals("automation-stops")){require(b.path("assetIds").isArray()&&!b.path("assetIds").isEmpty(),"INVALID_REQUEST");for(var a:b.get("assetIds"))access.permission(permission,number(store.external("asset",uuid(a.asText()),false),"id"));}else access.permission(permission,asset);}
    public void operation(String collection,String id,String operation,JsonNode b){String route=collection+"/"+operation;
        String permission=switch(route){case "assets/authorizations"->"authorization.request";case "sensors/configs"->"sensor.manage";case "authorizations/decisions","authorizations/revocations","sensor-configs/decisions","actions/decisions"->"authorization.approve";case "models/validations"->"model.validate";case "decision-policies/reviews"->"policy.approve";case "release-bundles/imports"->"evaluation.run";case "release-bundles/sealings"->"bundle.request";case "release-bundles/decisions","release-bundles/activations"->"bundle.approve";case "release-bundles/suspensions"->"automation.stop";case "actions/revocations"->"action.revoke";case "events/transitions","events/notes"->"event.manage";case "feedback/reviews"->"feedback.review";default->throw error(404,"RESOURCE_NOT_FOUND");};
        String table=switch(collection){case "assets"->"asset";case "sensors"->"sensor_agent";case "authorizations"->"asset_authorization";case "sensor-configs"->"sensor_config";case "actions"->"guard_action";case "events"->"security_event";case "feedback"->"guard_feedback";default->null;};
        Long asset=null;if(table!=null){var r=store.external(table,id,false);if(table.equals("asset"))asset=number(r,"id");else if(table.equals("sensor_config"))asset=number(store.get("sensor_agent",number(r,"sensor_id")),"asset_id");else if(table.equals("security_event")){require(r.get("guard_asset_id")!=null,"RESOURCE_NOT_FOUND");asset=number(r,"guard_asset_id");}else asset=number(r,"asset_id");}
        access.permission(permission,asset);
        if(operation.equals("activations"))for(var a:b.path("assetIds"))access.permission(permission,number(store.external("asset",uuid(a.asText()),false),"id"));
    }
}
