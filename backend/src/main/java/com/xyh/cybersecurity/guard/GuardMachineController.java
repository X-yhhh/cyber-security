package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 专用机器路由，sensor 与 executor 类型/范围不能互换，不信任 session。 */
@RestController
@RequestMapping(value="/api/v2/machine",produces=MediaType.APPLICATION_JSON_VALUE)
public class GuardMachineController {
    private final GuardAccess access;private final GuardIdempotency idem;private final GuardIngest ingest;private final GuardHealth health;private final GuardBudget budget;private final GuardActions actions;private final GuardReceipts receipts;private final GuardStore store;
    public GuardMachineController(GuardAccess access,GuardIdempotency idem,GuardIngest ingest,GuardHealth health,GuardBudget budget,GuardActions actions,GuardReceipts receipts,GuardStore store){this.access=access;this.idem=idem;this.ingest=ingest;this.health=health;this.budget=budget;this.actions=actions;this.receipts=receipts;this.store=store;}
    @GetMapping("/sensors/{id}/config") public JsonNode config(@PathVariable String id,HttpServletRequest request){return GuardController.envelope(ingest.config(uuid(id)),request);}
    @PostMapping(value="/{kind}/{id}/{operation}",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> write(@PathVariable String kind,@PathVariable String id,@PathVariable String operation,@RequestHeader("Idempotency-Key") String key,@RequestBody String raw,HttpServletRequest request){uuid(id);JsonNode b=parse(raw);String route=kind+"/"+operation;
        String permission=switch(route){case "sensors/observation-batches"->"machine.observation.write";case "sensors/heartbeats","sensors/health-windows"->"machine.sensor.health";case "executors/target-bindings","executors/budget-proofs"->"machine.target.bind";case "executors/heartbeats"->"machine.executor.health";case "executors/receipts","executors/reconciliations","executors/clearance-proofs"->"machine.receipt.write";case "executors/command-claims"->"machine.command.claim";default->throw error(404,"RESOURCE_NOT_FOUND");};
        // 重放响应前仍核验当前机器身份和具体资源，吊销后不能读取缓存结果。
        if(kind.equals("sensors"))access.sensor(id,permission);else access.executor(id,permission);
        int status=operation.equals("observation-batches")?202:operation.equals("target-bindings")?201:200;
        JsonNode data=idem.execute("POST:"+request.getRequestURI(),key,b,status,false,()->switch(route){
            case "sensors/observation-batches"->ingest.batches(id,b);case "sensors/heartbeats"->ingest.heartbeat(id,b);
            case "sensors/health-windows"->{JsonNode result=health.accept(id,b);if("healthy".equals(result.path("verificationStatus").asText())){var sensor=access.sensor(id,"machine.sensor.health");long aid=number(sensor,"asset_id");for(var target:store.rows("guard_budget_target",map("asset_id",aid),false,10000))budget.recover(aid,number(target,"id"),store.now());}yield result;}
            case "executors/target-bindings"->budget.bind(id,b);case "executors/budget-proofs"->budget.proof(id,b);case "executors/heartbeats"->receipts.heartbeat(id,b);case "executors/command-claims"->actions.claims(id,b);case "executors/receipts"->receipts.receipt(id,b);case "executors/reconciliations"->receipts.reconcile(id,b);case "executors/clearance-proofs"->receipts.clearance(id,b);default->throw error(404,"RESOURCE_NOT_FOUND");});if(operation.equals("command-claims"))data=actions.filterClaims(id,data);return GuardController.success(data,status,request);}
}
