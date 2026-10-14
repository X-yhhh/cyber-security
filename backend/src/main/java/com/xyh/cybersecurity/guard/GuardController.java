package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.util.Set;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** v2 人工接口只适配协议；权限、范围、审批、幂等和状态均由应用服务/事务复核。 */
@RestController
@RequestMapping(value="/api/v2",produces=MediaType.APPLICATION_JSON_VALUE)
public class GuardController {
    private final GuardWriteAuthorization authorization;private final GuardAdministration admin;private final GuardCatalog catalog;private final GuardActions actions;private final GuardCases cases;private final GuardQueries queries;private final GuardIdempotency idempotency;private final GuardReplay replay;
    public GuardController(GuardAdministration admin,GuardCatalog catalog,GuardActions actions,GuardCases cases,GuardQueries queries,GuardIdempotency idempotency,GuardWriteAuthorization authorization,GuardReplay replay){this.authorization=authorization;this.admin=admin;this.catalog=catalog;this.actions=actions;this.cases=cases;this.queries=queries;this.idempotency=idempotency;this.replay=replay;}
    @PostMapping(value="/{collection}",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> create(@PathVariable String collection,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,HttpServletRequest request){JsonNode b=parse(raw);authorization.create(collection,b);int status=Set.of("automation-stops","replay-runs").contains(collection)?202:201;boolean credential=collection.equals("sensors")||collection.equals("executors");
        JsonNode result=idempotency.execute("POST:"+request.getRequestURI(),key,b,status,credential,()->switch(collection){
            case "assets"->admin.asset(b);case "sensors"->admin.machine(b,false);case "executors"->admin.machine(b,true);case "datasets"->catalog.dataset(b);case "models"->catalog.model(b);case "evaluation-plans"->catalog.plan(b);case "capabilities"->catalog.capability(b);case "decision-policies"->catalog.policy(b);case "release-bundles"->catalog.bundle(b);case "replay-runs"->catalog.replayRun(b);case "actions"->actions.manual(b);case "automation-stops"->actions.stop(b);case "feedback"->cases.feedback(b);default->throw error(404,"RESOURCE_NOT_FOUND");});return success(result,status,request);}
    @PatchMapping(value="/assets/{id}",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> patchAsset(@PathVariable String id,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,@RequestHeader(value="If-Match",required=false) String revision,HttpServletRequest request){uuid(id);JsonNode b=parse(raw);authorization.operation("assets",id,"updates",b);
        JsonNode fingerprint=object("body",b,"ifMatch",revision);JsonNode result=idempotency.execute("PATCH:"+request.getRequestURI(),key,fingerprint,200,false,()->admin.updateAsset(id,b,revision));return success(result,200,request);}
    @PutMapping(value="/events/{id}/assignee",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> putAssignee(@PathVariable String id,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,@RequestHeader(value="If-Match",required=false) String revision,HttpServletRequest request){uuid(id);JsonNode b=parse(raw);authorization.operation("events",id,"assignee",b);
        JsonNode fingerprint=object("body",b,"ifMatch",revision);JsonNode result=idempotency.execute("PUT:"+request.getRequestURI(),key,fingerprint,200,false,()->cases.assign(id,b,revision));return success(result,200,request);}
    @PostMapping(value="/{collection}/{id}/{operation}",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> operation(@PathVariable String collection,@PathVariable String id,@PathVariable String operation,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,@RequestHeader(value="If-Match",required=false) String revision,HttpServletRequest request){uuid(id);JsonNode b=parse(raw.isBlank()?"{}":raw);authorization.operation(collection,id,operation,b);String route=collection+"/"+operation;int status=switch(operation){case "activations","suspensions","revocations","validations"->202;case "authorizations","configs","sealings","imports","notes"->201;default->200;};boolean credential=operation.equals("credential-rotations")||operation.equals("rotations");
        JsonNode fingerprint=object("body",b,"ifMatch",revision);JsonNode result=idempotency.execute("POST:"+request.getRequestURI(),key,fingerprint,status,credential,()->switch(route){
            case "assets/updates"->admin.updateAsset(id,b,revision);
            case "assets/authorizations"->admin.authorization(id,b);case "authorizations/decisions"->admin.approveAuthorization(id,b,revision);case "authorizations/revocations"->actions.revokeAuthorization(id,b,revision);
            case "sensors/configs"->admin.config(id,b);case "sensors/credential-rotations","sensors/rotations"->admin.rotateMachine(id,b,false);case "executors/credential-rotations","executors/rotations"->admin.rotateMachine(id,b,true);case "machine-clients/revocations"->admin.revokeClient(id,b);
            case "sensor-configs/decisions"->admin.approveConfig(id,b,revision);case "models/validations"->catalog.validation(id,b);
            case "decision-policies/reviews"->catalog.reviewPolicy(id,b,revision);case "release-bundles/imports"->catalog.report(id,b);case "release-bundles/sealings"->catalog.seal(id,b,revision);case "release-bundles/decisions"->catalog.approveBundle(id,b,revision);case "release-bundles/activations"->catalog.activate(id,b,revision);case "release-bundles/suspensions"->actions.suspend(id,b,revision);
            case "replay-runs/starts"->replay.start(id,b);case "replay-runs/completions"->replay.finish(id,b);case "replay-runs/failures"->replay.fail(id,b);case "actions/decisions"->actions.approve(id,b,revision);case "actions/revocations"->actions.revoke(id,b,revision);case "events/transitions"->cases.transition(id,b,revision);case "events/assignee","events/assignments"->cases.assign(id,b,revision);case "events/notes"->cases.note(id,b);case "feedback/reviews"->cases.review(id,b,revision);default->throw error(404,"RESOURCE_NOT_FOUND");});return success(result,status,request);}
    @GetMapping("/{collection}") public JsonNode list(@PathVariable String collection,@RequestParam(required=false) String assetId,@RequestParam(required=false) String status,@RequestParam(required=false) String cursor,@RequestParam(defaultValue="50") int limit,HttpServletRequest request){return envelope(queries.list(collection,assetId,status,cursor,limit),request);}
    @GetMapping("/{collection}/{id}") public JsonNode get(@PathVariable String collection,@PathVariable String id,HttpServletRequest request){return envelope(queries.get(collection,uuid(id)),request);}
    @GetMapping("/{collection}/{id}/{child}") public JsonNode child(@PathVariable String collection,@PathVariable String id,@PathVariable String child,HttpServletRequest request){return envelope(queries.child(collection,uuid(id),child),request);}
    static JsonNode envelope(JsonNode data,HttpServletRequest request){return object("requestId",request.getAttribute(com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE),"data",data,"error",null);}
    static ResponseEntity<JsonNode> success(JsonNode data,int status,HttpServletRequest request){return ResponseEntity.status(status).body(envelope(data,request));}
}
