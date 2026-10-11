package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.common.web.RequestIdFilter;

/** 明确路径优先于通用集合路由；仅协议适配，不在控制器解释资格或执行命令。 */
@RestController
@RequestMapping(value="/api/v2",produces=MediaType.APPLICATION_JSON_VALUE)
public class GuardLabController {
    private final GuardLabSessions sessions;
    private final GuardIdempotency idempotency;
    private final GuardLabAudit audit;
    public GuardLabController(GuardLabSessions sessions,GuardIdempotency idempotency,GuardLabAudit audit) {this.sessions=sessions;this.idempotency=idempotency;this.audit=audit;}
    @PostMapping(value="/lab-validation-runs",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> create(@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,HttpServletRequest request) {
        return write(null,request,()-> {
            var b=parse(raw);sessions.authorizeCreate(b);
            return GuardController.success(idempotency.execute("POST:"+request.getRequestURI(),key,b,201,false,()->sessions.create(b)),201,request);
        });
    }
    @PostMapping(value="/lab-validation-runs/{id}/{operation}",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> operate(@PathVariable String id,@PathVariable String operation,@RequestBody String raw,
            @RequestHeader("Idempotency-Key") String key,@RequestHeader(value="If-Match",required=false) String revision,HttpServletRequest request) {
        uuid(id);
        return write(id,request,()-> {
            var b=parse(raw);sessions.authorize(id,operation);
            var result=idempotency.execute("POST:"+request.getRequestURI(),key,object("body",b,"ifMatch",revision),200,false,
                    ()->sessions.operate(id,operation,b,revision));return GuardController.success(result,200,request);
        });
    }
    /** 字面路径优先于 GuardController 的通用 /{collection}；GuardQueries 不登记 lab 表，列表只经本服务的资产范围查询。 */
    @GetMapping("/lab-validation-runs")
    public JsonNode list(@RequestParam(required=false) String cursor,@RequestParam(required=false) String status,
                         @RequestParam(defaultValue="50") int limit,HttpServletRequest request) {
        return GuardController.envelope(sessions.list(cursor,status,limit),request);
    }
    @GetMapping("/lab-validation-runs/{id}")
    public JsonNode get(@PathVariable String id,HttpServletRequest request) {return GuardController.envelope(sessions.get(id),request);}
    @GetMapping("/lab-validation-runs/{id}/events")
    public JsonNode events(@PathVariable String id,@RequestParam(defaultValue="0") long after,@RequestParam(defaultValue="50") int limit,HttpServletRequest request) {
        return GuardController.envelope(sessions.events(id,after,limit),request);
    }
    @GetMapping("/lab-validation-runs/{id}/report-input")
    public JsonNode reportInput(@PathVariable String id,HttpServletRequest request) {return GuardController.envelope(sessions.reportInput(id),request);}
    @GetMapping("/machine/sensors/{sensorId}/lab-validation-runs/{id}")
    public JsonNode machine(@PathVariable String sensorId,@PathVariable String id,HttpServletRequest request) {return GuardController.envelope(sessions.machine(sensorId,id),request);}

    private ResponseEntity<JsonNode> write(String id,HttpServletRequest request,java.util.function.Supplier<ResponseEntity<JsonNode>> work) {
        try {return work.get();}
        catch(ApiRequestException failure) {
            audit.denied(id,(String)request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE),failure.code());throw failure;
        }
        catch(org.springframework.dao.ConcurrencyFailureException conflict) {
            // 不重试执行操作；让调用方重新读取 revision，已回滚的竞争请求不会变成 500 或重复副作用。
            audit.denied(id,(String)request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE),"LAB_CONCURRENT_UPDATE");
            throw error(409,"LAB_CONCURRENT_UPDATE");
        }
    }
}
