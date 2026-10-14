package com.xyh.cybersecurity.iam;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Set;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 身份 v2 协议适配；所有写入及重放的授权、状态和事务规则都由 IamService 校验。 */
@RestController
@RequestMapping(value="/api/v2",produces=MediaType.APPLICATION_JSON_VALUE)
public class IamController {
    private final IamService service;
    public IamController(IamService service) { this.service=service; }

    @GetMapping("/roles")
    public JsonNode roles(HttpServletRequest request) { query(request,Set.of());return envelope(service.roles(),request); }

    @GetMapping("/users")
    public JsonNode users(@RequestParam(required=false) String status,@RequestParam(required=false) String q,
                          @RequestParam(required=false) String cursor,@RequestParam(defaultValue="50") int limit,
                          HttpServletRequest request) {
        query(request,Set.of("status","q","cursor","limit"));
        return envelope(service.users(status,q,cursor,limit),request);
    }

    @GetMapping("/users/{id}")
    public JsonNode user(@PathVariable long id,HttpServletRequest request) {
        query(request,Set.of());return envelope(service.user(id),request);
    }

    @GetMapping("/users/{id}/role-bindings")
    public JsonNode bindings(@PathVariable long id,HttpServletRequest request) {
        query(request,Set.of());return envelope(service.bindings(id),request);
    }

    @PostMapping(value="/users",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> create(@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,HttpServletRequest request) {
        return ResponseEntity.status(201).body(envelope(service.create(parse(raw),key,request),request));
    }

    @PatchMapping(value="/users/{id}",consumes=MediaType.APPLICATION_JSON_VALUE)
    public JsonNode rename(@PathVariable long id,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,
                            @RequestHeader(value="If-Match",required=false) String revision,HttpServletRequest request) {
        return envelope(service.rename(id,parse(raw),revision,key,request),request);
    }

    @PostMapping(value="/users/{id}/status-changes",consumes=MediaType.APPLICATION_JSON_VALUE)
    public JsonNode status(@PathVariable long id,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,
                            @RequestHeader(value="If-Match",required=false) String revision,HttpServletRequest request) {
        return envelope(service.status(id,parse(raw),revision,key,request),request);
    }

    @PostMapping(value="/users/{id}/password-resets",consumes=MediaType.APPLICATION_JSON_VALUE)
    public JsonNode reset(@PathVariable long id,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,HttpServletRequest request) {
        return envelope(service.reset(id,parse(raw),key,request),request);
    }

    @PostMapping(value="/users/{id}/role-bindings",consumes=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> bind(@PathVariable long id,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,
                                         HttpServletRequest request) {
        return ResponseEntity.status(201).body(envelope(service.bind(id,parse(raw),key,request),request));
    }

    @PostMapping(value="/role-bindings/{id}/revocations",consumes=MediaType.APPLICATION_JSON_VALUE)
    public JsonNode revoke(@PathVariable long id,@RequestBody String raw,@RequestHeader("Idempotency-Key") String key,HttpServletRequest request) {
        return envelope(service.revoke(id,parse(raw),key,request),request);
    }

    static JsonNode envelope(JsonNode data,HttpServletRequest request) {
        return object("data",data,"error",null,"requestId",request.getAttribute(REQUEST_ID_ATTRIBUTE));
    }

    static void query(HttpServletRequest request,Set<String> allowed) {
        request.getParameterMap().forEach((key,values) -> {
            if(!allowed.contains(key) || values.length!=1 || values[0].isBlank()) throw error(400,"INVALID_QUERY");
        });
    }
}
