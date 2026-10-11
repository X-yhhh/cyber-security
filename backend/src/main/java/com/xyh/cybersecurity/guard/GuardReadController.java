package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.xyh.cybersecurity.guard.GuardReadMapper.Kind.*;

/** B5 固定只读路由比既有集合通配路由更具体；写接口和原有查询行为保持独立。 */
@RestController
@RequestMapping(value = "/api/v2", produces = MediaType.APPLICATION_JSON_VALUE)
public class GuardReadController {
    private final GuardReadQueries queries;

    public GuardReadController(GuardReadQueries queries) { this.queries = queries; }

    @GetMapping("/authorizations")
    public JsonNode authorizations(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(AUTHORIZATIONS, p), r);
    }

    @GetMapping("/authorizations/{id}")
    public JsonNode authorization(@PathVariable String id, HttpServletRequest r) {
        return GuardController.envelope(queries.get(AUTHORIZATIONS, id), r);
    }

    @GetMapping("/sensor-configs")
    public JsonNode configs(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(CONFIGS, p), r);
    }

    @GetMapping("/sensor-configs/{id}")
    public JsonNode config(@PathVariable String id, HttpServletRequest r) {
        return GuardController.envelope(queries.get(CONFIGS, id), r);
    }

    @GetMapping("/audit")
    public JsonNode audit(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(AUDIT, p), r);
    }

    @GetMapping("/health-windows")
    public JsonNode healthWindows(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(HEALTH, p), r);
    }

    @GetMapping("/health-windows/{id}")
    public JsonNode healthWindow(@PathVariable String id, HttpServletRequest r) {
        return GuardController.envelope(queries.get(HEALTH, id), r);
    }

    @GetMapping("/sensor-heartbeats")
    public JsonNode sensors(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(SENSORS, p), r);
    }

    @GetMapping("/sensor-heartbeats/{id}")
    public JsonNode sensor(@PathVariable String id, HttpServletRequest r) {
        return GuardController.envelope(queries.get(SENSORS, id), r);
    }

    @GetMapping("/executor-heartbeats")
    public JsonNode executors(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(EXECUTORS, p), r);
    }

    @GetMapping("/executor-heartbeats/{id}")
    public JsonNode executor(@PathVariable String id, HttpServletRequest r) {
        return GuardController.envelope(queries.get(EXECUTORS, id), r);
    }

    @GetMapping("/ops/status")
    public JsonNode ops(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(OPS, p), r);
    }
}
