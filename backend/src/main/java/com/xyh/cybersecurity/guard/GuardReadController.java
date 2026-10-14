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
    private final GuardSummary summary;
    private final GuardLiveStats liveStats;

    public GuardReadController(GuardReadQueries queries, GuardSummary summary, GuardLiveStats liveStats) {
        this.queries = queries;
        this.summary = summary;
        this.liveStats = liveStats;
    }

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

    @GetMapping("/machine-clients")
    public JsonNode machineClients(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(MACHINE_CLIENTS, p), r);
    }

    @GetMapping("/machine-clients/{id}")
    public JsonNode machineClient(@PathVariable String id, HttpServletRequest r) {
        return GuardController.envelope(queries.get(MACHINE_CLIENTS, id), r);
    }

    @GetMapping("/assignable-users")
    public JsonNode assignableUsers(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(queries.list(ASSIGNABLE_USERS, p), r);
    }

    @GetMapping("/summary")
    public JsonNode summary(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(summary.summary(p), r);
    }

    /** B5.2 实时态势统计：按权限裁剪序列，无采集覆盖的桶为 null（见 GuardLiveStats）。 */
    @GetMapping("/stats/live")
    public JsonNode live(@RequestParam MultiValueMap<String, String> p, HttpServletRequest r) {
        return GuardController.envelope(liveStats.live(p), r);
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
