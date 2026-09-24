package com.xyh.cybersecurity.ops;

import com.xyh.cybersecurity.common.api.ApiEnvelope;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 提供不含运行配置或依赖凭据的存活与就绪探针。 */
@RestController
@RequestMapping("/api/v1/health")
public class HealthController {

    private final JdbcTemplate jdbcTemplate;

    public HealthController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/live")
    public ApiEnvelope<Map<String, String>> live(HttpServletRequest request) {
        return ApiEnvelope.success(Map.of("status", "UP"), requestId(request));
    }

    @GetMapping("/ready")
    public ResponseEntity<ApiEnvelope<Map<String, String>>> ready(HttpServletRequest request) {
        try {
            jdbcTemplate.queryForObject("SELECT 1", Integer.class);
            return ResponseEntity.ok(ApiEnvelope.success(Map.of("status", "UP", "database", "UP"), requestId(request)));
        } catch (RuntimeException exception) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(ApiEnvelope.failure(
                    "DEPENDENCY_UNAVAILABLE", "服务依赖暂时不可用", requestId(request)));
        }
    }

    private String requestId(HttpServletRequest request) {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        return requestId instanceof String value ? value : "unknown";
    }
}
