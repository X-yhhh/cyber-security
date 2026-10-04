package com.xyh.cybersecurity.ops;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;


/**
 * 运行态业务指标。只暴露计数和延迟摘要，不记录原始载荷、凭据或网络内容；查询失败时以 -1 表示未知。
 * 所有指标均从 MySQL 事实表读取，Redis/RabbitMQ 不作为唯一事实源。
 */
@Component
public class OpsMetrics {

    private final OpsMetricsMapper mapper;

    public OpsMetrics(OpsMetricsMapper mapper, MeterRegistry registry) {
        this.mapper = mapper;
        Gauge.builder("cyber_security_outbox_events", this, self -> self.count("pending"))
                .tag("status", "pending").description("待发布事务发件箱数量").register(registry);
        Gauge.builder("cyber_security_outbox_events", this, self -> self.count("failed"))
                .tag("status", "failed").description("发布失败且仍可重试的发件箱数量").register(registry);
        Gauge.builder("cyber_security_outbox_events", this, self -> self.count("dead_letter"))
                .tag("status", "dead_letter").description("进入死信的发件箱数量").register(registry);
        Gauge.builder("cyber_security_outbox_oldest_pending_age_seconds", this, OpsMetrics::oldestPendingAge)
                .description("最老待发布发件箱年龄，秒").register(registry);
        Gauge.builder("cyber_security_outbox_publish_delay_seconds_24h", this, OpsMetrics::averagePublishedDelay)
                .description("过去 24 小时已确认发件箱平均发布延迟，秒").register(registry);
        Gauge.builder("cyber_security_sensors", this, self -> self.countOnlineSensors())
                .tag("state", "online").description("最近三分钟内有心跳的活动传感器数量").register(registry);
        Gauge.builder("cyber_security_sensors", this, self -> self.countHeartbeatTimeouts())
                .tag("state", "heartbeat_timeout").description("超过三分钟未更新或尚无心跳的活动传感器数量").register(registry);
        Gauge.builder("cyber_security_ingest_rejection_ratio_24h", this, OpsMetrics::rejectionRatio)
                .description("过去 24 小时接入记录拒绝比例").register(registry);
        Gauge.builder("cyber_security_login_throttle_blocked", this,
                        self -> self.countBlockedLogins())
                .description("当前登录节流阻断窗口数量").register(registry);
        Gauge.builder("cyber_security_login_throttle_failures_15m", this,
                        self -> self.countLoginThrottleFailures())
                .description("过去 15 分钟登录节流失败次数").register(registry);
    }

    public Snapshot snapshot() {
        return new Snapshot(
                count("pending"), count("failed"), count("dead_letter"),
                oldestPendingAge(),
                averagePublishedDelay(),
                countOnlineSensors(), countHeartbeatTimeouts(),
                rejectionRatio(),
                countBlockedLogins(), countLoginThrottleFailures());
    }

    private double oldestPendingAge() {
        try {
            return mapper.oldestPendingAgeSeconds();
        } catch (RuntimeException exception) { return -1; }
    }

    private double rejectionRatio() {
        try {
            OpsMetricsMapper.RejectionCounts row = mapper.rejectionCounts24h();
            double accepted = row == null ? 0 : row.accepted();
            double manualReview = row == null ? 0 : row.manualReview();
            double rejected = row == null ? 0 : row.rejected();
            double total = accepted + manualReview + rejected;
            return total == 0 ? 0 : rejected / total;
        } catch (RuntimeException exception) { return -1; }
    }

    private double averagePublishedDelay() {
        try { return mapper.averagePublishedDelaySeconds24h(); } catch (RuntimeException exception) { return -1; }
    }

    private double count(String status) {
        try {
            return mapper.countOutbox(status);
        } catch (RuntimeException exception) { return -1; }
    }

    private double countOnlineSensors() { try { return mapper.countOnlineSensors(); } catch (RuntimeException e) { return -1; } }
    private double countHeartbeatTimeouts() { try { return mapper.countSensorHeartbeatTimeouts(); } catch (RuntimeException e) { return -1; } }
    private double countBlockedLogins() { try { return mapper.countBlockedLogins(); } catch (RuntimeException e) { return -1; } }
    private double countLoginThrottleFailures() { try { return mapper.countLoginThrottleFailures(); } catch (RuntimeException e) { return -1; } }

    public record Snapshot(double outboxPending, double outboxFailed, double outboxDeadLetter,
                           double oldestPendingAgeSeconds, double averagePublishedDelaySeconds24h,
                           double sensorsOnline, double sensorsHeartbeatTimeout,
                           double ingestRejectionRatio24h, double loginThrottleBlocked,
                           double loginThrottleFailures15m) { }
}
