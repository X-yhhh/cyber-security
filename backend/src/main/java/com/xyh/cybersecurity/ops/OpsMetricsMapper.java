package com.xyh.cybersecurity.ops;

import org.apache.ibatis.annotations.Mapper;

/** 运维指标只读查询；失败由上层转换为未知值，不把载荷写入指标。 */
@Mapper
public interface OpsMetricsMapper {
    long countOutbox(String status);
    double oldestPendingAgeSeconds();
    double averagePublishedDelaySeconds24h();
    long countOnlineSensors();
    long countSensorHeartbeatTimeouts();
    RejectionCounts rejectionCounts24h();
    long countBlockedLogins();
    long countLoginThrottleFailures();

    record RejectionCounts(long accepted, long manualReview, long rejected) { }
}
