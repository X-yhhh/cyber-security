package com.xyh.cybersecurity.drift;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 定时计算漂移窗口。默认关闭（{@code cyber.drift.enabled=false}），影子运行与部署环境显式开启。
 * 每次运行补算回看范围内所有已结束、尚未写入的窗口，因此停机后恢复不会漏算（超出回看范围的除外）。
 */
@Component
@ConditionalOnProperty(name = "cyber.drift.enabled", havingValue = "true")
public class DriftMetricJob {
    private final DriftMetricService service;

    public DriftMetricJob(DriftMetricService service) {
        this.service = service;
    }

    @Scheduled(initialDelayString = "${cyber.drift.initial-delay-ms:60000}", fixedDelayString = "${cyber.drift.poll-ms:600000}")
    public void run() {
        service.computeDueWindows();
    }
}
