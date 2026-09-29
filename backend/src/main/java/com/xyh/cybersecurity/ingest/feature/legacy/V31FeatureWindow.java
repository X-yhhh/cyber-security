package com.xyh.cybersecurity.ingest.feature.legacy;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** v3.1 历史实现：每个 sensor 独立维护的有界、事件时间排序窗口；不接入 v4 路径，见 {@link V31FeatureBuilder}。 */
public final class V31FeatureWindow {
    public static final int WINDOW_SIZE = 100;
    private final Duration allowedLateness;
    private final List<V31FeatureBuilder.FlowInput> flows = new ArrayList<>();
    private final Set<String> recordKeys = new HashSet<>();
    private Instant maxEventTime;

    public V31FeatureWindow(Duration allowedLateness) {
        if (allowedLateness == null || allowedLateness.isNegative()) throw new IllegalArgumentException("允许迟到时间不能为负数");
        this.allowedLateness = allowedLateness;
    }

    public synchronized AddResult add(V31FeatureBuilder.FlowInput flow) {
        if (flow == null || flow.flowEndAt() == null) throw new IllegalArgumentException("流记录时间不能为空");
        if (maxEventTime != null && flow.flowEndAt().isBefore(maxEventTime.minus(allowedLateness))) {
            return new AddResult(false, "late_event");
        }
        if (!recordKeys.add(flow.recordKey())) return new AddResult(false, "duplicate_record");
        if (maxEventTime == null || flow.flowEndAt().isAfter(maxEventTime)) maxEventTime = flow.flowEndAt();
        flows.add(flow);
        flows.sort(Comparator.comparing(V31FeatureBuilder.FlowInput::flowEndAt)
                .thenComparing(V31FeatureBuilder.FlowInput::recordKey));
        while (flows.size() > WINDOW_SIZE) recordKeys.remove(flows.removeFirst().recordKey());
        return new AddResult(true, flows.size() == WINDOW_SIZE ? "ready" : "warming");
    }

    public synchronized List<V31FeatureBuilder.FlowInput> snapshot() { return List.copyOf(flows); }
    public synchronized boolean ready() { return flows.size() == WINDOW_SIZE; }
    public record AddResult(boolean accepted, String status) { }
}
