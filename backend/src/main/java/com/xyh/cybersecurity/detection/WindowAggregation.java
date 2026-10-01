package com.xyh.cybersecurity.detection;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 时间窗聚合规则的纯判定（开发路线 §4.2）。在线告警生成与离线规则回放共用本类，保证两处口径一致。
 *
 * <p>口径：记录按 {@code (事件时间, 记录 ID)} 全序排列；候选记录 {@code r} 的窗口是事件时间落在
 * {@code (t − seconds, t]} 且不排在 {@code r} 之后的已过滤记录（含 {@code r} 自身）。聚合值达到阈值、
 * 且 {@code (t − seconds, t]} 内没有同一规则同一资产的已有告警时，在 {@code r} 上告警。</p>
 *
 * <p>按事件时间计算已落库数据；不回溯重算先前消费的候选。跨批次迟到记录可能影响检出位置或造成漏检，
 * 离线全量排序回放与在线乱序到达不保证相同。重复消费通过已有告警抑制和告警唯一键避免重复写入。</p>
 */
final class WindowAggregation {
    private WindowAggregation() { }

    /** 一条已通过逐条过滤的记录及其对聚合值的贡献（{@code count} 为 1）。 */
    record Point(long recordId, Instant eventTime, double value) { }

    /**
     * 一次告警。
     *
     * @param windowStart  窗口开区间下界 {@code t − seconds}
     * @param firstEventAt 窗口内最早记录的事件时间
     * @param records      窗口内记录数
     * @param aggregate    聚合值（{@code count} 时等于 {@code records}）
     */
    record Firing(long recordId, Instant eventTime, Instant windowStart, Instant firstEventAt, int records,
                  double aggregate) { }

    static final Comparator<Point> ORDER = Comparator.comparing(Point::eventTime).thenComparingLong(Point::recordId);

    /**
     * @param window         规则窗口参数
     * @param context        同一资产在 {@code [最早候选 − seconds, 最晚候选]} 内全部已过滤记录（含候选本身）
     * @param candidates     本次需要判定的记录（通常是当前批次中已过滤的记录）
     * @param priorFirings   同一规则同一资产在上述区间内已有告警的事件时间
     * @return 新告警，按时间顺序
     */
    static List<Firing> evaluate(RuleCondition.Window window, List<Point> context, List<Point> candidates,
                                 List<Instant> priorFirings) {
        List<Point> sorted = new ArrayList<>(context);
        sorted.sort(ORDER);
        double[] prefix = new double[sorted.size() + 1];
        for (int i = 0; i < sorted.size(); i++) prefix[i + 1] = prefix[i] + sorted.get(i).value();

        List<Instant> fired = new ArrayList<>(priorFirings);
        List<Point> ordered = new ArrayList<>(candidates);
        ordered.sort(ORDER);
        List<Firing> out = new ArrayList<>();
        for (Point candidate : ordered) {
            int end = upperBound(sorted, candidate);          // 不排在候选之后的记录个数
            Instant windowStart = candidate.eventTime().minusSeconds(window.seconds());
            int start = firstAfter(sorted, windowStart, end); // 事件时间严格晚于窗口下界的首条
            int records = end - start;
            if (records <= 0) continue;
            double aggregate = prefix[end] - prefix[start];
            if (aggregate < window.threshold()) continue;
            boolean suppressed = fired.stream().anyMatch(at -> at.isAfter(windowStart) && !at.isAfter(candidate.eventTime()));
            if (suppressed) continue;
            fired.add(candidate.eventTime());
            out.add(new Firing(candidate.recordId(), candidate.eventTime(), windowStart,
                    sorted.get(start).eventTime(), records, aggregate));
        }
        return out;
    }

    private static int upperBound(List<Point> sorted, Point key) {
        int lo = 0;
        int hi = sorted.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (ORDER.compare(sorted.get(mid), key) <= 0) lo = mid + 1; else hi = mid;
        }
        return lo;
    }

    private static int firstAfter(List<Point> sorted, Instant bound, int limit) {
        int lo = 0;
        int hi = limit;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (sorted.get(mid).eventTime().isAfter(bound)) hi = mid; else lo = mid + 1;
        }
        return lo;
    }
}
