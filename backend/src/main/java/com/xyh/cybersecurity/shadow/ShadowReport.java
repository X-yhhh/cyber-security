package com.xyh.cybersecurity.shadow;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * 影子验证汇总（路线 B §13.2 观测指标、§13.3 决策门 G3、§13.4 必须如实报告的结论）。
 *
 * <p>只含计数、比例与分布统计，不含记录内容、地址或凭据。{@code criteria} 逐项给出 G3 阈值判定：
 * {@code pass} / {@code fail} / {@code pending}（数据尚不足以判定，例如运行时长不够、抽检未完成）/
 * {@code not_evaluable}（前提缺失，例如无基线、无样本）。{@code verdict}：任一 fail 为 {@code fail}；
 * 否则任一 pending / not_evaluable 为 {@code incomplete}；全部 pass 为 {@code pass}。</p>
 */
public record ShadowReport(String reportVersion, String thresholdsVersion, Instant generatedAt, long dataSourceId,
                           Instant from, Instant to, String timeZone, Coverage coverage, Records records, Alerts alerts,
                           Review review, Drift drift, Performance performance, List<Criterion> criteria,
                           String verdict, List<String> limitations) {

    /**
     * @param coverageRatio 健康窗口覆盖时长 / (传感器数 × 范围时长)
     * @param gaps          相邻健康窗口间隔超过 5 分钟的停机段（含范围首尾），最多列出 50 段
     */
    public record Coverage(int sensors, long healthWindows, double coveredHours, double rangeHours,
                           double coverageRatio, int observedDays, int observedWeekdays, int observedWeekendDays,
                           List<Day> days, long gapCount, double gapHours, List<Gap> gaps, long flowsSeen,
                           long flowsEmitted, long flowsDropped, long queueDepthMax) { }

    /** @param observed 当天覆盖 ≥ 12 小时 */
    public record Day(LocalDate date, boolean weekend, double coveredHours, boolean observed, long modelAlerts) { }

    public record Gap(Instant start, Instant end, double minutes) { }

    /**
     * @param contractRejectRate (接入拒绝 + 推理契约拒绝) / 全部记录；推理运行故障（无激活模型、超时等）单列，不计入
     * @param scopeAttackRatio   模型范围内判为攻击的流 / 送推理成功的流
     */
    public record Records(long total, long ingestRejected, long manualReview, Map<String, Long> ingestIssueCodes,
                          long notInferred, Map<String, Long> inferenceStatus, Map<String, Long> rejectReasons,
                          long contractRejected, long operationalFailed, Double contractRejectRate,
                          long notInModelScope, long scored, long scoredAttack, Double scopeAttackRatio,
                          Map<String, Long> outOfVocabulary, Map<String, Double> outOfVocabularyRatio) { }

    /** @param meanPerAssetDay 模型告警总数 / (传感器数 × 覆盖天数)；{@code maxPerAssetDay} 按所选时区的自然日 */
    public record Alerts(long modelAlerts, int assetsWithAlerts, Double meanPerAssetDay, long maxPerAssetDay,
                         LocalDate maxDay) { }

    /**
     * @param rule   抽检规则说明
     * @param sample 抽检样本（仅调用者有告警读取权限时返回）
     */
    public record Review(String rule, long population, int sampleSize, int labeled, int falsePositive,
                         int truePositive, Double falsePositiveRate, List<ReviewItem> sample) { }

    public record ReviewItem(long alertId, String alertKey, LocalDateTime detectedAt, String severity, Double score,
                             String label, String reviewStatus) { }

    /**
     * @param status {@code computed} / {@code insufficient_samples} / {@code baseline_unavailable} /
     *               {@code mixed_artifacts}（范围内用过多个不同 ONNX 制品，不合并比较）/ {@code no_samples}
     */
    public record Drift(String status, Long baselineModelVersionId, String baselineVersion, List<ModelUse> models,
                        long samples, long minSamples, Map<String, Double> psi, Map<String, Double> otherRatio,
                        Map<String, Long> invalid, List<String> fieldsAboveWarning, Double maxPsi) { }

    public record ModelUse(long modelVersionId, String version, String artifactSha256, long scored) { }

    /** 端到端延迟：批次接收（{@code ingest_batch.started_at}）→ 该批最后一条推理完成，仅含有推理成功记录的批次。 */
    public record Performance(long batches, Long p50Ms, Long p95Ms, Long p99Ms, Long maxMs, long deadLetters,
                              long consumerRetrying, long outboxPending, Double oldestPendingSeconds) { }

    public record Criterion(String key, String title, String threshold, String value, String status, String note) { }
}
