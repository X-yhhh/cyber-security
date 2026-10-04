package com.xyh.cybersecurity.shadow;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.drift.FeatureBaseline;
import com.xyh.cybersecurity.drift.FeatureDistribution;
import com.xyh.cybersecurity.incident.IncidentMapper;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * 影子验证汇总（路线 B §13）：从 MySQL 事实表只读汇总一个数据源在给定时间范围内的覆盖、契约拒绝、词表外比例、
 * 告警量、人工抽检、PSI 漂移与端到端延迟，并按 §13.3 G3 阈值逐项判定。
 *
 * <p>边界：只读，不写任何表、不改阈值或模型；结论只用于决定是否进入阶段 8（人工审批型处置），不触发处置。
 * 数据源不在调用者 {@code shadow.report.read} 范围内时返回 404。</p>
 */
@Service
public class ShadowReportService {
    static final String REPORT_VERSION = "shadow-report-v1";
    /** §13.3 G3 阈值（2026-09-29 定案）。调整须在路线文档 §21 追加决策记录。 */
    static final String THRESHOLDS_VERSION = "g3-2026-09-29";
    static final double MEAN_ALERTS_PER_DAY = 10;
    static final long MAX_ALERTS_PER_DAY = 30;
    static final double MANUAL_FP_RATE = 0.20;
    static final double SCOPE_ATTACK_RATIO = 0.005;
    static final double CONTRACT_REJECT_RATE = 0.01;
    static final double PSI_ALERT = 0.3;
    static final double PSI_WARNING = 0.2;
    static final int PSI_WARNING_FIELDS = 3;
    static final long LATENCY_P95_MS = 50;
    static final int FULL_REVIEW_LIMIT = 20;
    static final Duration MIN_RUN = Duration.ofDays(7);
    static final double MIN_COVERAGE_RATIO = 0.9;
    static final double OBSERVED_DAY_HOURS = 12;
    static final Duration GAP_THRESHOLD = Duration.ofMinutes(5);
    static final Duration MAX_RANGE = Duration.ofDays(31);
    private static final int FEATURE_PAGE = 1000;
    private static final int MAX_GAPS = 50;
    private static final int MAX_SAMPLE_ITEMS = 500;

    private final ShadowReportMapper mapper;
    private final IncidentMapper incidents;
    private final ObjectMapper json;
    private final Clock clock;

    @Autowired
    public ShadowReportService(ShadowReportMapper mapper, IncidentMapper incidents, ObjectMapper json) {
        this(mapper, incidents, json, Clock.systemUTC());
    }

    ShadowReportService(ShadowReportMapper mapper, IncidentMapper incidents, ObjectMapper json, Clock clock) {
        this.mapper = mapper;
        this.incidents = incidents;
        this.json = json;
        this.clock = clock;
    }

    /**
     * @param fromText       ISO-8601 瞬时，缺省为 {@code to − 7 天}
     * @param toText         ISO-8601 瞬时，缺省为当前时间
     * @param zoneText       划分自然日与工作日所用的时区，缺省 UTC
     * @param includeSamples 调用者持有告警读取权限时返回抽检样本明细
     */
    @Transactional(readOnly = true)
    public ShadowReport summary(long userId, long dataSourceId, String fromText, String toText, String zoneText,
                                boolean includeSamples) {
        if (!mapper.hasSourcePermission(userId, dataSourceId, "shadow.report.read")) throw ApiRequestException.notFound();
        Instant to = toText == null || toText.isBlank() ? clock.instant() : instant(toText, "to");
        Instant from = fromText == null || fromText.isBlank() ? to.minus(MIN_RUN) : instant(fromText, "from");
        if (!from.isBefore(to) || Duration.between(from, to).compareTo(MAX_RANGE) > 0) {
            throw ApiRequestException.badRequest("时间范围须满足 from < to 且不超过 31 天");
        }
        ZoneId zone = zone(zoneText);

        List<ShadowReportMapper.AlertHour> alertHours = mapper.countModelAlertsByHour(dataSourceId, from, to);
        ShadowReport.Coverage coverage = coverage(dataSourceId, from, to, zone, alertHours);
        ShadowReport.Records records = records(dataSourceId, from, to);
        ShadowReport.Alerts alerts = alerts(alertHours, coverage, zone);
        ShadowReport.Review review = review(userId, dataSourceId, from, to, includeSamples);
        ShadowReport.Drift drift = drift(dataSourceId, from, to);
        ShadowReport.Performance performance = performance(dataSourceId, from, to);

        List<ShadowReport.Criterion> criteria = List.of(
                durationCriterion(from, to, coverage),
                alertCriterion(alerts, coverage),
                reviewCriterion(review),
                scopeAttackCriterion(records),
                contractRejectCriterion(records),
                psiCriterion(drift),
                latencyCriterion(performance),
                deadLetterCriterion(performance));
        return new ShadowReport(REPORT_VERSION, THRESHOLDS_VERSION, clock.instant(), dataSourceId, from, to, zone.getId(),
                coverage, records, alerts, review, drift, performance, criteria, verdict(criteria), limitations());
    }

    // ---------------------------------------------------------------- 覆盖

    private ShadowReport.Coverage coverage(long sourceId, Instant from, Instant to, ZoneId zone,
                                           List<ShadowReportMapper.AlertHour> alertHours) {
        List<ShadowReportMapper.HealthWindow> windows = mapper.listHealthWindows(sourceId, from, to);
        Map<Long, List<ShadowReportMapper.HealthWindow>> bySensor = new TreeMap<>();
        windows.forEach(w -> bySensor.computeIfAbsent(w.sensorId(), id -> new ArrayList<>()).add(w));
        int sensors = Math.max(1, bySensor.size());
        Map<LocalDate, Double> dayHours = new TreeMap<>();
        for (LocalDate day = LocalDate.ofInstant(from, zone); !day.isAfter(LocalDate.ofInstant(to.minusNanos(1), zone));
             day = day.plusDays(1)) {
            dayHours.put(day, 0.0);
        }
        double covered = 0;
        long seen = 0, emitted = 0, dropped = 0, queueMax = 0;
        List<ShadowReport.Gap> gaps = new ArrayList<>();
        long gapCount = 0;
        double gapHours = 0;
        for (List<ShadowReportMapper.HealthWindow> list : bySensor.values()) {
            Instant cursor = from;
            for (ShadowReportMapper.HealthWindow w : list) {
                Instant start = w.windowStart().toInstant(ZoneOffset.UTC);
                Instant end = w.windowEnd().toInstant(ZoneOffset.UTC);
                if (Duration.between(cursor, start).compareTo(GAP_THRESHOLD) > 0) {
                    gapCount++;
                    gapHours += hours(cursor, start);
                    if (gaps.size() < MAX_GAPS) gaps.add(gap(cursor, start));
                }
                Instant effectiveStart = start.isBefore(cursor) ? cursor : start;
                if (end.isAfter(effectiveStart)) {
                    double h = hours(effectiveStart, end);
                    covered += h;
                    dayHours.merge(LocalDate.ofInstant(effectiveStart, zone), h, Double::sum);
                    cursor = end;
                }
                seen += w.flowsSeen();
                emitted += w.flowsEmitted();
                dropped += w.flowsDropped();
                queueMax = Math.max(queueMax, w.queueDepthMax());
            }
            if (Duration.between(cursor, to).compareTo(GAP_THRESHOLD) > 0) {
                gapCount++;
                gapHours += hours(cursor, to);
                if (gaps.size() < MAX_GAPS) gaps.add(gap(cursor, to));
            }
        }
        if (bySensor.isEmpty()) {
            gapCount = 1;
            gapHours = hours(from, to);
            gaps.add(gap(from, to));
        }
        Map<LocalDate, Long> dayAlerts = new TreeMap<>();
        alertHours.forEach(h -> dayAlerts.merge(localDay(h.hour(), zone), h.count(), Long::sum));
        List<ShadowReport.Day> days = new ArrayList<>();
        int observed = 0, weekdays = 0, weekends = 0;
        for (var entry : dayHours.entrySet()) {
            double perSensor = entry.getValue() / sensors;
            boolean isObserved = perSensor >= OBSERVED_DAY_HOURS;
            boolean weekend = weekend(entry.getKey());
            if (isObserved) {
                observed++;
                if (weekend) weekends++; else weekdays++;
            }
            days.add(new ShadowReport.Day(entry.getKey(), weekend, round(entry.getValue(), 3), isObserved,
                    dayAlerts.getOrDefault(entry.getKey(), 0L)));
        }
        double range = hours(from, to);
        return new ShadowReport.Coverage(bySensor.size(), windows.size(), round(covered, 3), round(range, 3),
                round(covered / (sensors * range), 4), observed, weekdays, weekends, days, gapCount, round(gapHours, 3),
                gaps, seen, emitted, dropped, queueMax);
    }

    // ---------------------------------------------------------------- 记录与契约

    private ShadowReport.Records records(long sourceId, Instant from, Instant to) {
        long total = 0, ingestRejected = 0, manualReview = 0, notInferred = 0, contractRejected = 0, operational = 0;
        long notInScope = 0, scored = 0, attack = 0;
        Map<String, Long> statuses = new TreeMap<>();
        Map<String, Long> reasons = new TreeMap<>();
        for (ShadowReportMapper.RecordCount row : mapper.countRecords(sourceId, from, to)) {
            total += row.count();
            if ("rejected".equals(row.qualityStatus())) { ingestRejected += row.count(); continue; }
            if ("manual_review".equals(row.qualityStatus())) { manualReview += row.count(); continue; }
            if (row.inferenceStatus() == null) { notInferred += row.count(); continue; }
            statuses.merge(row.inferenceStatus(), row.count(), Long::sum);
            if (row.rejectReason() != null) reasons.merge(row.rejectReason(), row.count(), Long::sum);
            switch (row.inferenceStatus()) {
                case "succeeded" -> {
                    scored += row.count();
                    if ("Attack".equals(row.binaryLabel())) attack += row.count();
                }
                case "not_in_model_scope" -> notInScope += row.count();
                case "rejected" -> {
                    if ("ACTIVE_MODEL_UNAVAILABLE".equals(row.errorCode())) operational += row.count();
                    else contractRejected += row.count();
                }
                case "failed", "timed_out" -> operational += row.count();
                default -> operational += row.count();
            }
        }
        Map<String, Long> issueCodes = new TreeMap<>();
        mapper.countIngestIssues(sourceId, from, to).forEach(c -> issueCodes.put(String.valueOf(c.code()), c.count()));
        Map<String, Long> oov = new TreeMap<>();
        mapper.countOutOfVocabulary(sourceId, from, to).forEach(c -> oov.put(String.valueOf(c.code()), c.count()));
        Map<String, Double> oovRatio = new TreeMap<>();
        for (String field : List.of("proto", "service")) {
            oov.putIfAbsent(field, 0L);
        }
        long scoredTotal = scored;
        oov.forEach((field, count) -> oovRatio.put(field, scoredTotal == 0 ? null : round(count / (double) scoredTotal, 6)));
        long rejectedAll = ingestRejected + contractRejected;
        return new ShadowReport.Records(total, ingestRejected, manualReview, issueCodes, notInferred, statuses, reasons,
                contractRejected, operational, total == 0 ? null : round(rejectedAll / (double) total, 6), notInScope,
                scored, attack, scored == 0 ? null : round(attack / (double) scored, 6), oov, oovRatio);
    }

    // ---------------------------------------------------------------- 告警量

    private ShadowReport.Alerts alerts(List<ShadowReportMapper.AlertHour> hours, ShadowReport.Coverage coverage,
                                       ZoneId zone) {
        long total = hours.stream().mapToLong(ShadowReportMapper.AlertHour::count).sum();
        Map<Long, Map<LocalDate, Long>> perAssetDay = new TreeMap<>();
        hours.forEach(h -> perAssetDay.computeIfAbsent(h.assetId(), id -> new TreeMap<>())
                .merge(localDay(h.hour(), zone), h.count(), Long::sum));
        long max = 0;
        LocalDate maxDay = null;
        for (Map<LocalDate, Long> days : perAssetDay.values()) {
            for (var entry : days.entrySet()) {
                if (entry.getValue() > max) { max = entry.getValue(); maxDay = entry.getKey(); }
            }
        }
        int sensors = Math.max(1, coverage.sensors());
        double coveredDays = coverage.coveredHours() / 24.0 / sensors;
        Double mean = coveredDays <= 0 ? null : round(total / (sensors * coveredDays), 3);
        return new ShadowReport.Alerts(total, perAssetDay.size(), mean, max, maxDay);
    }

    // ---------------------------------------------------------------- 人工抽检

    private ShadowReport.Review review(long userId, long sourceId, Instant from, Instant to, boolean includeSamples) {
        List<ShadowReportMapper.AlertLabel> population = mapper.listModelAlertLabels(sourceId, from, to);
        List<ShadowReportMapper.AlertLabel> sample;
        String rule;
        if (population.size() <= FULL_REVIEW_LIMIT) {
            sample = population;
            rule = "告警不超过 " + FULL_REVIEW_LIMIT + " 条：全部复核";
        } else {
            int size = Math.max(FULL_REVIEW_LIMIT, (int) Math.ceil(population.size() * 0.10));
            sample = population.stream()
                    .sorted(Comparator.comparing((ShadowReportMapper.AlertLabel a) -> sha256(a.alertKey()))
                            .thenComparingLong(ShadowReportMapper.AlertLabel::alertId))
                    .limit(size).sorted(Comparator.comparingLong(ShadowReportMapper.AlertLabel::alertId)).toList();
            rule = "告警超过 " + FULL_REVIEW_LIMIT + " 条：按 SHA-256(alert_key) 升序确定性抽取 max(20, ⌈10%⌉) 条";
        }
        int labeled = 0, fp = 0, tp = 0;
        for (ShadowReportMapper.AlertLabel item : sample) {
            if (item.label() == null) continue;
            labeled++;
            if ("false_positive".equals(item.label())) fp++;
            else if ("true_positive".equals(item.label())) tp++;
        }
        Double rate = labeled == 0 ? null : round(fp / (double) labeled, 4);
        List<ShadowReport.ReviewItem> items = List.of();
        if (includeSamples && !sample.isEmpty()) {
            // 明细只返回调用者按告警可见性谓词（资产 + 数据源范围）能看到的告警；计数不受影响。
            List<ShadowReportMapper.AlertLabel> head = sample.stream().limit(MAX_SAMPLE_ITEMS).toList();
            Set<Long> visible = Set.copyOf(incidents.filterVisibleAlertIds(userId,
                    head.stream().map(ShadowReportMapper.AlertLabel::alertId).toList()));
            items = head.stream().filter(a -> visible.contains(a.alertId()))
                    .map(a -> new ShadowReport.ReviewItem(a.alertId(), a.alertKey(), a.detectedAt(), a.severity(),
                            a.score(), a.label(), a.reviewStatus())).toList();
        }
        return new ShadowReport.Review(rule, population.size(), sample.size(), labeled, fp, tp, rate, items);
    }

    // ---------------------------------------------------------------- 漂移

    private ShadowReport.Drift drift(long sourceId, Instant from, Instant to) {
        List<ShadowReport.ModelUse> models = mapper.listScoredModels(sourceId, from, to).stream()
                .map(m -> new ShadowReport.ModelUse(m.modelVersionId(), m.version(), m.artifactSha256(), m.count()))
                .toList();
        long distinctArtifacts = models.stream().map(ShadowReport.ModelUse::artifactSha256).distinct().count();
        if (models.isEmpty()) return emptyDrift("no_samples", models, null, null, 0);
        if (distinctArtifacts > 1) return emptyDrift("mixed_artifacts", models, null, null, 0);
        String artifact = models.getFirst().artifactSha256();
        Long baselineModel = null;
        FeatureBaseline baseline = null;
        for (long modelId : mapper.listModelIdsByArtifact(artifact)) {
            Optional<FeatureBaseline> candidate = baseline(modelId);
            if (candidate.isPresent()) { baselineModel = modelId; baseline = candidate.get(); break; }
        }
        if (baseline == null) return emptyDrift("baseline_unavailable", models, null, null, 0);
        FeatureDistribution distribution = new FeatureDistribution(baseline);
        long afterId = 0;
        while (true) {
            List<ShadowReportMapper.FeatureRow> page = mapper.listScoredFeatures(sourceId, artifact, from, to, afterId,
                    FEATURE_PAGE);
            for (ShadowReportMapper.FeatureRow row : page) {
                distribution.add(parse(row.features()));
                afterId = row.id();
            }
            if (page.size() < FEATURE_PAGE) break;
        }
        Map<String, Double> psi = new LinkedHashMap<>();
        distribution.psi().forEach((field, value) -> psi.put(field, value == null ? null : round(value, 6)));
        List<String> above = psi.entrySet().stream().filter(e -> e.getValue() != null && e.getValue() > PSI_WARNING)
                .map(Map.Entry::getKey).toList();
        Double max = psi.values().stream().filter(v -> v != null).max(Double::compare).orElse(null);
        String status = distribution.samples() < baseline.minSamples() ? "insufficient_samples" : "computed";
        Map<String, Double> other = new LinkedHashMap<>();
        distribution.otherRatio().forEach((field, value) -> other.put(field, value == null ? null : round(value, 6)));
        return new ShadowReport.Drift(status, baselineModel, versionOf(baselineModel), models,
                distribution.samples(), baseline.minSamples(), psi, other, distribution.invalid(), above, max);
    }

    private ShadowReport.Drift emptyDrift(String status, List<ShadowReport.ModelUse> models, Long baselineModel,
                                          String version, long samples) {
        return new ShadowReport.Drift(status, baselineModel, version, models, samples, 0, Map.of(), Map.of(), Map.of(),
                List.of(), null);
    }

    private String versionOf(Long modelId) {
        if (modelId == null) return null;
        String manifest = mapper.findManifest(modelId);
        try {
            return manifest == null ? null : json.readTree(manifest).path("model_version").asText(null);
        } catch (JsonProcessingException invalid) {
            return null;
        }
    }

    private Optional<FeatureBaseline> baseline(long modelId) {
        String manifest = mapper.findManifest(modelId);
        if (manifest == null) return Optional.empty();
        try {
            return FeatureBaseline.fromManifestInputs(json.readTree(manifest));
        } catch (JsonProcessingException | ModelContractException invalid) {
            return Optional.empty();
        }
    }

    // ---------------------------------------------------------------- 性能

    private ShadowReport.Performance performance(long sourceId, Instant from, Instant to) {
        long[] latencies = mapper.listBatchLatencies(sourceId, from, to).stream().mapToLong(Long::longValue).sorted().toArray();
        ShadowReportMapper.Backlog backlog = mapper.backlog(sourceId);
        long deadLetters = mapper.countDeadLetters(sourceId, from, to);
        return new ShadowReport.Performance(latencies.length, nearestRank(latencies, 0.50), nearestRank(latencies, 0.95),
                nearestRank(latencies, 0.99), latencies.length == 0 ? null : latencies[latencies.length - 1], deadLetters,
                backlog == null ? 0 : backlog.consumerRetrying(), backlog == null ? 0 : backlog.outboxPending(),
                backlog == null || backlog.oldestPendingSeconds() == null ? null : round(backlog.oldestPendingSeconds(), 3));
    }

    // ---------------------------------------------------------------- G3 判定

    private ShadowReport.Criterion durationCriterion(Instant from, Instant to, ShadowReport.Coverage coverage) {
        String value = String.format("范围 %.1f 天，覆盖率 %.1f%%，观测日 %d（工作日 %d / 非工作日 %d）",
                hours(from, to) / 24, coverage.coverageRatio() * 100, coverage.observedDays(),
                coverage.observedWeekdays(), coverage.observedWeekendDays());
        String threshold = "连续 ≥ 7 天、覆盖率 ≥ 90%，工作日与非工作日均有观测日（当天覆盖 ≥ 12 小时）";
        if (Duration.between(from, to).compareTo(MIN_RUN) < 0) {
            return new ShadowReport.Criterion("run_duration", "运行时长与覆盖", threshold, value, "pending", "运行不足 7 天");
        }
        boolean met = coverage.coverageRatio() >= MIN_COVERAGE_RATIO && coverage.observedWeekdays() > 0
                && coverage.observedWeekendDays() > 0;
        return new ShadowReport.Criterion("run_duration", "运行时长与覆盖", threshold, value,
                met ? "pass" : "not_evaluable", met ? null : "覆盖不足：其余指标的样本不代表完整一周");
    }

    private ShadowReport.Criterion alertCriterion(ShadowReport.Alerts alerts, ShadowReport.Coverage coverage) {
        String threshold = "7 天均值 ≤ 10 条/主机/天，且任一天 ≤ 30 条";
        if (alerts.meanPerAssetDay() == null) {
            return new ShadowReport.Criterion("alert_volume", "模型告警量", threshold, "无覆盖", "not_evaluable", null);
        }
        String value = String.format("均值 %.2f 条/天，单日最多 %d 条%s", alerts.meanPerAssetDay(), alerts.maxPerAssetDay(),
                alerts.maxDay() == null ? "" : "（" + alerts.maxDay() + "）");
        boolean pass = alerts.meanPerAssetDay() <= MEAN_ALERTS_PER_DAY && alerts.maxPerAssetDay() <= MAX_ALERTS_PER_DAY;
        return new ShadowReport.Criterion("alert_volume", "模型告警量", threshold, value, pass ? "pass" : "fail", null);
    }

    private ShadowReport.Criterion reviewCriterion(ShadowReport.Review review) {
        String threshold = "≤ 20%（告警不超过 20 条时全部复核）";
        if (review.population() == 0) {
            return new ShadowReport.Criterion("manual_fp_rate", "人工抽检误报率", threshold, "0 条模型告警", "pass",
                    "无告警可复核；不代表模型对攻击的检出能力");
        }
        String value = String.format("已复核 %d / %d（总体 %d 条）%s", review.labeled(), review.sampleSize(),
                review.population(), review.falsePositiveRate() == null ? ""
                        : String.format("，误报 %d 条，误报率 %.1f%%", review.falsePositive(), review.falsePositiveRate() * 100));
        if (review.labeled() < review.sampleSize()) {
            return new ShadowReport.Criterion("manual_fp_rate", "人工抽检误报率", threshold, value, "pending",
                    "抽检样本尚未全部复核");
        }
        boolean pass = review.falsePositiveRate() <= MANUAL_FP_RATE;
        return new ShadowReport.Criterion("manual_fp_rate", "人工抽检误报率", threshold, value, pass ? "pass" : "fail", null);
    }

    private ShadowReport.Criterion scopeAttackCriterion(ShadowReport.Records records) {
        String threshold = "≤ 0.5%（判为攻击的流 / 送推理成功的流，仅模型范围内）";
        if (records.scopeAttackRatio() == null) {
            return new ShadowReport.Criterion("scope_attack_ratio", "模型范围内误报流比例", threshold, "0 条推理成功",
                    "not_evaluable", null);
        }
        String value = String.format("%d / %d = %.3f%%", records.scoredAttack(), records.scored(),
                records.scopeAttackRatio() * 100);
        boolean pass = records.scopeAttackRatio() <= SCOPE_ATTACK_RATIO;
        return new ShadowReport.Criterion("scope_attack_ratio", "模型范围内误报流比例", threshold, value,
                pass ? "pass" : "fail", "真实流量视为几乎全部正常；判为攻击的流按误报计");
    }

    private ShadowReport.Criterion contractRejectCriterion(ShadowReport.Records records) {
        String threshold = "≤ 1%（除窗口预热外）";
        if (records.contractRejectRate() == null) {
            return new ShadowReport.Criterion("contract_reject_rate", "契约拒绝率", threshold, "0 条记录", "not_evaluable", null);
        }
        String value = String.format("(%d + %d) / %d = %.3f%%", records.ingestRejected(), records.contractRejected(),
                records.total(), records.contractRejectRate() * 100);
        boolean pass = records.contractRejectRate() <= CONTRACT_REJECT_RATE;
        return new ShadowReport.Criterion("contract_reject_rate", "契约拒绝率", threshold, value, pass ? "pass" : "fail",
                "分母为全部上报记录（含模型范围外），传感器不上报预热期记录；运行故障 " + records.operationalFailed() + " 条单列");
    }

    private ShadowReport.Criterion psiCriterion(ShadowReport.Drift drift) {
        String threshold = "所有字段 ≤ 0.3，且 > 0.2 的字段不超过 3 个";
        if (!"computed".equals(drift.status())) {
            String note = switch (drift.status()) {
                case "baseline_unavailable" -> "模型 manifest 没有训练基线统计";
                case "insufficient_samples" -> "样本 " + drift.samples() + " < " + drift.minSamples();
                case "mixed_artifacts" -> "范围内使用了多个不同的 ONNX 制品";
                default -> "无推理成功样本";
            };
            return new ShadowReport.Criterion("psi", "单字段 PSI", threshold, drift.status(), "not_evaluable", note);
        }
        boolean nullField = drift.psi().values().stream().anyMatch(v -> v == null);
        String value = String.format("最大 %.3f，> 0.2 的字段 %d 个 %s（样本 %d）", drift.maxPsi(),
                drift.fieldsAboveWarning().size(), drift.fieldsAboveWarning(), drift.samples());
        if (nullField) {
            return new ShadowReport.Criterion("psi", "单字段 PSI", threshold, value, "not_evaluable", "存在无有效样本的字段");
        }
        boolean pass = drift.maxPsi() <= PSI_ALERT && drift.fieldsAboveWarning().size() <= PSI_WARNING_FIELDS;
        return new ShadowReport.Criterion("psi", "单字段 PSI", threshold, value, pass ? "pass" : "fail", null);
    }

    private ShadowReport.Criterion latencyCriterion(ShadowReport.Performance performance) {
        String threshold = "P95 ≤ 50 ms（批次入库 → 推理完成）";
        if (performance.p95Ms() == null) {
            return new ShadowReport.Criterion("latency_p95", "推理延迟 P95", threshold, "无批次", "not_evaluable", null);
        }
        String value = String.format("P50 %d / P95 %d / P99 %d / 最大 %d ms（%d 批）", performance.p50Ms(),
                performance.p95Ms(), performance.p99Ms(), performance.maxMs(), performance.batches());
        return new ShadowReport.Criterion("latency_p95", "推理延迟 P95", threshold, value,
                performance.p95Ms() <= LATENCY_P95_MS ? "pass" : "fail", null);
    }

    private ShadowReport.Criterion deadLetterCriterion(ShadowReport.Performance performance) {
        return new ShadowReport.Criterion("dead_letters", "死信数", "0（非注入故障）",
                Long.toString(performance.deadLetters()), performance.deadLetters() == 0 ? "pass" : "fail", null);
    }

    static String verdict(List<ShadowReport.Criterion> criteria) {
        if (criteria.stream().anyMatch(c -> "fail".equals(c.status()))) return "fail";
        if (criteria.stream().anyMatch(c -> !"pass".equals(c.status()))) return "incomplete";
        return "pass";
    }

    private static List<String> limitations() {
        return List.of(
                "只覆盖部署了传感器的主机上实际可见的流量，不代表全网。",
                "模型只评估 responder 视角的 IPv4 流；initiator 视角与 IPv6 流不在模型范围内，只统计不评估。",
                "“正常流量上的误报率”不代表“对攻击的检出率”；后者只能在隔离靶场内用公开数据回放评估。",
                "人工抽检基于研判员对流特征与当时本机活动的判断，传感器不保存对端地址与载荷。",
                "工作日/非工作日按所选时区的周六、周日划分，未考虑法定节假日调休。");
    }

    // ---------------------------------------------------------------- 工具

    static Long nearestRank(long[] sorted, double q) {
        if (sorted.length == 0) return null;
        int index = (int) Math.ceil(q * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, index))];
    }

    private static LocalDate localDay(LocalDateTime utcHour, ZoneId zone) {
        return LocalDate.ofInstant(utcHour.toInstant(ZoneOffset.UTC), zone);
    }

    private static boolean weekend(LocalDate date) {
        return date.getDayOfWeek() == DayOfWeek.SATURDAY || date.getDayOfWeek() == DayOfWeek.SUNDAY;
    }

    private static ShadowReport.Gap gap(Instant start, Instant end) {
        return new ShadowReport.Gap(start, end, round(Duration.between(start, end).toMillis() / 60000.0, 2));
    }

    private static double hours(Instant start, Instant end) {
        return Duration.between(start, end).toMillis() / 3_600_000.0;
    }

    private static double round(double value, int digits) {
        double scale = Math.pow(10, digits);
        return Math.round(value * scale) / scale;
    }

    private JsonNode parse(String features) {
        try {
            return features == null ? null : json.readTree(features);
        } catch (JsonProcessingException invalid) {
            return null;
        }
    }

    private static Instant instant(String text, String name) {
        try {
            return Instant.parse(text.trim());
        } catch (DateTimeParseException invalid) {
            throw ApiRequestException.badRequest(name + " 必须是 ISO-8601 瞬时");
        }
    }

    private static ZoneId zone(String text) {
        if (text == null || text.isBlank()) return ZoneOffset.UTC;
        try {
            return ZoneId.of(text.trim());
        } catch (RuntimeException invalid) {
            throw ApiRequestException.badRequest("时区无效");
        }
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
