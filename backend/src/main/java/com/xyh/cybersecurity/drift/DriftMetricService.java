package com.xyh.cybersecurity.drift;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * M8 漂移窗口计算（路线 B §13.2、§15）：按 UTC 整点小时，对每个 (数据源, 模型版本) 汇总推理成功记录的输入分布、
 * 分数分布、拒绝率与人工反馈，与 manifest 训练基线比较得出 PSI 与漂移状态。
 *
 * <p>边界：只读推理台账与接入记录，只追加 {@code drift_metric_window}；不修改阈值、不换模型、不触发处置。
 * 窗口在结束后 {@link #GRACE} 才计算，之后迟到的推理结论不再回写该窗口（影子报告另按记录重算整段分布）。
 * 同一窗口重复计算被唯一键拦下。</p>
 */
@Service
public class DriftMetricService {
    private static final Logger log = LoggerFactory.getLogger(DriftMetricService.class);
    static final String COMPUTED_BY = "drift-job-v1";
    /** 窗口结束后等待的时间，覆盖消费事务提交延迟。 */
    static final Duration GRACE = Duration.ofMinutes(5);
    /** 每次最多回看的时间范围：后端停机超过该时长时，更早的窗口不再补算。 */
    static final Duration LOOKBACK = Duration.ofHours(48);
    private static final int PAGE = 500;
    private static final int MAX_WINDOWS_PER_RUN = 200;
    private static final double[] SCORE_EDGES = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9};

    private final DriftMapper mapper;
    private final ObjectMapper json;
    private final TransactionTemplate transactions;
    private final Clock clock;
    private final Map<Long, Optional<FeatureBaseline>> baselines = new ConcurrentHashMap<>();

    @Autowired
    public DriftMetricService(DriftMapper mapper, ObjectMapper json, TransactionTemplate transactions) {
        this(mapper, json, transactions, Clock.systemUTC());
    }

    DriftMetricService(DriftMapper mapper, ObjectMapper json, TransactionTemplate transactions, Clock clock) {
        this.mapper = mapper;
        this.json = json;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** 计算全部到期窗口；单个窗口失败只记日志，不影响其他窗口。返回本次写入的窗口数。 */
    public int computeDueWindows() {
        Instant now = clock.instant();
        Instant before = now.minus(GRACE).truncatedTo(ChronoUnit.HOURS);
        Instant since = before.minus(LOOKBACK);
        int written = 0;
        for (DriftMapper.DueWindow due : mapper.findDueWindows(since, before, MAX_WINDOWS_PER_RUN)) {
            try {
                Boolean inserted = transactions.execute(status -> computeWindow(due));
                if (Boolean.TRUE.equals(inserted)) written++;
            } catch (RuntimeException failure) {
                log.warn("漂移窗口计算失败 source={} model={} start={}: {}", due.dataSourceId(), due.modelVersionId(),
                        due.windowStart(), failure.getClass().getSimpleName());
            }
        }
        return written;
    }

    /** 计算并写入一个窗口；已存在时返回 false。 */
    boolean computeWindow(DriftMapper.DueWindow due) {
        LocalDateTime from = due.windowStart();
        LocalDateTime to = from.plusHours(1);
        long sourceId = due.dataSourceId();
        long modelId = due.modelVersionId();

        Map<String, Long> statuses = new LinkedHashMap<>();
        mapper.countStatuses(sourceId, modelId, from, to).forEach(row -> statuses.put(row.status(), row.count()));
        long requests = statuses.values().stream().mapToLong(Long::longValue).sum();
        long rejected = statuses.getOrDefault("rejected", 0L) + statuses.getOrDefault("failed", 0L)
                + statuses.getOrDefault("timed_out", 0L);

        Optional<FeatureBaseline> baseline = baseline(modelId);
        FeatureDistribution distribution = baseline.map(FeatureDistribution::new).orElse(null);
        List<Double> scores = new ArrayList<>();
        long attacks = 0;
        long afterId = 0;
        while (true) {
            List<DriftMapper.ScoredSample> page = mapper.listScored(sourceId, modelId, from, to, afterId, PAGE);
            for (DriftMapper.ScoredSample sample : page) {
                scores.add(sample.attackProbability());
                if ("Attack".equals(sample.binaryLabel())) attacks++;
                if (distribution != null) distribution.add(parse(sample.features()));
                afterId = sample.id();
            }
            if (page.size() < PAGE) break;
        }
        long samples = scores.size();

        String status;
        Map<String, Object> featureStats = new LinkedHashMap<>();
        if (baseline.isEmpty()) {
            status = "baseline_unavailable";
            featureStats.put("baseline", null);
        } else {
            FeatureBaseline base = baseline.get();
            featureStats.put("baseline", Map.of("schema", base.schemaVersion(), "method", base.method(),
                    "source", base.sourceRef(), "minSamples", base.minSamples()));
            featureStats.putAll(distribution.countsJson());
            Map<String, Double> psi = distribution.psi();
            featureStats.put("psi", psi);
            featureStats.put("otherRatio", distribution.otherRatio());
            status = status(base, samples, psi);
        }

        DriftMapper.FeedbackCount feedback = mapper.countFeedback(sourceId, modelId, from, to);
        Map<String, Object> feedbackStats = new LinkedHashMap<>();
        feedbackStats.put("alerts", feedback.alerts());
        feedbackStats.put("labeled", feedback.labeled());
        feedbackStats.put("falsePositive", feedback.falsePositive());
        feedbackStats.put("truePositive", feedback.truePositive());

        BigDecimal rejectRate = requests == 0 ? null
                : BigDecimal.valueOf(rejected).divide(BigDecimal.valueOf(requests), 6, RoundingMode.HALF_UP);
        DriftMapper.WindowInsert insert = new DriftMapper.WindowInsert(sourceId, modelId, from, to, samples, requests,
                baseline.map(b -> "model_version:" + modelId + ":" + b.schemaVersion()).orElse(null),
                write(featureStats), write(scoreStats(scores, attacks, statuses)), write(feedbackStats), rejectRate,
                status, COMPUTED_BY);
        try {
            mapper.insertWindow(insert);
            return true;
        } catch (DuplicateKeyException concurrent) {
            return false;
        }
    }

    /** PSI 判级：样本不足时不给结论；任一字段无有效样本同样视为样本不足。 */
    static String status(FeatureBaseline baseline, long samples, Map<String, Double> psi) {
        if (samples < baseline.minSamples() || psi.values().stream().anyMatch(value -> value == null)) {
            return "insufficient_samples";
        }
        double max = psi.values().stream().mapToDouble(Double::doubleValue).max().orElse(0);
        if (max > baseline.alertThreshold()) return "alert";
        if (max > baseline.warningThreshold()) return "warning";
        return "ok";
    }

    private Map<String, Object> scoreStats(List<Double> scores, long attacks, Map<String, Long> statuses) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("statuses", statuses);
        result.put("scored", scores.size());
        result.put("attack", attacks);
        long[] histogram = new long[SCORE_EDGES.length + 1];
        for (double score : scores) {
            int bin = 0;
            while (bin < SCORE_EDGES.length && SCORE_EDGES[bin] < score) bin++;
            histogram[bin]++;
        }
        result.put("histogramEdges", SCORE_EDGES);
        result.put("histogram", histogram);
        if (!scores.isEmpty()) {
            double[] sorted = scores.stream().mapToDouble(Double::doubleValue).sorted().toArray();
            result.put("mean", Arrays.stream(sorted).average().orElse(0));
            result.put("p50", quantile(sorted, 0.50));
            result.put("p95", quantile(sorted, 0.95));
            result.put("max", sorted[sorted.length - 1]);
        }
        return result;
    }

    /** 最近秩分位数（不插值），与影子报告口径一致。 */
    static double quantile(double[] sorted, double q) {
        int index = (int) Math.ceil(q * sorted.length) - 1;
        return sorted[Math.max(0, Math.min(sorted.length - 1, index))];
    }

    /** 模型版本的 manifest 不可变，基线按版本缓存；结构不合规的基线记为不可用并告警，不用于判定。 */
    Optional<FeatureBaseline> baseline(long modelId) {
        return baselines.computeIfAbsent(modelId, id -> {
            String manifest = mapper.findManifest(id);
            if (manifest == null) return Optional.empty();
            try {
                return FeatureBaseline.fromManifestInputs(json.readTree(manifest));
            } catch (JsonProcessingException | ModelContractException invalid) {
                log.warn("模型版本 {} 的基线统计不可用: {}", id, invalid.getMessage());
                return Optional.empty();
            }
        });
    }

    private JsonNode parse(String features) {
        try {
            return features == null ? null : json.readTree(features);
        } catch (JsonProcessingException invalid) {
            return null;
        }
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException("DRIFT_STATS_SERIALIZATION_FAILED", failure);
        }
    }
}
