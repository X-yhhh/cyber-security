package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.IngestMapper;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 从已落库的推理结论与已批准规则生成告警（路线 B §11）。
 *
 * <p>幂等：模型告警键 {@code model:<记录ID>:<模型制品 SHA-256>}，规则告警键 {@code rule:<规则ID>:<记录ID>}；
 * 已存在的键跳过，重复投递与消费台账被清后的重放都不会产生第二条告警。</p>
 */
@Component
class AlertGenerator {
    /** 单资产单次窗口上下文上限；超限显式失败并回滚消费，不能以不完整窗口确认消息。 */
    static final int WINDOW_CONTEXT_LIMIT = 100_000;

    private final DetectionMapper mapper;
    private final ObjectMapper json;

    AlertGenerator(DetectionMapper mapper, ObjectMapper json) {
        this.mapper = mapper;
        this.json = json;
    }

    /** 本次新建、待关联的告警。 */
    record NewAlert(long alertId, long recordId, Long assetId, Instant eventTime, String alertType, String severity,
                    String summary) { }

    List<NewAlert> generate(long batchId, List<IngestMapper.AcceptedRecord> records, DetectionPolicies policies,
                            Instant now) {
        // 跨规则统一锁顺序，避免规则 A/B 涉及不同资产集合时形成反向锁序。
        records.stream().map(IngestMapper.AcceptedRecord::assetId).filter(java.util.Objects::nonNull)
                .distinct().sorted().forEach(mapper::lockAsset);
        List<Pending> pending = new ArrayList<>(modelAlerts(batchId, policies.severity(), now));
        pending.addAll(ruleAlerts(batchId, records, now));
        if (pending.isEmpty()) return List.of();
        Set<String> existing = new HashSet<>(mapper.findExistingAlertKeys(
                pending.stream().map(item -> item.insert().alertKey()).toList()));
        List<NewAlert> created = new ArrayList<>();
        for (Pending item : pending) {
            if (!existing.add(item.insert().alertKey())) continue;
            mapper.insertAlert(item.insert());
            long id = mapper.findAlertId(item.insert().alertKey());
            created.add(new NewAlert(id, item.insert().ingestRecordId(), item.assetId(), item.eventTime(),
                    item.insert().alertType(), item.insert().severity(), item.summary()));
        }
        return created;
    }

    private record Pending(DetectionMapper.AlertInsert insert, Long assetId, Instant eventTime, String summary) { }

    private List<Pending> modelAlerts(long batchId, DetectionPolicies.Severity severity, Instant now) {
        List<Pending> out = new ArrayList<>();
        for (DetectionMapper.ModelCandidate c : mapper.findModelAlertCandidates(batchId)) {
            double score = c.attackProbability();
            String level = severity.map(score);
            ObjectNode basis = json.createObjectNode().put("source", "model").put("modelKey", c.modelKey())
                    .put("modelVersion", c.modelVersion()).put("attackProbability", score)
                    .put("decisionThreshold", c.decisionThreshold())
                    .put("thresholdPolicyVersion", c.thresholdPolicyVersion())
                    .put("severityPolicyVersion", severity.version()).put("severityBandFloor", severity.bandFloor(score));
            DetectionMapper.AlertInsert insert = new DetectionMapper.AlertInsert(
                    "model:" + c.recordId() + ":" + c.artifactSha256(), c.recordId(), c.inferenceRequestId(),
                    c.modelVersionId(), c.contractVersion(), c.contractSha256(), null, "model", level,
                    severity.version(), decimal(score), c.thresholdPolicyVersion(), basis.toString(), now);
            out.add(new Pending(insert, c.assetId(), c.eventTime(),
                    "模型 " + c.modelKey() + "@" + c.modelVersion() + " 判定攻击，概率 " + round(score)));
        }
        return out;
    }

    private List<Pending> ruleAlerts(long batchId, List<IngestMapper.AcceptedRecord> records, Instant now) {
        List<DetectionMapper.RuleRow> rules = mapper.findActiveRules();
        if (rules.isEmpty() || records.isEmpty()) return List.of();
        String contract = mapper.findBatchContract(batchId);
        List<Pending> out = new ArrayList<>();
        for (DetectionMapper.RuleRow rule : rules) {
            RuleCondition condition;
            JsonNode scope;
            try {
                condition = RuleCondition.parse(json.readTree(rule.conditionJson()));
                scope = json.readTree(rule.scopeJson());
            } catch (Exception exception) {
                continue; // 登记时已校验；损坏的规则不命中，也不阻断其他规则与模型告警。
            }
            String scoped = scope.path("featureContractVersion").asText(null);
            if (scoped != null && !scoped.equals(contract)) continue;
            if (condition.window() != null) {
                out.addAll(windowAlerts(rule, condition, scoped, contract, records, now));
                continue;
            }
            for (IngestMapper.AcceptedRecord record : records) {
                JsonNode payload = payload(record.normalizedPayload());
                ObjectNode matched = payload == null ? null : condition.match(payload, json);
                if (matched == null) continue;
                ObjectNode basis = json.createObjectNode().put("source", "rule").put("ruleKey", rule.ruleKey())
                        .put("ruleVersion", rule.version());
                basis.set("matched", matched);
                out.add(new Pending(ruleInsert(rule, record, contract, basis, now), record.assetId(), record.eventTime(),
                        "规则 " + rule.ruleKey() + "@" + rule.version() + " 命中"));
            }
        }
        return out;
    }

    /**
     * 时间窗聚合规则（开发路线 §4.2）：按资产分组，窗口上下文从已落库记录读取（含本批次），
     * 判定口径见 {@link WindowAggregation}。只有无资产的记录不参与（关联与聚合都以资产为单位）。
     */
    private List<Pending> windowAlerts(DetectionMapper.RuleRow rule, RuleCondition condition, String scopedContract,
                                       String batchContract, List<IngestMapper.AcceptedRecord> records, Instant now) {
        RuleCondition.Window window = condition.window();
        Map<Long, List<IngestMapper.AcceptedRecord>> byAsset = new TreeMap<>();
        Map<Long, ObjectNode> matchedById = new HashMap<>();
        for (IngestMapper.AcceptedRecord record : records) {
            if (record.assetId() <= 0) continue;
            JsonNode payload = payload(record.normalizedPayload());
            ObjectNode matched = payload == null ? null : condition.match(payload, json);
            if (matched == null || window.contribution(payload) == null) continue;
            matchedById.put(record.id(), matched);
            byAsset.computeIfAbsent(record.assetId(), key -> new ArrayList<>()).add(record);
        }
        List<Pending> out = new ArrayList<>();
        for (Map.Entry<Long, List<IngestMapper.AcceptedRecord>> entry : byAsset.entrySet()) {
            List<IngestMapper.AcceptedRecord> candidates = entry.getValue();
            // 与事件关联同样按资产 ID 升序加锁：并发批次对同一资产的窗口判定与告警抑制串行执行。
            if (mapper.lockAsset(entry.getKey()) == null) continue;
            Instant from = candidates.stream().map(IngestMapper.AcceptedRecord::eventTime).min(Instant::compareTo)
                    .orElseThrow().minusSeconds(window.seconds());
            Instant to = candidates.stream().map(IngestMapper.AcceptedRecord::eventTime).max(Instant::compareTo).orElseThrow();
            List<WindowAggregation.Point> context = new ArrayList<>();
            List<DetectionMapper.WindowRecord> rows = mapper.findAssetWindowRecords(entry.getKey(), from, to,
                    scopedContract == null ? batchContract : scopedContract, WINDOW_CONTEXT_LIMIT + 1);
            if (rows.size() > WINDOW_CONTEXT_LIMIT) {
                throw new DetectionUnavailableException("DETECTION_WINDOW_CAPACITY_EXCEEDED");
            }
            for (DetectionMapper.WindowRecord row : rows) {
                JsonNode payload = payload(row.normalizedPayload());
                if (payload == null || condition.match(payload, json) == null) continue;
                Double value = window.contribution(payload);
                if (value != null) context.add(new WindowAggregation.Point(row.id(), row.eventTime(), value));
            }
            List<WindowAggregation.Point> points = candidates.stream().map(record -> new WindowAggregation.Point(
                    record.id(), record.eventTime(), window.contribution(payload(record.normalizedPayload())))).toList();
            List<Instant> prior = mapper.findRuleFiringTimes(rule.id(), entry.getKey(), from, to);
            Map<Long, IngestMapper.AcceptedRecord> byId = new HashMap<>();
            candidates.forEach(record -> byId.put(record.id(), record));
            for (WindowAggregation.Firing firing : WindowAggregation.evaluate(window, context, points, prior)) {
                IngestMapper.AcceptedRecord record = byId.get(firing.recordId());
                ObjectNode basis = json.createObjectNode().put("source", "rule").put("ruleKey", rule.ruleKey())
                        .put("ruleVersion", rule.version());
                basis.set("matched", matchedById.get(firing.recordId()));
                ObjectNode stats = window.describe(json).put("value", firing.aggregate()).put("records", firing.records())
                        .put("windowStartExclusive", firing.windowStart().toString())
                        .put("firstEventAt", firing.firstEventAt().toString())
                        .put("windowEnd", firing.eventTime().toString());
                basis.set("window", stats);
                out.add(new Pending(ruleInsert(rule, record, batchContract, basis, now), record.assetId(),
                        record.eventTime(), "规则 " + rule.ruleKey() + "@" + rule.version() + " 时间窗聚合 "
                        + window.aggregate() + "=" + plain(firing.aggregate()) + "（" + window.seconds() + " 秒内 "
                        + firing.records() + " 条）达到阈值"));
            }
        }
        return out;
    }

    private DetectionMapper.AlertInsert ruleInsert(DetectionMapper.RuleRow rule, IngestMapper.AcceptedRecord record,
                                                   String contract, ObjectNode basis, Instant now) {
        return new DetectionMapper.AlertInsert("rule:" + rule.id() + ":" + record.id(), record.id(), null, null, contract,
                null, rule.id(), "rule", rule.severity(), null, null, rule.ruleKey() + "@" + rule.version(),
                basis.toString(), now);
    }

    private JsonNode payload(String text) {
        try {
            JsonNode node = text == null ? null : json.readTree(text);
            return node != null && node.isObject() ? node : null;
        } catch (Exception exception) {
            return null;
        }
    }

    private static BigDecimal decimal(double value) {
        return BigDecimal.valueOf(value).setScale(8, RoundingMode.HALF_UP);
    }

    private static String plain(double value) {
        return BigDecimal.valueOf(value).stripTrailingZeros().toPlainString();
    }

    private static String round(double value) {
        return BigDecimal.valueOf(value).setScale(4, RoundingMode.HALF_UP).toPlainString();
    }
}
