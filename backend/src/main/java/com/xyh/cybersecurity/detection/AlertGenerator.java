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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 从已落库的推理结论与已批准规则生成告警（路线 B §11）。
 *
 * <p>幂等：模型告警键 {@code model:<记录ID>:<模型制品 SHA-256>}，规则告警键 {@code rule:<规则ID>:<记录ID>}；
 * 已存在的键跳过，重复投递与消费台账被清后的重放都不会产生第二条告警。</p>
 */
@Component
class AlertGenerator {
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
            for (IngestMapper.AcceptedRecord record : records) {
                JsonNode payload = payload(record.normalizedPayload());
                ObjectNode matched = payload == null ? null : condition.match(payload, json);
                if (matched == null) continue;
                ObjectNode basis = json.createObjectNode().put("source", "rule").put("ruleKey", rule.ruleKey())
                        .put("ruleVersion", rule.version());
                basis.set("matched", matched);
                DetectionMapper.AlertInsert insert = new DetectionMapper.AlertInsert(
                        "rule:" + rule.id() + ":" + record.id(), record.id(), null, null, contract, null, rule.id(),
                        "rule", rule.severity(), null, null, rule.ruleKey() + "@" + rule.version(), basis.toString(), now);
                out.add(new Pending(insert, record.assetId(), record.eventTime(),
                        "规则 " + rule.ruleKey() + "@" + rule.version() + " 命中"));
            }
        }
        return out;
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

    private static String round(double value) {
        return BigDecimal.valueOf(value).setScale(4, RoundingMode.HALF_UP).toPlainString();
    }
}
