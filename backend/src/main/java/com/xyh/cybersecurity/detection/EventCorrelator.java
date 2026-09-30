package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * 把新告警按“同资产 + 关联时间窗”并入未结束事件，或新建事件，并重算风险评分（路线 B §11、§21）。
 *
 * <p>并发：按资产 ID 升序锁定资产行，同一资产的关联串行执行，不会并发新建两个事件；多资产批次按固定顺序加锁，
 * 避免死锁。时间窗按记录事件时间计算，回放数据也按其原始时间关联。</p>
 */
@Component
class EventCorrelator {
    static final String FORMULA = "min(1, severityWeight*criticalityWeight + min(repeatCap, repeatStep*(alertCount-1)))";

    private final DetectionMapper mapper;
    private final ObjectMapper json;

    EventCorrelator(DetectionMapper mapper, ObjectMapper json) {
        this.mapper = mapper;
        this.json = json;
    }

    /** @return 本次新建或更新的事件 ID */
    Set<Long> correlate(List<AlertGenerator.NewAlert> alerts, DetectionPolicies policies) {
        Map<Long, List<AlertGenerator.NewAlert>> byAsset = alerts.stream().filter(alert -> alert.assetId() != null)
                .collect(Collectors.groupingBy(AlertGenerator.NewAlert::assetId, TreeMap::new, Collectors.toList()));
        Set<Long> touched = new LinkedHashSet<>();
        long window = policies.correlation().windowSeconds();
        for (Map.Entry<Long, List<AlertGenerator.NewAlert>> entry : byAsset.entrySet()) {
            DetectionMapper.AssetRow asset = mapper.lockAsset(entry.getKey());
            if (asset == null) continue;
            Set<Long> assetEvents = new LinkedHashSet<>();
            String key = "asset:" + asset.id();
            List<AlertGenerator.NewAlert> ordered = entry.getValue().stream()
                    .sorted(Comparator.comparing(AlertGenerator.NewAlert::eventTime)
                            .thenComparing(AlertGenerator.NewAlert::alertId)).toList();
            for (AlertGenerator.NewAlert alert : ordered) {
                Long eventId = mapper.findOpenCorrelatedEvent(key, alert.eventTime().minusSeconds(window),
                        alert.eventTime().plusSeconds(window));
                if (eventId == null) {
                    String eventKey = "auto:" + key + ":alert:" + alert.alertId();
                    mapper.insertEvent(new DetectionMapper.EventInsert(eventKey, title(asset), alert.severity(),
                            alert.eventTime(), alert.eventTime(), key, policies.correlation().version()));
                    eventId = mapper.findEventId(eventKey);
                } else {
                    mapper.updateEventWindow(eventId, alert.eventTime());
                }
                mapper.insertAlertLink(eventId, alert.alertId());
                mapper.upsertAssetLink(eventId, asset.id());
                ObjectNode details = json.createObjectNode().put("alertId", alert.alertId())
                        .put("alertType", alert.alertType()).put("severity", alert.severity())
                        .put("correlationKey", key).put("correlationPolicyVersion", policies.correlation().version());
                mapper.insertTimeline(eventId, alert.eventTime(), alert.summary(), "detection_alert:" + alert.alertId(),
                        details.toString());
                assetEvents.add(eventId);
            }
            for (long eventId : assetEvents) rescore(eventId, asset, policies.risk());
            touched.addAll(assetEvents);
        }
        return touched;
    }

    private void rescore(long eventId, DetectionMapper.AssetRow asset, DetectionPolicies.Risk risk) {
        List<String> severities = mapper.listEventAlertSeverities(eventId);
        String top = severities.stream().max(Comparator.comparingInt(DetectionPolicies::rank)).orElse("medium");
        Risk computed = compute(risk, top, severities.size(), asset.criticality());
        mapper.updateEventRisk(eventId, top, computed.score(), risk.version(), computed.basis(json).toString());
    }

    /** 可解释风险评分；依据中列出每一项输入与公式，便于复算。 */
    record Risk(BigDecimal score, String topSeverity, double severityWeight, String criticality,
                double criticalityWeight, boolean criticalityDefaulted, int alertCount, double repeatBonus,
                String policyVersion) {
        ObjectNode basis(ObjectMapper json) {
            return json.createObjectNode().put("policyVersion", policyVersion).put("formula", FORMULA)
                    .put("topSeverity", topSeverity).put("severityWeight", severityWeight)
                    .put("assetCriticality", criticality).put("criticalityWeight", criticalityWeight)
                    .put("criticalityDefaulted", criticalityDefaulted).put("alertCount", alertCount)
                    .put("repeatBonus", repeatBonus).put("riskScore", score.doubleValue());
        }
    }

    static Risk compute(DetectionPolicies.Risk risk, String topSeverity, int alertCount, String criticality) {
        double severityWeight = risk.severityWeight().getOrDefault(topSeverity, 0.0);
        String normalized = criticality == null ? "" : criticality.toLowerCase(Locale.ROOT);
        Double mapped = risk.criticalityWeight().get(normalized);
        // 资产重要性不在策略表中（创建接口未限定取值）：按 medium 计算并在依据中标明，不静默放大或忽略。
        double criticalityWeight = mapped != null ? mapped : risk.criticalityWeight().get("medium");
        double repeatBonus = Math.min(risk.repeatCap(), risk.repeatStep() * Math.max(0, alertCount - 1));
        double score = Math.min(1.0, severityWeight * criticalityWeight + repeatBonus);
        return new Risk(BigDecimal.valueOf(score).setScale(8, RoundingMode.HALF_UP), topSeverity, severityWeight,
                criticality, criticalityWeight, mapped == null, alertCount, repeatBonus, risk.version());
    }

    private static String title(DetectionMapper.AssetRow asset) {
        String title = "资产 " + asset.assetKey() + " 检测告警";
        return title.length() <= 255 ? title : title.substring(0, 255);
    }
}
