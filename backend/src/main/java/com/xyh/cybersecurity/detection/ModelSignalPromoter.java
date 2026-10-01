package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.IngestMapper;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.*;

/**
 * 模型信号升级：同资产/契约/策略快照，按事件时间判断高分、前向计数窗口或双向规则关联窗口。
 * 后到达记录只复核受影响窗口；旧参数产生的信号不套用新参数。查询上限超出则整批回滚。
 * 计数按输入记录去重（同一记录多个权重不得重复累计）；二分窗口查询避免大窗口平方复杂度。
 */
@Component
class ModelSignalPromoter {
    private final ModelSignalMapper mapper;
    private final ObjectMapper json;
    ModelSignalPromoter(ModelSignalMapper mapper, ObjectMapper json) { this.mapper=mapper; this.json=json; }

    List<AlertGenerator.NewAlert> promote(List<IngestMapper.AcceptedRecord> records, DetectionPolicies policies, Instant now) {
        var signal=policies.severity().signal();
        if (signal==null || !signal.enabled() || records.isEmpty()) return List.of();
        Map<Long,List<IngestMapper.AcceptedRecord>> assets=new TreeMap<>();
        for (var r:records) if (r.assetId()>0) assets.computeIfAbsent(r.assetId(), k->new ArrayList<>()).add(r);
        List<AlertGenerator.NewAlert> out=new ArrayList<>();
        long window=policies.correlation().windowSeconds();
        for (var entry:assets.entrySet()) {
            Instant low=entry.getValue().stream().map(IngestMapper.AcceptedRecord::eventTime).min(Instant::compareTo).orElseThrow().minusSeconds(window);
            Instant high=entry.getValue().stream().map(IngestMapper.AcceptedRecord::eventTime).max(Instant::compareTo).orElseThrow().plusSeconds(window);
            var rows=mapper.context(entry.getKey(),low.minusSeconds(window),high.plusSeconds(window),
                    policies.severity().version(),policies.correlation().version(),AlertGenerator.WINDOW_CONTEXT_LIMIT+1);
            if (rows.size()>AlertGenerator.WINDOW_CONTEXT_LIMIT) throw new DetectionUnavailableException("DETECTION_WINDOW_CAPACITY_EXCEEDED");
            Map<String,List<ModelSignalMapper.Row>> contracts=new HashMap<>();
            for (var r:rows) if (r.contractVersion()!=null) contracts.computeIfAbsent(r.contractVersion(), k->new ArrayList<>()).add(r);
            for (var group:contracts.values()) {
                List<Instant> rules=new ArrayList<>();
                Map<Long,Instant> modelRecords=new HashMap<>();
                for (var r:group) {
                    if (r.alertType().equals("rule")) rules.add(r.eventTime());
                    else modelRecords.put(r.recordId(),r.eventTime());
                }
                rules.sort(Instant::compareTo);
                List<Instant> models=modelRecords.values().stream().sorted().toList();
                for (var r:group) {
                    if (!r.alertLayer().equals("signal") || r.eventTime().isBefore(low) || r.eventTime().isAfter(high)) continue;
                    int count=upper(models,r.eventTime())-upper(models,r.eventTime().minusSeconds(window));
                    boolean rule=upper(rules,r.eventTime().plusSeconds(window))>lower(rules,r.eventTime().minusSeconds(window));
                    String cause=rule?"rule_corroboration":r.score().doubleValue()>=signal.highScore()?"high_score":count>=signal.countThreshold()?"signal_count":null;
                    if (cause==null) continue;
                    String level=policies.severity().map(r.score().doubleValue());
                    var basis=json.createObjectNode().put("reason",cause).put("signalCount",count)
                            .put("countThreshold",signal.countThreshold()).put("highScore",signal.highScore())
                            .put("windowSeconds",window).put("correlationPolicyVersion",policies.correlation().version())
                            .put("severityPolicyVersion",policies.severity().version());
                    if (mapper.promote(r.id(),level,basis.toString(),now)==1) out.add(new AlertGenerator.NewAlert(r.id(),r.recordId(),entry.getKey(),r.eventTime(),"model",level,"模型信号升级："+cause));
                }
            }
        }
        return out;
    }
    private static int upper(List<Instant> values, Instant key) { return bound(values,key,true); }
    private static int lower(List<Instant> values, Instant key) { return bound(values,key,false); }
    private static int bound(List<Instant> values, Instant key, boolean inclusive) {
        int lo=0,hi=values.size();
        while(lo<hi) { int mid=(lo+hi)>>>1; int c=values.get(mid).compareTo(key); if(c<0 || (inclusive && c==0)) lo=mid+1; else hi=mid; }
        return lo;
    }
}
