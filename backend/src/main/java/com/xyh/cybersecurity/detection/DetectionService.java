package com.xyh.cybersecurity.detection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.IngestMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.Set;

/**
 * M4 告警生成与事件关联入口（路线 B §11）：加载 active 策略 → 模型/规则告警 → 事件关联与风险评分。
 *
 * <p>必须在 M2 消费事务内、推理之后执行，与推理结论和消费台账同一事务提交；策略缺失或不合规抛
 * {@link DetectionUnavailableException}，整批回滚重试。只检测，不触发任何处置动作。</p>
 */
@Service
public class DetectionService {
    private final DetectionMapper mapper;
    private final AlertGenerator generator;
    private final EventCorrelator correlator;
    private final ObjectMapper json;
    private final Clock clock;

    @Autowired
    public DetectionService(DetectionMapper mapper, AlertGenerator generator, EventCorrelator correlator,
                            ObjectMapper json) {
        this(mapper, generator, correlator, json, Clock.systemUTC());
    }

    DetectionService(DetectionMapper mapper, AlertGenerator generator, EventCorrelator correlator, ObjectMapper json,
                     Clock clock) {
        this.mapper = mapper;
        this.generator = generator;
        this.correlator = correlator;
        this.json = json;
        this.clock = clock;
    }

    public record Summary(int alertsCreated, int eventsTouched) { }

    @Transactional(propagation = Propagation.MANDATORY)
    public Summary processBatch(long batchId, List<IngestMapper.AcceptedRecord> records) {
        DetectionPolicies policies = DetectionPolicies.load(mapper, json);
        List<AlertGenerator.NewAlert> alerts = generator.generate(batchId, records, policies, clock.instant());
        if (alerts.isEmpty()) return new Summary(0, 0);
        Set<Long> events = correlator.correlate(alerts, policies);
        return new Summary(alerts.size(), events.size());
    }
}
