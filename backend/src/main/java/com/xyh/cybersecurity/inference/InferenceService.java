package com.xyh.cybersecurity.inference;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.ingest.IngestMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.model.runtime.FeatureContractModelGate;
import com.xyh.cybersecurity.model.runtime.OnnxModelManager;
import com.xyh.cybersecurity.model.runtime.OnnxModelRuntime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * M3 本机推理服务（路线 B §10.1 第 2、3 项）：契约门禁 → 按 manifest 顺序构造输入 → 激活版本推理 → 结果快照。
 *
 * <p>失败语义：无激活模型、契约不一致、输入不合规、超时、会话错误都写成显式状态与稳定错误码，
 * 不回退到其他模型、不给默认分数。容量耗尽或判定后版本切换抛 {@link InferenceUnavailableException}，整批回滚重试。</p>
 */
@Service
public class InferenceService {
    private static final String MISMATCH = FeatureContractModelGate.MISMATCH;

    private final InferenceMapper mapper;
    private final OnnxModelManager models;
    private final FeatureContractModelGate gate;
    private final FeatureContractRegistry contracts;
    private final ObjectMapper json;
    private final LocalInferenceRunner runner;
    private final Clock clock;

    @Autowired
    public InferenceService(InferenceMapper mapper, OnnxModelManager models, FeatureContractModelGate gate,
                            FeatureContractRegistry contracts, ObjectMapper json, LocalInferenceRunner runner) {
        this(mapper, models, gate, contracts, json, runner, Clock.systemUTC());
    }

    InferenceService(InferenceMapper mapper, OnnxModelManager models, FeatureContractModelGate gate,
                     FeatureContractRegistry contracts, ObjectMapper json, LocalInferenceRunner runner, Clock clock) {
        this.mapper = mapper;
        this.models = models;
        this.gate = gate;
        this.contracts = contracts;
        this.json = json;
        this.runner = runner;
        this.clock = clock;
    }

    /**
     * 推理并落库。必须在调用方事务内执行（M2 消费事务），与消费幂等台账一起提交或回滚；
     * 已有 {@code inference_request} 的记录跳过，重复投递不会重复推理。
     *
     * @return 本次新写入的结果；全部已推理过时为空
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public List<InferenceResult> inferBatch(long batchId, List<IngestMapper.AcceptedRecord> records) {
        if (records.isEmpty()) return List.of();
        List<String> keys = records.stream().map(record -> InferenceResult.requestKey(record.id())).toList();
        Set<String> existing = new HashSet<>(mapper.findExistingRequestKeys(keys));
        List<IngestMapper.AcceptedRecord> pending = records.stream()
                .filter(record -> !existing.contains(InferenceResult.requestKey(record.id()))).toList();
        if (pending.isEmpty()) return List.of();
        List<InferenceResult> results = evaluate(batchId, pending);
        results.forEach(result -> mapper.insertRequest(result.toInsert()));
        return results;
    }

    /** 同一判定与推理路径，但不写 {@code inference_request}；仅供回放数据 dry-run。 */
    public List<InferenceResult> dryRun(long batchId, List<IngestMapper.AcceptedRecord> records) {
        return records.isEmpty() ? List.of() : evaluate(batchId, records);
    }

    private List<InferenceResult> evaluate(long batchId, List<IngestMapper.AcceptedRecord> records) {
        Instant requestedAt = clock.instant();
        InferenceMapper.BatchContext context = mapper.findBatchContext(batchId);
        if (context == null) throw new IllegalStateException("INFERENCE_BATCH_NOT_FOUND");
        String recordContract = context.recordContractVersion();
        FeatureContract contract = recordContract == null ? null : contracts.find(recordContract);
        String contractSha = contract == null ? null : contract.fileSha256();

        InferenceResult.Snapshot bare = new InferenceResult.Snapshot(null, recordContract, contractSha, requestedAt);
        if (recordContract == null) return rejectAll(records, bare, MISMATCH, "record_contract_missing");
        if (context.sensorId() == null || context.configContractVersion() == null
                || !"active".equals(context.configStatus())) {
            return rejectAll(records, bare, MISMATCH, "config_not_active");
        }
        OnnxModelManager.ActiveModel model = models.activeLocal().orElse(null);
        if (model == null) return rejectAll(records, bare, "ACTIVE_MODEL_UNAVAILABLE", "model_unavailable");

        InferenceResult.Snapshot snapshot = new InferenceResult.Snapshot(model, recordContract, contractSha, requestedAt);
        InferenceResult[] results = new InferenceResult[records.size()];
        List<Integer> scored = new ArrayList<>();
        List<OnnxModelRuntime.FlowInput> inputs = new ArrayList<>();
        for (int i = 0; i < records.size(); i++) {
            IngestMapper.AcceptedRecord record = records.get(i);
            InferencePayload.Parsed parsed = InferencePayload.parse(json, record.normalizedPayload());
            if (parsed == null) {
                results[i] = InferenceResult.unscored(record, snapshot, InferenceResult.REJECTED,
                        "MODEL_INPUT_CONTRACT_MISMATCH", "payload_invalid", null, requestedAt);
                continue;
            }
            FeatureContractModelGate.Decision decision = gate.check(recordContract, context.configContractVersion(),
                    context.configContractSha256(), model.inputs(), parsed.metadata());
            if (decision.outcome() == FeatureContractModelGate.Outcome.REJECT) {
                results[i] = InferenceResult.unscored(record, snapshot, InferenceResult.REJECTED,
                        decision.errorCode(), decision.reason(), null, requestedAt);
                continue;
            }
            if (decision.outcome() == FeatureContractModelGate.Outcome.NOT_IN_MODEL_SCOPE) {
                results[i] = InferenceResult.unscored(record, snapshot, InferenceResult.NOT_IN_MODEL_SCOPE,
                        null, decision.reason(), null, requestedAt);
                continue;
            }
            InferencePayload.Extraction extraction = InferencePayload.extract(parsed.features(), model.inputs());
            if (!extraction.ok()) {
                results[i] = InferenceResult.unscored(record, snapshot, InferenceResult.REJECTED,
                        "MODEL_INPUT_CONTRACT_MISMATCH", extraction.reason(), null, requestedAt);
                continue;
            }
            scored.add(i);
            inputs.add(extraction.input());
        }
        if (!inputs.isEmpty()) score(records, snapshot, scored, inputs, results);
        return List.of(results);
    }

    private void score(List<IngestMapper.AcceptedRecord> records, InferenceResult.Snapshot snapshot,
                       List<Integer> scored, List<OnnxModelRuntime.FlowInput> inputs, InferenceResult[] results) {
        OnnxModelManager.ActiveModel model = snapshot.model();
        LocalInferenceRunner.Outcome outcome = runner.run(model.modelId(), inputs);
        Instant completedAt = clock.instant();
        boolean sizeOk = outcome.kind() != LocalInferenceRunner.Kind.SUCCEEDED
                || outcome.predictions().size() == inputs.size();
        for (int n = 0; n < scored.size(); n++) {
            int i = scored.get(n);
            IngestMapper.AcceptedRecord record = records.get(i);
            if (outcome.kind() == LocalInferenceRunner.Kind.TIMED_OUT) {
                results[i] = InferenceResult.unscored(record, snapshot, InferenceResult.TIMED_OUT,
                        outcome.errorCode(), "batch_timeout", outcome.latencyMs(), completedAt);
            } else if (outcome.kind() == LocalInferenceRunner.Kind.FAILED || !sizeOk) {
                results[i] = InferenceResult.unscored(record, snapshot, InferenceResult.FAILED,
                        sizeOk ? outcome.errorCode() : "MODEL_OUTPUT_CONTRACT_MISMATCH", "runtime_failed",
                        outcome.latencyMs(), completedAt);
            } else {
                OnnxModelRuntime.Prediction prediction = outcome.predictions().get(n);
                double probability = prediction.attackProbability();
                // 图内 is_attack 已按 manifest 阈值判定；与分数不一致说明输出不可信，不写成功结论。
                if (prediction.isAttack() != (prediction.attackProbability() >= model.decisionThreshold())) {
                    results[i] = InferenceResult.unscored(record, snapshot, InferenceResult.FAILED,
                            "MODEL_OUTPUT_CONTRACT_MISMATCH", "label_threshold_inconsistent",
                            outcome.latencyMs(), completedAt);
                } else {
                    results[i] = InferenceResult.succeeded(record, snapshot, probability, prediction.isAttack(),
                            outcome.latencyMs(), completedAt);
                }
            }
        }
    }

    private List<InferenceResult> rejectAll(List<IngestMapper.AcceptedRecord> records, InferenceResult.Snapshot snapshot,
                                            String errorCode, String reason) {
        return records.stream().map(record -> InferenceResult.unscored(record, snapshot, InferenceResult.REJECTED,
                errorCode, reason, null, snapshot.requestedAt())).toList();
    }
}
