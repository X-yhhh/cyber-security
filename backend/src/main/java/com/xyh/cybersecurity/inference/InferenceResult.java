package com.xyh.cybersecurity.inference;

import com.xyh.cybersecurity.ingest.IngestMapper;
import com.xyh.cybersecurity.model.runtime.OnnxModelManager;

import java.time.Instant;

/**
 * 单条记录的推理结论快照，与 {@code inference_request} 的一行对应（dry-run 不落库）。
 *
 * <p>只有 {@code succeeded} 带分数、标签和阈值快照；{@code rejected}/{@code failed}/{@code timed_out}
 * 必带稳定错误码；{@code not_in_model_scope} 只带细分原因。与 V12 的 CHECK 约束一致。</p>
 *
 * @param modelVersionId 判定或推理所用的激活模型；没有激活模型、批次未声明契约或配置失效时为空
 * @param latencyMs      从提交到拿到结果的墙钟耗时（含排队），同批次各条相同；未进入推理时为空
 * @param rejectReason   机器可读的细分原因（≤64 字符），不含记录内容
 */
public record InferenceResult(long ingestRecordId, String recordKey, String requestKey, String status,
                              Long modelVersionId, String modelKey, String modelVersion,
                              String contractVersion, String contractSha256, Double attackProbability,
                              String binaryLabel, Double decisionThreshold, String thresholdPolicyVersion,
                              Long latencyMs, String errorCode, String rejectReason,
                              Instant requestedAt, Instant completedAt) {

    public static final String DEPLOYMENT_MODE = "local";
    public static final String SUCCEEDED = "succeeded";
    public static final String REJECTED = "rejected";
    public static final String FAILED = "failed";
    public static final String TIMED_OUT = "timed_out";
    public static final String NOT_IN_MODEL_SCOPE = "not_in_model_scope";

    /**
     * 同一条接入记录在本机只推理一次。键不含模型版本：重复投递、版本切换后的重放都不会产生第二行；
     * 影子对比等多版本推理以后另用独立前缀，不复用此键。
     */
    public static String requestKey(long ingestRecordId) {
        return "local:record:" + ingestRecordId;
    }

    /**
     * 一个批次共享的判定上下文。
     *
     * @param model 激活模型描述；为空表示判定时没有可用模型
     */
    record Snapshot(OnnxModelManager.ActiveModel model, String contractVersion, String contractSha256,
                    Instant requestedAt) { }

    static InferenceResult succeeded(IngestMapper.AcceptedRecord record, Snapshot snapshot, double probability,
                                     boolean attack, long latencyMs, Instant completedAt) {
        OnnxModelManager.ActiveModel model = snapshot.model();
        return new InferenceResult(record.id(), record.recordKey(), requestKey(record.id()), SUCCEEDED,
                model.modelId(), model.modelKey(), model.version(), snapshot.contractVersion(),
                snapshot.contractSha256(), probability, attack ? "Attack" : "Normal", model.decisionThreshold(),
                model.thresholdPolicyVersion(), latencyMs, null, null, snapshot.requestedAt(), completedAt);
    }

    static InferenceResult unscored(IngestMapper.AcceptedRecord record, Snapshot snapshot, String status,
                                    String errorCode, String reason, Long latencyMs, Instant completedAt) {
        OnnxModelManager.ActiveModel model = snapshot.model();
        return new InferenceResult(record.id(), record.recordKey(), requestKey(record.id()), status,
                model == null ? null : model.modelId(), model == null ? null : model.modelKey(),
                model == null ? null : model.version(), snapshot.contractVersion(), snapshot.contractSha256(),
                null, null, null, null, latencyMs, errorCode, truncate(reason), snapshot.requestedAt(), completedAt);
    }

    InferenceMapper.RequestInsert toInsert() {
        return new InferenceMapper.RequestInsert(requestKey, ingestRecordId, modelVersionId, contractVersion,
                contractSha256, DEPLOYMENT_MODE, status, attackProbability, binaryLabel, decisionThreshold,
                thresholdPolicyVersion, latencyMs, errorCode, rejectReason, requestedAt, completedAt);
    }

    private static String truncate(String reason) {
        return reason == null || reason.length() <= 64 ? reason : reason.substring(0, 64);
    }
}
