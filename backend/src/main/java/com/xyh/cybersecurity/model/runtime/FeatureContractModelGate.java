package com.xyh.cybersecurity.model.runtime;

import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.ingest.contract.RecordMetadata;
import org.springframework.stereotype.Component;

/**
 * 推理入口的契约一致性门禁（路线 B §3.2、§9.1 第 6 项）。
 *
 * <p>推理前必须同时满足：记录契约 = 传感器已批准配置契约 = 激活模型 manifest 契约，且配置登记的契约文件哈希
 * 等于当前注册契约的文件哈希、契约本身 {@code onlineEnabled}。任一不满足返回稳定错误码
 * {@code FEATURE_CONTRACT_MODEL_MISMATCH}，不切换模型、不回退到其他契约。</p>
 *
 * <p>契约一致但视角或地址族不在模型评估范围（manifest {@code supported_viewpoints}/
 * {@code supported_address_families}）时返回 {@link Outcome#NOT_IN_MODEL_SCOPE}：记录不推理，但不算作拒绝。</p>
 *
 * <p>本类是纯判定组件，不访问数据库；阶段 4 的推理任务提交实现在写 {@code inference_request} 前调用它。</p>
 */
@Component
public final class FeatureContractModelGate {
    public static final String MISMATCH = "FEATURE_CONTRACT_MODEL_MISMATCH";

    private final FeatureContractRegistry registry;

    public FeatureContractModelGate(FeatureContractRegistry registry) {
        this.registry = registry;
    }

    /**
     * @param recordContract     记录（批次）声明的契约版本
     * @param configContract     传感器已批准配置绑定的契约版本
     * @param configContractSha  配置登记的契约文件 SHA-256（V11 {@code sensor_config.feature_contract_sha256}）
     * @param model              激活模型的输入契约；{@code null} 表示没有激活模型
     * @param metadata           记录元数据；契约要求元数据时必填
     */
    public Decision check(String recordContract, String configContract, String configContractSha,
                          ModelInputContract model, RecordMetadata metadata) {
        if (model == null) return Decision.reject("model_unavailable");
        if (recordContract == null || !recordContract.equals(configContract)) return Decision.reject("record_config_mismatch");
        if (!recordContract.equals(model.contractVersion())) return Decision.reject("record_model_mismatch");
        FeatureContract contract = registry.find(recordContract);
        if (contract == null || !contract.onlineEnabled()) return Decision.reject("contract_not_online");
        if (configContractSha == null || !configContractSha.equals(contract.fileSha256())) {
            return Decision.reject("config_contract_hash_mismatch");
        }
        if (contract.specSha256() != null && !contract.specSha256().equals(model.specSha256())) {
            return Decision.reject("model_spec_hash_mismatch");
        }
        if (contract.requiresRecordMetadata()) {
            if (metadata == null || metadata.viewpoint() == null || metadata.addressFamily() == null) {
                return Decision.reject("record_metadata_missing");
            }
            boolean viewpointOk = model.supportedViewpoints().isEmpty() || model.supportedViewpoints().contains(metadata.viewpoint());
            boolean familyOk = model.supportedAddressFamilies().isEmpty()
                    || model.supportedAddressFamilies().contains(metadata.addressFamily());
            if (!viewpointOk || !familyOk) return new Decision(Outcome.NOT_IN_MODEL_SCOPE, null, "not_in_model_scope");
        }
        return new Decision(Outcome.ACCEPT, null, null);
    }

    public enum Outcome { ACCEPT, REJECT, NOT_IN_MODEL_SCOPE }

    /**
     * @param errorCode 仅 REJECT 时为 {@link #MISMATCH}
     * @param reason    机器可读的细分原因，不含记录内容
     */
    public record Decision(Outcome outcome, String errorCode, String reason) {
        static Decision reject(String reason) { return new Decision(Outcome.REJECT, MISMATCH, reason); }

        public boolean accepted() { return outcome == Outcome.ACCEPT; }
    }
}
