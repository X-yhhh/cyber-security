package com.xyh.cybersecurity.ingest.contract;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 接入层读取“当前激活模型的输入范围”的端口，由模型运行时实现（依赖方向：model → ingest.contract）。
 *
 * <p>接入层只把这些信息用于非阻断遥测（词表外类别、词表不可用、不在模型评估范围）；是否推理由推理入口的
 * {@code FeatureContractModelGate} 按同一份模型输入契约最终判定。没有激活模型时返回空，接入不因此阻断
 * （路线 B 阶段 3 决策 4）。</p>
 */
public interface ActiveModelInputs {

    /** 无激活模型的实现，用于测试与未启用模型运行时的场景。 */
    ActiveModelInputs NONE = contractVersion -> Optional.empty();

    /** 返回绑定该契约版本的激活模型输入范围；没有则为空。 */
    Optional<Scope> forContract(String contractVersion);

    /**
     * 激活模型的输入范围快照。
     *
     * @param modelVersion             模型版本（仅用于遥测说明）
     * @param vocabularies             类别字段名 → 训练词表（来自已核对哈希的 preprocessing.json）
     * @param supportedViewpoints      manifest {@code supported_viewpoints}；空表示模型未声明、不限制
     * @param supportedAddressFamilies manifest {@code supported_address_families}；空表示不限制
     * @param supportedProtocols       manifest {@code supported_protocols}；空表示不限制
     * @param requiresHandshakeSeen    manifest {@code requires_handshake_seen}
     */
    record Scope(String modelVersion, Map<String, Set<String>> vocabularies, List<String> supportedViewpoints,
                 List<String> supportedAddressFamilies, List<String> supportedProtocols, boolean requiresHandshakeSeen) {
        public Scope {
            vocabularies = Map.copyOf(vocabularies);
            supportedViewpoints = List.copyOf(supportedViewpoints);
            supportedAddressFamilies = List.copyOf(supportedAddressFamilies);
            supportedProtocols = List.copyOf(supportedProtocols);
        }

        public Scope(String modelVersion, Map<String, Set<String>> vocabularies, List<String> supportedViewpoints,
                     List<String> supportedAddressFamilies) {
            this(modelVersion, vocabularies, supportedViewpoints, supportedAddressFamilies, List.of(), false);
        }

        /**
         * 视角、地址族、协议与握手都在模型评估范围内时返回 true；元数据缺失按不在范围处理。
         * 判定口径与推理门禁 {@code FeatureContractModelGate} 一致。
         */
        public boolean covers(RecordMetadata metadata, String proto) {
            if (metadata == null) return supportedViewpoints.isEmpty() && supportedAddressFamilies.isEmpty()
                    && supportedProtocols.isEmpty() && !requiresHandshakeSeen;
            return (supportedViewpoints.isEmpty() || supportedViewpoints.contains(metadata.viewpoint()))
                    && (supportedAddressFamilies.isEmpty() || supportedAddressFamilies.contains(metadata.addressFamily()))
                    && (supportedProtocols.isEmpty() || proto != null && supportedProtocols.contains(proto))
                    && (!requiresHandshakeSeen || Boolean.TRUE.equals(metadata.handshakeSeen()));
        }
    }
}
