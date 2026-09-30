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
     */
    record Scope(String modelVersion, Map<String, Set<String>> vocabularies, List<String> supportedViewpoints,
                 List<String> supportedAddressFamilies) {
        public Scope {
            vocabularies = Map.copyOf(vocabularies);
            supportedViewpoints = List.copyOf(supportedViewpoints);
            supportedAddressFamilies = List.copyOf(supportedAddressFamilies);
        }

        /** 视角与地址族都在模型评估范围内时返回 true；元数据缺失按不在范围处理。 */
        public boolean covers(RecordMetadata metadata) {
            if (metadata == null) return supportedViewpoints.isEmpty() && supportedAddressFamilies.isEmpty();
            return (supportedViewpoints.isEmpty() || supportedViewpoints.contains(metadata.viewpoint()))
                    && (supportedAddressFamilies.isEmpty() || supportedAddressFamilies.contains(metadata.addressFamily()));
        }
    }
}
