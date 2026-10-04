package com.xyh.cybersecurity.inference;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.xyh.cybersecurity.ingest.IngestMapper;
import com.xyh.cybersecurity.ingest.contract.FeatureContract;
import com.xyh.cybersecurity.ingest.contract.FeatureContractRegistry;
import com.xyh.cybersecurity.model.runtime.ModelInputContract;
import com.xyh.cybersecurity.model.runtime.OnnxModelManager;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** 推理单元测试共用的 v4 契约、激活模型描述与合成记录（特征为合成值，不含地址）。 */
final class InferenceTestSupport {
    static final String V4 = "unsw-nb15-flow-v4";
    static final FeatureContractRegistry REGISTRY = FeatureContractRegistry.fromClasspath();
    static final FeatureContract CONTRACT = REGISTRY.require(V4);
    static final ObjectMapper JSON = new ObjectMapper();
    static final ModelInputContract INPUTS = new ModelInputContract(V4, CONTRACT.specSha256(),
            CONTRACT.numericFieldNames(), CONTRACT.categoricalFieldNames(), Set.of(), Map.of(),
            List.of("responder"), List.of("ipv4"));
    static final OnnxModelManager.ActiveModel MODEL = new OnnxModelManager.ActiveModel(5, "unsw-binary", "2026.10.0",
            0.35, "fixed:unsw-binary-2026.10.0", INPUTS);

    private InferenceTestSupport() { }

    /** @param droppedFeature 需要从 features 中删除的字段；{@code null} 表示字段齐全 */
    static IngestMapper.AcceptedRecord record(long id, String viewpoint, String droppedFeature) {
        ObjectNode root = JSON.createObjectNode();
        root.putObject("metadata").put("viewpoint", viewpoint).put("addressFamily", "ipv4").put("handshakeSeen", true);
        ObjectNode features = root.putObject("features");
        CONTRACT.numericFieldNames().forEach(name -> features.put(name, 1));
        features.put("proto", "tcp").put("service", "http");
        if (droppedFeature != null) features.remove(droppedFeature);
        return new IngestMapper.AcceptedRecord(id, 7, 3, "r-" + id, Instant.parse("2026-09-29T11:00:00Z"), 4,
                root.toString());
    }

    static IngestMapper.AcceptedRecord rawRecord(long id, String payload) {
        return new IngestMapper.AcceptedRecord(id, 7, 3, "r-" + id, Instant.parse("2026-09-29T11:00:00Z"), 4, payload);
    }

    /** 批次 7 的契约上下文；{@code configContract=null} 时模拟 connector 批次（无传感器配置）。 */
    static InferenceMapper.BatchContext context(String recordContract, String configContract, String status) {
        return new InferenceMapper.BatchContext(7, 3, recordContract, configContract == null ? null : 11L, "cfg-1",
                configContract, configContract == null ? null : CONTRACT.fileSha256(), status);
    }
}
