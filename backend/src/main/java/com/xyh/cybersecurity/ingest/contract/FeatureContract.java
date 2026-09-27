package com.xyh.cybersecurity.ingest.contract;

import java.util.List;
import java.util.Set;

/**
 * 不可变的原始流特征契约。接入端只提供 raw fields，不能重复执行 ONNX 图中的派生和编码。
 */
public record FeatureContract(String version, List<String> numericFields, List<String> categoricalFields,
                              Set<String> nullableNumericFields, boolean onlineEnabled) {
    public static final String V3_1 = "unsw-nb15-flow-v3.1";
    public static final FeatureContract UNSW_NB15_V3_1 = new FeatureContract(
            V3_1,
            List.of("dur", "sbytes", "dbytes", "sttl", "sload", "dload", "sloss", "dinpkt",
                    "sjit", "djit", "tcprtt", "ackdat", "smean", "dmean", "ct_srv_src",
                    "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
                    "ct_dst_src_ltm", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "spkts",
                    "dpkts", "synack"),
            List.of("proto", "service"),
            Set.of("ct_flw_http_mthd"),
            // ct_state_ttl 的训练 codebook 尚未随当前 manifest 固化，在线推理必须保持关闭。
            false);
}
