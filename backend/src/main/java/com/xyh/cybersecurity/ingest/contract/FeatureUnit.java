package com.xyh.cybersecurity.ingest.contract;

import java.util.Arrays;
import java.util.Optional;

/**
 * 契约数值字段允许的单位枚举。
 *
 * <p>{@code code} 是契约 JSON 中的机器可读值；{@code manifestLabel} 是训练端 manifest / preprocessing.json
 * 中的中文单位名。两者一一对应，模型制品校验按此比对“契约单位 = manifest 单位”，不做模糊匹配。</p>
 */
public enum FeatureUnit {
    SECOND("second", "秒"),
    BYTE("byte", "字节"),
    BIT_PER_SECOND("bit_per_second", "比特/秒"),
    PACKET("packet", "包"),
    FLOW_COUNT("flow_count", "条");

    private final String code;
    private final String manifestLabel;

    FeatureUnit(String code, String manifestLabel) {
        this.code = code;
        this.manifestLabel = manifestLabel;
    }

    public String code() { return code; }

    public String manifestLabel() { return manifestLabel; }

    /** 按契约 JSON 的单位代码解析；未知代码返回空，由加载器 fail-fast。 */
    public static Optional<FeatureUnit> fromCode(String code) {
        return Arrays.stream(values()).filter(unit -> unit.code.equals(code)).findFirst();
    }
}
