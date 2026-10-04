package com.xyh.cybersecurity.ingest.contract;

import java.util.Arrays;
import java.util.Optional;

/**
 * 契约声明的跨字段边界约束（规格 §2.1 说明、§4 边界取值汇总）。
 *
 * <p>只收录规格中“必须取 0”的硬边界，不校验 {@code sload}、{@code smean} 等公式本身：公式由流引擎/传感器实现，
 * 训练数据中公式与 CSV 并非逐行成立（规格 §5），在接入端复算会误拒真实记录。违反任何一条都按
 * {@code FEATURE_VALUE_INVALID} fail-closed。</p>
 *
 * <p>收录标准：训练数据（UNSW-NB15 原始 2,540,047 行，按规格 §4 处理 load 边界后）违反数为 0。规格 §2.1 的
 * “握手三项全有或全无”不收录：训练数据中有 402 条 TCP 行只有部分握手字段非零，强制执行会拒绝模型训练过的样本。</p>
 */
public enum ConsistencyRule {
    /** 非 TCP 流的 {@code synack}、{@code ackdat}、{@code tcprtt} 必须为 0（规格 §4）。 */
    HANDSHAKE_ZERO_WHEN_NOT_TCP("handshake_zero_when_not_tcp"),
    /** {@code dpkts = 0} 时 {@code dbytes}、{@code dmean}、{@code dload} 必须为 0（规格 §4）。 */
    REVERSE_DIRECTION_ZERO_WHEN_NO_PACKETS("reverse_direction_zero_when_no_packets"),
    /** {@code dur = 0} 或某方向包数 ≤ 1 时，该方向 load 必须为 0（规格 §2.1 #3/#4、§4）。 */
    LOAD_ZERO_WHEN_INSUFFICIENT_PACKETS_OR_DURATION("load_zero_when_insufficient_packets_or_duration");

    private final String code;

    ConsistencyRule(String code) { this.code = code; }

    public String code() { return code; }

    public static Optional<ConsistencyRule> fromCode(String code) {
        return Arrays.stream(values()).filter(rule -> rule.code.equals(code)).findFirst();
    }
}
