package com.xyh.cybersecurity.ingest.feature;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 训练侧冻结的状态/TTL 编码表。没有明确编码表时，构造器拒绝创建，避免把本地猜测写入模型输入。
 */
public final class CtStateTtlCodebook {
    private final List<Entry> entries;

    public CtStateTtlCodebook(List<Entry> entries) {
        if (entries == null || entries.isEmpty()) throw new IllegalArgumentException("ct_state_ttl codebook 不能为空");
        this.entries = List.copyOf(entries);
        for (Entry entry : this.entries) Objects.requireNonNull(entry, "codebook entry");
    }

    public static CtStateTtlCodebook from(Map<StateTtl, Integer> values) {
        if (values == null || values.isEmpty()) throw new IllegalArgumentException("ct_state_ttl codebook 不能为空");
        return new CtStateTtlCodebook(values.entrySet().stream()
                .map(e -> new Entry(e.getKey(), e.getValue())).toList());
    }

    public int encode(String state, int ttl) {
        return entries.stream().filter(e -> e.matches(state, ttl)).findFirst()
                .map(Entry::code).orElseThrow(() -> new UnknownStateTtlException(state, ttl));
    }

    public List<Entry> entries() { return entries; }

    public record StateTtl(String state, int minTtl, int maxTtl) {
        public StateTtl {
            if (state == null || state.isBlank() || minTtl < 0 || maxTtl < minTtl) {
                throw new IllegalArgumentException("状态或 TTL 区间不合法");
            }
        }
        boolean matches(String value, int ttl) { return state.equals(value) && ttl >= minTtl && ttl <= maxTtl; }
    }

    public record Entry(StateTtl range, int code) {
        public Entry {
            Objects.requireNonNull(range, "range");
            if (code < 0) throw new IllegalArgumentException("ct_state_ttl 编码不能为负数");
        }
        boolean matches(String state, int ttl) { return range.matches(state, ttl); }
    }

    public static final class UnknownStateTtlException extends RuntimeException {
        public UnknownStateTtlException(String state, int ttl) { super("未找到状态/TTL 编码"); }
    }
}
