package com.xyh.cybersecurity.ingest.feature;

import java.net.InetAddress;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiPredicate;

/**
 * 单个传感器、单个地址族的「最近 N 条已完成流」窗口（规格 §3、契约 {@code window}）。
 *
 * <p>排序键 {@code (flowEndAt, flowStartAt, exportSeq)}，{@code allowedLatenessSeconds = 0}：
 * 排序键不大于已接纳的最大键的记录一律按迟到拒绝，不做回填或重排（传感器负责先重排序再上报）。
 * 同一 {@code recordKey} 重复出现按重复拒绝。窗口包含当前流自身。</p>
 *
 * <p>本类不是线程安全的；由 {@link FeatureBuilder} 串行调用。</p>
 */
final class FeatureWindow {
    static final Comparator<Member> ORDER = Comparator.comparing(Member::flowEndAt)
            .thenComparing(Member::flowStartAt).thenComparingLong(Member::exportSeq);

    private final int size;
    private final ArrayDeque<Member> members = new ArrayDeque<>();
    private final Set<String> recentKeys = new HashSet<>();
    private Member last;

    FeatureWindow(int size) {
        if (size < 1) throw new IllegalArgumentException("窗口长度必须为正数");
        this.size = size;
    }

    /** 尝试加入一条流；返回 {@code null} 表示已加入，否则返回拒绝原因。 */
    String add(Member member) {
        if (recentKeys.contains(member.recordKey())) return "duplicate_record";
        if (last != null && ORDER.compare(member, last) <= 0) return "late_event";
        members.addLast(member);
        recentKeys.add(member.recordKey());
        last = member;
        while (members.size() > size) recentKeys.remove(members.removeFirst().recordKey());
        return null;
    }

    boolean ready() { return members.size() == size; }

    int size() { return members.size(); }

    /** 统计窗口内与当前流满足谓词的流数（含当前流自身）。 */
    int count(Member current, BiPredicate<Member, Member> sameKey) {
        int n = 0;
        for (Member member : members) if (sameKey.test(member, current)) n++;
        return n;
    }

    List<Member> snapshot() { return List.copyOf(members); }

    /**
     * 窗口成员只保留计数所需的元数据；地址仅在受控内存中使用，不写入特征或日志。
     *
     * @param responderPort 响应方端口；无端口协议为 0，来源缺失时为 {@code null}（按独立取值参与相等比较）
     */
    record Member(String recordKey, Instant flowStartAt, Instant flowEndAt, long exportSeq, InetAddress initiator,
                  InetAddress responder, Integer responderPort, String service) { }
}
