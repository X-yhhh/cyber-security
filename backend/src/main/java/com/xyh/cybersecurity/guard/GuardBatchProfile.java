package com.xyh.cybersecurity.guard;

import jdk.jfr.*;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * 批次性能诊断：仅在 JFR 录制开启时记录阶段、批次 UUID 和耗时，不保存观察、端点或凭据。
 * 诊断事件不参与事务和判定；提交段从 beforeCommit 到 afterCompletion，回滚单独标记。
 */
public final class GuardBatchProfile {
    private GuardBatchProfile() {}
    private static final ThreadLocal<String> BATCH = new ThreadLocal<>();
    static { if (FlightRecorder.isAvailable()) FlightRecorder.register(PhaseEvent.class); }

    @Name("cyber.guard.BatchPhase")
    @Label("Guard batch phase")
    @Category({"Cyber", "Guard"})
    @StackTrace(false)
    @Enabled(true)
    @Threshold("0 ns")
    public static final class PhaseEvent extends Event {
        public String batchId;
        public String phase;
        public boolean committed;
    }

    /** 在当前机器请求线程绑定批次，退出时恢复上下文；未录制时无业务侧状态。 */
    public static Scope batch(String id) {
        String previous = BATCH.get();
        if (id != null && new PhaseEvent().isEnabled()) BATCH.set(id);
        return () -> { if (previous == null) BATCH.remove(); else BATCH.set(previous); };
    }

    /** 阶段可嵌套，聚合时分别报告包含时间，不能把父/子阶段相加当作总耗时。 */
    public static Scope phase(String name) {
        PhaseEvent event = event(name);
        if (event == null) return () -> {};
        event.begin();
        return () -> { event.end(); event.commit(); };
    }

    /** 注册真实事务提交阶段；没有批次上下文或事务时不生成事件。 */
    public static void transaction(String name) {
        PhaseEvent event = event(name);
        if (event == null || !TransactionSynchronizationManager.isSynchronizationActive()) return;
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            private boolean started;
            @Override public void beforeCommit(boolean readOnly) { event.begin(); started = true; }
            @Override public void afterCompletion(int status) {
                if (!started) event.begin();
                event.committed = status == STATUS_COMMITTED;
                event.end();
                event.commit();
            }
        });
    }

    private static PhaseEvent event(String phase) {
        if (BATCH.get() == null) return null;
        PhaseEvent event = new PhaseEvent();
        if (!event.isEnabled()) return null;
        event.batchId = BATCH.get();
        event.phase = phase;
        return event;
    }

    @FunctionalInterface public interface Scope extends AutoCloseable {
        @Override void close();
    }
}
