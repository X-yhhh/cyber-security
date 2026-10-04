package com.xyh.cybersecurity.ingest.outbox;

import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 调度 outbox relay，保证调用 publishPending 时经过事务代理。
 *
 * <p>两条触发路径：接入事务提交后的 {@link OutboxAppended} 信号立即唤醒一次排空（路线 B §13.3 端到端延迟门限），
 * 定时轮询兜底（信号丢失、发布失败后的退避重试）。两条路径共用一把锁，同一时刻只有一个线程排空；
 * 信号在排空期间到达时置脏标记，持锁线程释放前复查，避免“刚查完就有新行”被拖到下一次轮询。</p>
 */
@Component
@ConditionalOnProperty(name = "cyber.ingest.outbox-relay.enabled", havingValue = "true")
public class OutboxRelayScheduler {
    private static final Logger log = LoggerFactory.getLogger(OutboxRelayScheduler.class);
    /** 单次排空的页数上限；超过后交给下一次触发，避免单线程长期占锁。 */
    static final int MAX_PAGES_PER_DRAIN = 64;
    private static final int PAGE_SIZE = OutboxRelay.PAGE_SIZE;

    private final OutboxRelay relay;
    private final ReentrantLock lock = new ReentrantLock();
    private final AtomicBoolean dirty = new AtomicBoolean();
    private final AtomicBoolean scheduled = new AtomicBoolean();
    private final ExecutorService trigger = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "outbox-relay-trigger");
        thread.setDaemon(true);
        return thread;
    });

    public OutboxRelayScheduler(OutboxRelay relay) {
        this.relay = relay;
    }

    @Scheduled(fixedDelayString = "${cyber.ingest.outbox-relay.poll-ms:1000}")
    public void poll() {
        dirty.set(true);
        drain();
    }

    /**
     * 接入事务提交后唤醒 relay。在提交线程上只做入队，不阻塞 HTTP 响应；排队中已有任务时合并。
     * 回滚的事务不会触发（AFTER_COMMIT），没有活动事务时也不触发（兜底由轮询负责）。
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onOutboxAppended(OutboxAppended event) {
        dirty.set(true);
        if (!scheduled.compareAndSet(false, true)) return;
        try {
            trigger.execute(() -> {
                scheduled.set(false);
                drain();
            });
        } catch (RejectedExecutionException shuttingDown) {
            scheduled.set(false);
        }
    }

    /** 排空待发布行；锁被占用时直接返回，脏标记由持锁线程复查。 */
    void drain() {
        while (dirty.get()) {
            if (!lock.tryLock()) return;
            try {
                dirty.set(false);
                for (int page = 0; page < MAX_PAGES_PER_DRAIN; page++) {
                    if (relay.publishPending() < PAGE_SIZE) break;
                }
            } catch (RuntimeException failure) {
                // 事务已回滚，行仍为 pending/failed，由下一次轮询重试；不在此循环重试以免数据库故障时空转。
                log.warn("outbox relay 排空失败，等待下一次轮询: {}", failure.getClass().getSimpleName());
                return;
            } finally {
                lock.unlock();
            }
        }
    }

    /** 测试钩子：在调用线程上同步模拟一次信号，便于确定性地验证锁竞争时的复查。 */
    void drainForTest() {
        dirty.set(true);
        drain();
    }

    @PreDestroy
    void shutdown() {
        trigger.shutdownNow();
    }
}
