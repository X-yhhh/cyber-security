package com.xyh.cybersecurity.ingest.outbox;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** 提交后信号立即唤醒 relay；排空期间到达的信号不丢失；一次排空有页数上限；失败不在循环内空转。 */
class OutboxRelaySchedulerTest {

    @Test
    void commitSignalDrainsWithoutWaitingForPoll() {
        OutboxRelay relay = mock(OutboxRelay.class);
        when(relay.publishPending()).thenReturn(1);
        OutboxRelayScheduler scheduler = new OutboxRelayScheduler(relay);
        try {
            scheduler.onOutboxAppended(new OutboxAppended(7));
            verify(relay, timeout(2000).times(1)).publishPending();
        } finally {
            scheduler.shutdown();
        }
    }

    @Test
    void signalArrivingDuringDrainTriggersAnotherPass() throws Exception {
        OutboxRelay relay = mock(OutboxRelay.class);
        CountDownLatch inFirstPass = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        when(relay.publishPending()).thenAnswer(invocation -> {
            if (calls.incrementAndGet() == 1) {
                inFirstPass.countDown();
                release.await(2, TimeUnit.SECONDS);
            }
            return 0;
        });
        OutboxRelayScheduler scheduler = new OutboxRelayScheduler(relay);
        try {
            Thread poller = new Thread(scheduler::poll);
            poller.start();
            assertThat(inFirstPass.await(2, TimeUnit.SECONDS)).isTrue();
            // 持锁线程正在排空；此时新提交的信号拿不到锁，只能靠脏标记由持锁线程复查。
            scheduler.drainForTest();
            release.countDown();
            poller.join(2000);
            assertThat(calls.get()).isEqualTo(2);
        } finally {
            scheduler.shutdown();
        }
    }

    @Test
    void drainStopsAtPageLimit() {
        OutboxRelay relay = mock(OutboxRelay.class);
        when(relay.publishPending()).thenReturn(OutboxRelay.PAGE_SIZE);
        OutboxRelayScheduler scheduler = new OutboxRelayScheduler(relay);
        try {
            scheduler.poll();
            verify(relay, times(OutboxRelayScheduler.MAX_PAGES_PER_DRAIN)).publishPending();
        } finally {
            scheduler.shutdown();
        }
    }

    @Test
    void failureEndsDrainAndLeavesRetryToPoll() {
        OutboxRelay relay = mock(OutboxRelay.class);
        when(relay.publishPending()).thenThrow(new IllegalStateException("db down"));
        OutboxRelayScheduler scheduler = new OutboxRelayScheduler(relay);
        try {
            scheduler.poll();
            verify(relay, times(1)).publishPending();
        } finally {
            scheduler.shutdown();
        }
    }
}
