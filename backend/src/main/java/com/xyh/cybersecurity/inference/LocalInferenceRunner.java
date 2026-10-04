package com.xyh.cybersecurity.inference;

import com.xyh.cybersecurity.model.runtime.OnnxModelManager;
import com.xyh.cybersecurity.model.runtime.OnnxModelRuntime;
import com.xyh.cybersecurity.model.validation.ModelContractException;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 在有界工作线程池中执行一次批量推理，并施加单批超时（路线 B §10.1 第 3、4 项）。
 *
 * <p>推理在 {@link OnnxModelManager#runOnActive} 的读锁内运行：超时后调用方不再等待，但工作线程仍持锁直到
 * ONNX 调用返回，因此版本切换不会关闭仍在使用的会话。线程池和队列都有上限，队列满时整批按
 * {@code INFERENCE_CAPACITY_EXHAUSTED} 回滚重试，不无限堆积超时任务。</p>
 */
@Component
public class LocalInferenceRunner implements DisposableBean {
    /** 判定后激活版本变化：整批重来，不能把新旧版本的结果写进同一批次。 */
    private static final Set<String> RETRYABLE_CODES = Set.of("ACTIVE_MODEL_CHANGED", "ACTIVE_MODEL_UNAVAILABLE");

    private final OnnxModelManager models;
    private final ThreadPoolExecutor executor;
    private final long timeoutMillis;

    public LocalInferenceRunner(OnnxModelManager models,
                                @Value("${cyber.inference.local.batch-timeout-ms:2000}") long timeoutMillis,
                                @Value("${cyber.inference.local.workers:2}") int workers,
                                @Value("${cyber.inference.local.queue-capacity:16}") int queueCapacity) {
        if (timeoutMillis < 1 || timeoutMillis > 60_000 || workers < 1 || workers > 64
                || queueCapacity < 1 || queueCapacity > 1024) {
            throw new IllegalArgumentException("cyber.inference.local 超时、线程数或队列容量超出允许范围");
        }
        this.models = models;
        this.timeoutMillis = timeoutMillis;
        AtomicInteger counter = new AtomicInteger();
        this.executor = new ThreadPoolExecutor(workers, workers, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity), runnable -> {
                    Thread thread = new Thread(runnable, "inference-worker-" + counter.incrementAndGet());
                    thread.setDaemon(true);
                    return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
    }

    /**
     * @param modelId 门禁判定时看到的激活版本；执行时版本已变化则整批重试
     * @throws InferenceUnavailableException 容量耗尽、版本切换或调用线程被中断
     */
    Outcome run(long modelId, List<OnnxModelRuntime.FlowInput> inputs) {
        long started = System.nanoTime();
        Future<List<OnnxModelRuntime.Prediction>> future;
        try {
            future = executor.submit(() -> models.runOnActive(modelId, runtime -> runtime.predict(inputs)));
        } catch (RejectedExecutionException exception) {
            throw new InferenceUnavailableException("INFERENCE_CAPACITY_EXHAUSTED", exception);
        }
        try {
            return new Outcome(Kind.SUCCEEDED, future.get(timeoutMillis, TimeUnit.MILLISECONDS), null, elapsed(started));
        } catch (TimeoutException exception) {
            future.cancel(true);
            return new Outcome(Kind.TIMED_OUT, List.of(), "INFERENCE_TIMEOUT", elapsed(started));
        } catch (InterruptedException exception) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new InferenceUnavailableException("INFERENCE_INTERRUPTED", exception);
        } catch (ExecutionException exception) {
            if (exception.getCause() instanceof ModelContractException contract) {
                if (RETRYABLE_CODES.contains(contract.code())) throw new InferenceUnavailableException(contract.code(), contract);
                return new Outcome(Kind.FAILED, List.of(), contract.code(), elapsed(started));
            }
            // OrtException 等运行时故障：不回显原因（可能含路径），只记稳定错误码。
            return new Outcome(Kind.FAILED, List.of(), "MODEL_RUNTIME_FAILED", elapsed(started));
        }
    }

    private static long elapsed(long startedNanos) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos);
    }

    @Override public void destroy() { executor.shutdownNow(); }

    enum Kind { SUCCEEDED, TIMED_OUT, FAILED }

    /** @param errorCode 仅 {@code TIMED_OUT}/{@code FAILED} 时非空 */
    record Outcome(Kind kind, List<OnnxModelRuntime.Prediction> predictions, String errorCode, long latencyMs) { }
}
