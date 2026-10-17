package com.xyh.cybersecurity.ingest;

import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * 后端就绪后托管已登记的本机传感器，退出时先停止采集。唯一文件锁防止开发/部署进程重复打开网卡；
 * 崩溃重试使用新 boot/spool，失败通过健康状态显式呈现，不获得授权、审批或防火墙权限。
 */
@Component
@ConditionalOnProperty(name = "cyber.sensor.enabled", havingValue = "true")
public class ManagedSensorLifecycle implements HealthIndicator {
    private static final Logger LOG = LoggerFactory.getLogger(ManagedSensorLifecycle.class);
    private final Path root;
    private final Path release;
    private final Path python;
    private final int port;
    private final ScheduledExecutorService supervisor = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().daemon().name("managed-sensor").factory());
    private Process child;
    private FileChannel channel;
    private FileLock lock;
    private boolean stopping;
    private String state = "waiting_for_backend";
    private long retryAfter;

    public ManagedSensorLifecycle(@Value("${cyber.sensor.root}") Path root,
            @Value("${cyber.sensor.release}") Path release,
            @Value("${cyber.sensor.python}") Path python,
            @Value("${local.server.port:${server.port:18080}}") int port) {
        this.root = root.toAbsolutePath().normalize();
        this.release = release.toAbsolutePath().normalize();
        this.python = python.toAbsolutePath().normalize();
        this.port = port;
    }

    /** 监听器已经就绪才允许机器上报；启动过程不调用 shell，也不从配置生成审批。 */
    @EventListener(ApplicationReadyEvent.class)
    public void ready() {
        supervisor.scheduleWithFixedDelay(this::supervise, 0, 5, TimeUnit.SECONDS);
    }

    synchronized void supervise() {
        if (stopping || (child != null && child.isAlive()) || System.nanoTime() < retryAfter) return;
        try {
            if (lock == null) {
                Path ledger = root.resolve("ledger");
                if (!Files.isDirectory(ledger)) throw new IOException("SENSOR_ROOT_NOT_PROVISIONED");
                channel = FileChannel.open(ledger.resolve("sensor.backend.lock"),
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                Files.setPosixFilePermissions(ledger.resolve("sensor.backend.lock"),
                        PosixFilePermissions.fromString("rw-------"));
                try {
                    lock = channel.tryLock();
                } catch (OverlappingFileLockException busy) {
                    // 同一 JVM 的测试/重复上下文与跨进程占用采用相同等待语义。
                    lock = null;
                }
                if (lock == null) {
                    channel.close(); channel = null;
                    state = "owned_by_another_backend";
                    return;
                }
                Path marker = ledger.resolve("sensor.backend.pid");
                Path temporary = Files.createTempFile(ledger, ".sensor-parent-", ".tmp");
                Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-------"));
                Files.writeString(temporary, ProcessHandle.current().pid() + "\n");
                Files.move(temporary, marker, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            }
            Path stdout = root.resolve("logs/sensor.stdout.log");
            Path stderr = root.resolve("logs/sensor.stderr.log");
            for (Path log : List.of(stdout, stderr)) {
                if (!Files.exists(log)) Files.createFile(log);
                Files.setPosixFilePermissions(log, PosixFilePermissions.fromString("rw-------"));
            }
            child = new ProcessBuilder(command()).directory(release.toFile())
                    .redirectOutput(ProcessBuilder.Redirect.appendTo(stdout.toFile()))
                    .redirectError(ProcessBuilder.Redirect.appendTo(stderr.toFile())).start();
            state = "running";
            retryAfter = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            LOG.info("本机传感器已启动，pid={}，随当前后端停止", child.pid());
        } catch (IOException failure) {
            if (lock == null && channel != null) {
                try { channel.close(); } catch (IOException ignored) { /* 下一次启动重新申请锁。 */ }
                channel = null;
            }
            state = "start_failed";
            retryAfter = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
            LOG.error("本机传感器启动失败；检查受控配置、身份与 BPF 权限");
        }
    }

    List<String> command() {
        return List.of(python.toString(), release.resolve("scripts/p8/sensor_service.py").toString(),
                "--root", root.toString(), "--release", release.toString(),
                "--parent-pid", Long.toString(ProcessHandle.current().pid()),
                "--backend-url", "https://127.0.0.1:" + port);
    }

    /** 这里只报告进程存活；连续采集质量仍以 v2 capture-health 的服务端判定为准。 */
    @Override public synchronized Health health() {
        boolean alive = child != null && child.isAlive();
        var result = alive ? Health.up() : "owned_by_another_backend".equals(state) ? Health.unknown() : Health.down();
        return result.withDetail("state", alive ? "running" : child != null ? "process_exited" : state)
                .withDetail("captureHealth", "see_v2_sensor_health")
                .withDetail("pid", alive ? child.pid() : 0).build();
    }

    /** 先发 SIGTERM 封口，最多等 8 秒；强制结束后未确认 spool 保留供核对和续传。 */
    @PreDestroy public synchronized void close() {
        stopping = true;
        supervisor.shutdownNow();
        if (child != null && child.isAlive()) {
            child.destroy();
            try {
                if (!child.waitFor(8, TimeUnit.SECONDS)) {
                    child.destroyForcibly();
                    child.waitFor(2, TimeUnit.SECONDS);
                }
            } catch (InterruptedException interrupted) {
                child.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
        try {
            if (lock != null && lock.isValid()) {
                Files.deleteIfExists(root.resolve("ledger/sensor.backend.pid"));
                lock.release();
            }
            if (channel != null) channel.close();
        } catch (IOException failure) {
            LOG.warn("传感器所有权锁关闭失败");
        }
        state = "stopped";
    }
}
