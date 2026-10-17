package com.xyh.cybersecurity.ingest;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.assertThat;

/** 真实替身子进程验证唯一所有权与退出；不打开网卡、不连接业务库或系统服务。 */
class ManagedSensorLifecycleTest {
    @TempDir Path root;

    ManagedSensorLifecycle fixture() throws Exception {
        Files.createDirectories(root.resolve("ledger"));
        Files.createDirectories(root.resolve("logs"));
        Path scripts = Files.createDirectories(root.resolve("scripts/p8"));
        Files.writeString(scripts.resolve("sensor_service.py"), "exec /bin/sleep 60\n");
        return new ManagedSensorLifecycle(root, root, Path.of("/bin/sh"), 18082);
    }

    @Test void startsSingleChildAndStopsItBeforeReleasingOwnership() throws Exception {
        var owner = fixture();
        var other = fixture();
        long pid;
        try {
            owner.supervise();
            pid = ((Number) owner.health().getDetails().get("pid")).longValue();
            assertThat(ProcessHandle.of(pid)).isPresent();
            assertThat(Files.readString(root.resolve("ledger/sensor.backend.pid")).trim())
                    .isEqualTo(Long.toString(ProcessHandle.current().pid()));
            other.supervise();
            assertThat(other.health().getStatus().getCode()).isEqualTo("UNKNOWN");
            assertThat(owner.command()).contains("--parent-pid", Long.toString(ProcessHandle.current().pid()),
                    "--backend-url", "https://127.0.0.1:18082");
            owner.close();
            assertThat(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)).isFalse();
            assertThat(root.resolve("ledger/sensor.backend.pid")).doesNotExist();
            other.supervise();
            assertThat(other.health().getStatus().getCode()).isEqualTo("UP");
        } finally {
            owner.close();
            other.close();
        }
    }

    @Test void missingProvisionedRootDoesNotCreateCaptureOrReportHealthy() {
        var sensor = new ManagedSensorLifecycle(root.resolve("missing"), root, Path.of("/bin/sh"), 18082);
        try {
            sensor.supervise();
            assertThat(sensor.health().getStatus().getCode()).isEqualTo("DOWN");
            assertThat(root.resolve("missing")).doesNotExist();
        } finally { sensor.close(); }
    }
}
