package com.xyh.cybersecurity.database;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 防止生产代码按 JVM 默认时区取当前时间。
 *
 * <p>数据库时间列统一按 UTC 语义保存，连接会话时区已固定为 UTC；但 {@code LocalDateTime.now()} 等无参调用
 * 取的是 JVM 默认时区，连接参数管不到，在非 UTC 主机上会写入整小时偏差的时间。
 * 取时必须显式指定 {@code ZoneOffset.UTC} 或使用 UTC {@code Clock}。只扫描生产源码。</p>
 */
class UtcClockGuardTest {

    /** 依赖默认时区的取时与时区 API。 */
    private static final Pattern DEFAULT_ZONE = Pattern.compile(
            "\\b(LocalDateTime|LocalDate|LocalTime|OffsetDateTime|ZonedDateTime)\\.now\\(\\s*\\)"
                    + "|ZoneId\\.systemDefault\\(|TimeZone\\.getDefault\\(|Clock\\.systemDefaultZone\\(");

    @Test
    void productionSourcesDoNotReadTimeInTheJvmDefaultZone() throws IOException {
        Path sourceRoot = Path.of(System.getProperty("user.dir"), "src", "main", "java");
        List<String> violations;
        try (Stream<Path> files = Files.walk(sourceRoot)) {
            violations = files.filter(path -> path.toString().endsWith(".java"))
                    .flatMap(this::violations)
                    .toList();
        }
        assertThat(violations).as("按 JVM 默认时区取时的位置").isEmpty();
    }

    private Stream<String> violations(Path path) {
        try {
            List<String> lines = Files.readAllLines(path);
            return java.util.stream.IntStream.range(0, lines.size())
                    .filter(i -> DEFAULT_ZONE.matcher(lines.get(i)).find())
                    .mapToObj(i -> path.getFileName() + ":" + (i + 1));
        } catch (IOException exception) {
            throw new IllegalStateException("无法读取生产源码: " + path, exception);
        }
    }
}
