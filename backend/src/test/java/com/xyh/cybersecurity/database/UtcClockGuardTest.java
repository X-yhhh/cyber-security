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
 * 取时必须显式指定 {@code ZoneOffset.UTC} 或使用 UTC {@code Clock}。只扫描生产源码。
 * 实时统计契约允许读取服务器时区作为自然日显示边界；它仍用数据库 UTC 时刻取时并转回 UTC 查询，
 * 仅为该构造器的精确语句保留例外，换算边界由 GuardLiveStatsTest 覆盖。</p>
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

    @Test
    void displayZoneExceptionCannotPermitImplicitClocksOrOtherCallSites() {
        Path stats = Path.of("com", "xyh", "cybersecurity", "guard", "GuardLiveStats.java");
        String displayZone = "this(mapper, access, ZoneId.systemDefault());";
        assertThat(displayZoneOnly(stats, displayZone)).isTrue();
        assertThat(displayZoneOnly(Path.of("Other.java"), displayZone)).isFalse();
        assertThat(displayZoneOnly(stats, "LocalDateTime.now();")).isFalse();
        assertThat(displayZoneOnly(stats, displayZone + " LocalDateTime.now();")).isFalse();
        assertThat(DEFAULT_ZONE.matcher("LocalDateTime.now()").find()).isTrue();
        assertThat(DEFAULT_ZONE.matcher("Clock.systemDefaultZone()").find()).isTrue();
    }

    /** 只允许统计构造器读取展示时区，不豁免整个类，也不允许隐式读取当前时间。 */
    private static boolean displayZoneOnly(Path path, String line) {
        return path.endsWith(Path.of("com", "xyh", "cybersecurity", "guard", "GuardLiveStats.java"))
                && line.strip().equals("this(mapper, access, ZoneId.systemDefault());");
    }

    private Stream<String> violations(Path path) {
        try {
            List<String> lines = Files.readAllLines(path);
            return java.util.stream.IntStream.range(0, lines.size())
                    .filter(i -> DEFAULT_ZONE.matcher(lines.get(i)).find())
                    .filter(i -> !displayZoneOnly(path, lines.get(i)))
                    .mapToObj(i -> path.getFileName() + ":" + (i + 1));
        } catch (IOException exception) {
            throw new IllegalStateException("无法读取生产源码: " + path, exception);
        }
    }
}
