package com.xyh.cybersecurity.database;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 防止业务持久化边界回退到直接 JDBC；Spring Session JDBC 仍由框架内部负责，
 * 本检查只扫描生产源码，不扫描测试夹具。
 */
class MyBatisMigrationGuardTest {

    @Test
    void productionSourcesDoNotUseDirectJdbcApis() throws IOException {
        Path sourceRoot = Path.of(System.getProperty("user.dir"), "src", "main", "java");
        String source = Files.walk(sourceRoot)
                .filter(path -> path.toString().endsWith(".java"))
                .map(this::read)
                .collect(Collectors.joining("\n"));

        assertThat(source)
                .doesNotContain("JdbcTemplate")
                .doesNotContain("NamedParameterJdbcTemplate")
                .doesNotContain("JdbcClient")
                .doesNotContain("DriverManager")
                .doesNotContain("java.sql.");
    }

    private String read(Path path) {
        try {
            return Files.readString(path);
        } catch (IOException exception) {
            throw new IllegalStateException("无法读取生产源码: " + path, exception);
        }
    }
}
