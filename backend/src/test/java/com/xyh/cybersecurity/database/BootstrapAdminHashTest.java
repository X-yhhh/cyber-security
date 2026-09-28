package com.xyh.cybersecurity.database;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** 校验版本化初始化脚本中的本机账号仍可用 admin/admin 登录；既存数据库不会被该测试修改。 */
class BootstrapAdminHashTest {

    private static final Pattern ADMIN_HASH = Pattern.compile(
            "'(?<hash>\\$2[aby]\\$\\d{2}\\$[./A-Za-z0-9]{53})'\\s*\\n?\\s*\\)\\s*\\n?\\s*ON DUPLICATE KEY UPDATE",
            Pattern.MULTILINE);

    @Test
    void initScriptAdminHashMatchesBootstrapPassword() throws IOException {
        String sql = Files.readString(findInitScript());
        Matcher matcher = ADMIN_HASH.matcher(sql);

        assertThat(matcher.find()).as("database/init.sql must contain one bootstrap admin hash").isTrue();
        assertThat(matcher.group("hash")).matches("\\$2[aby]\\$12\\$[./A-Za-z0-9]{53}");
        assertThat(new BCryptPasswordEncoder(12).matches("admin", matcher.group("hash"))).isTrue();
    }

    private static Path findInitScript() {
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        for (int i = 0; i < 6 && current != null; i++, current = current.getParent()) {
            Path candidate = current.resolve("database/init.sql");
            if (Files.isRegularFile(candidate)) return candidate;
        }
        throw new IllegalStateException("database/init.sql not found from " + Path.of(System.getProperty("user.dir")));
    }
}
