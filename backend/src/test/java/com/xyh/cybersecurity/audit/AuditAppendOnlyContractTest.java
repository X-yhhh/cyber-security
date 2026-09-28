package com.xyh.cybersecurity.audit;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/** 防止审计 Mapper 引入更新或删除 SQL，保证业务访问路径只追加并查询审计事实。 */
class AuditAppendOnlyContractTest {

    @Test
    void mapperHasNoAuditMutationMethods() {
        assertThat(AuditMapper.class.getDeclaredMethods())
                .extracting(java.lang.reflect.Method::getName)
                .allMatch(name -> name.startsWith("insert") || name.startsWith("count") || name.startsWith("list"));
    }

    @Test
    void mapperXmlHasNoAuditUpdateOrDeleteStatements() throws IOException {
        try (var input = getClass().getResourceAsStream("/mapper/AuditMapper.xml")) {
            assertThat(input).as("AuditMapper.xml must be on the test classpath").isNotNull();
            String xml = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            Matcher statements = Pattern.compile("(?is)<(update|delete)\\b[^>]*>(.*?)</\\1>").matcher(xml);
            while (statements.find()) {
                assertThat(statements.group(2)).doesNotContain("audit_log");
            }
        }
    }
}
