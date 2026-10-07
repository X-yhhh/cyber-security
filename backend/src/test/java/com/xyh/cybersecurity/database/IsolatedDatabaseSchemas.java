package com.xyh.cybersecurity.database;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.test.context.TestContextManager;
import org.springframework.test.annotation.DirtiesContext.HierarchyMode;

import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 为每个测试类分配随机 MySQL schema，避免复用历史迁移分支或并行测试的数据。
 * 只清理由本扩展成功创建的库；创建冲突或迁移失败均不会 repair、覆盖或删除已有库。
 */
public final class IsolatedDatabaseSchemas implements BeforeAllCallback, AfterAllCallback {
    private static final Map<Class<?>, List<String>> REQUESTED = new ConcurrentHashMap<>();
    private static final Map<Class<?>, List<String>> CREATED = new ConcurrentHashMap<>();

    /** 仅分配标识，不连接数据库；未启用数据库测试时不会创建 schema。 */
    public static String name(Class<?> owner, String purpose) {
        if (!purpose.matches("[a-z0-9_]{1,20}")) {
            throw new IllegalArgumentException("隔离库用途只能包含小写字母、数字和下划线，长度不超过20");
        }
        String name = "cyber_it_" + purpose + "_" + UUID.randomUUID().toString().replace("-", "");
        REQUESTED.computeIfAbsent(owner, ignored -> new ArrayList<>()).add(name);
        return name;
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        Class<?> owner = context.getRequiredTestClass();
        Class.forName(owner.getName(), true, owner.getClassLoader());
        try (var connection = DriverManager.getConnection(required("DB_TEST_BASE_URL"),
                required("DB_TEST_USERNAME"), required("DB_TEST_PASSWORD"));
             var statement = connection.createStatement()) {
            for (String schema : REQUESTED.getOrDefault(owner, List.of())) {
                statement.execute("CREATE DATABASE `" + schema
                        + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci");
                CREATED.computeIfAbsent(owner, ignored -> new ArrayList<>()).add(schema);
            }
        }
    }

    @Override
    public void afterAll(ExtensionContext context) throws Exception {
        // 先关闭缓存的 Spring 上下文及连接池/定时任务，避免删库后仍访问该库。
        var testContext = new TestContextManager(context.getRequiredTestClass()).getTestContext();
        if (testContext.hasApplicationContext()) {
            testContext.markApplicationContextDirty(HierarchyMode.EXHAUSTIVE);
        }
        List<String> owned = CREATED.remove(context.getRequiredTestClass());
        if (owned == null || owned.isEmpty()) return;
        try (var connection = DriverManager.getConnection(required("DB_TEST_BASE_URL"),
                required("DB_TEST_USERNAME"), required("DB_TEST_PASSWORD"));
             var statement = connection.createStatement()) {
            for (String schema : owned) {
                statement.execute("DROP DATABASE `" + schema + "`");
            }
        }
    }

    private static String required(String key) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) throw new IllegalStateException("缺少数据库测试环境变量：" + key);
        return value;
    }
}
