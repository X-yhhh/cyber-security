package com.xyh.cybersecurity.guard;

import com.xyh.cybersecurity.database.IsolatedDatabaseSchemas;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import java.sql.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

/**
 * L2/B4 的 V25 只追加 guard_lab_run/guard_lab_event 两张表。
 * 覆盖空库迁移到 V25、V24→V25 单步升级；核对 V1—V24 的 Flyway 历史整行（含校验和）、V20 资格列与既有账号不变。
 * 只在随机隔离 schema 内执行，不读取或修改业务库。
 */
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
@ExtendWith(IsolatedDatabaseSchemas.class)
class GuardLabMigrationIntegrationTest {
    static final String SCHEMA=IsolatedDatabaseSchemas.name(GuardLabMigrationIntegrationTest.class,"lab_migration");
    static final String EMPTY=IsolatedDatabaseSchemas.name(GuardLabMigrationIntegrationTest.class,"lab_empty");

    static String url(String schema) {
        return System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","")+"/"+schema+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
    }

    /** 空库一次迁移到 V25：共 25 条成功记录、最新版本为 25，两张 lab 表为空且状态 CHECK 生效。 */
    @Test void emptyDatabaseMigratesToV25() throws Exception {
        String url=url(EMPTY),user=System.getenv("DB_TEST_USERNAME"),dbCredential=System.getenv("DB_TEST_PASSWORD");
        var flyway=Flyway.configure().dataSource(url,user,dbCredential).locations("classpath:db/migration").target("25").load();
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(25);flyway.validate();
        try(var c=DriverManager.getConnection(url,user,dbCredential);var st=c.createStatement()) {
            assertThat(rows(c,"SELECT COUNT(*) FROM flyway_schema_history WHERE success=1")).containsExactly(List.of("25"));
            assertThat(rows(c,"SELECT version FROM flyway_schema_history WHERE success=1 ORDER BY installed_rank DESC LIMIT 1")).containsExactly(List.of("25"));
            assertThat(rows(c,"SELECT script FROM flyway_schema_history WHERE version='25'")).containsExactly(List.of("V25__lab_validation_runtime.sql"));
            assertThat(rows(c,"SELECT COUNT(*) FROM guard_lab_run")).containsExactly(List.of("0"));
            assertThat(rows(c,"SELECT COUNT(*) FROM guard_lab_event")).containsExactly(List.of("0"));
            assertThat(rows(c,"SELECT VERSION()").getFirst().getFirst()).startsWith("8.");
            assertThatThrownBy(()->st.execute("INSERT INTO guard_lab_run(session_id,sensor_id,boot_id,manifest_ref,manifest_sha256,manifest_jcs,scenarios_jcs,mapping_jcs,status) VALUES(999999,999999,UUID(),'fixture',REPEAT('a',64),'{}','{}','{}','applied')"))
                    .isInstanceOf(SQLException.class);
        }
    }

    /** V24→V25 只执行一条迁移；V1—V24 历史整行、V20 资格列与账号整行（含口令哈希）均不变。 */
    @Test void v24ToV25SingleStepPreservesExistingFacts() throws Exception {
        String url=url(SCHEMA),user=System.getenv("DB_TEST_USERNAME"),dbCredential=System.getenv("DB_TEST_PASSWORD");
        Flyway.configure().dataSource(url,user,dbCredential).locations("classpath:db/migration").target("24").load().migrate();
        try(var c=DriverManager.getConnection(url,user,dbCredential);var st=c.createStatement()) {
            st.execute("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES('lab-sentinel','admin','隔离迁移哨兵','synthetic-preserved-hash','active')");
            var history=rows(c,"SELECT * FROM flyway_schema_history ORDER BY installed_rank");
            assertThat(history).hasSize(24);
            var accounts=rows(c,"SELECT * FROM sys_user ORDER BY id");
            var columns=rows(c,"SHOW COLUMNS FROM guard_validation_session");
            var flyway=Flyway.configure().dataSource(url,user,dbCredential).locations("classpath:db/migration").target("25").load();
            assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);flyway.validate();
            assertThat(rows(c,"SELECT * FROM flyway_schema_history WHERE version<>'25' ORDER BY installed_rank")).isEqualTo(history);
            assertThat(rows(c,"SELECT version,success FROM flyway_schema_history WHERE version='25'")).containsExactly(List.of("25","1"));
            assertThat(rows(c,"SELECT * FROM sys_user ORDER BY id")).isEqualTo(accounts);
            assertThat(rows(c,"SELECT password_hash FROM sys_user WHERE user_key='lab-sentinel'")).containsExactly(List.of("synthetic-preserved-hash"));
            assertThat(rows(c,"SHOW COLUMNS FROM guard_validation_session")).isEqualTo(columns);
            assertThat(rows(c,"SELECT COUNT(*) FROM guard_lab_run")).containsExactly(List.of("0"));
            assertThat(rows(c,"SELECT COUNT(*) FROM guard_lab_event")).containsExactly(List.of("0"));
            assertThat(rows(c,"SELECT VERSION()").getFirst().getFirst()).startsWith("8.");
            assertThatThrownBy(()->st.execute("INSERT INTO guard_lab_run(session_id,sensor_id,boot_id,manifest_ref,manifest_sha256,manifest_jcs,scenarios_jcs,mapping_jcs,status) VALUES(999999,999999,UUID(),'fixture',REPEAT('a',64),'{}','{}','{}','applied')"))
                    .isInstanceOf(SQLException.class);
        }
    }

    private static List<List<String>> rows(Connection c,String sql) throws SQLException {
        var rows=new ArrayList<List<String>>();try(var st=c.createStatement();var r=st.executeQuery(sql)) {
            while(r.next()){var row=new ArrayList<String>();for(int i=1;i<=r.getMetaData().getColumnCount();i++)row.add(r.getString(i));rows.add(row);}
        }return rows;
    }
}
