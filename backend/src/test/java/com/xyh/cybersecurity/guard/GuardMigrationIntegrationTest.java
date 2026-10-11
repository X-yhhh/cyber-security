package com.xyh.cybersecurity.guard;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.sql.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

/** 在独立 MySQL 8 schema 验证 V20→V24 升级、历史校验和、原账号及既有能力行的保留。 */
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
class GuardMigrationIntegrationTest {
    /** V23/V24 各自单步追加；比较旧迁移整行、全部账号与四条能力，避免升级隐式改写。 */
    @ParameterizedTest @ValueSource(ints={23,24})
    void adjacentMigrationPreservesHistoryAccountsAndExistingCapabilities(int target) throws Exception {
        String schema="cyber_guard_mig_v23_"+UUID.randomUUID().toString().replace("-","");
        String base=System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");
        String user=System.getenv("DB_TEST_USERNAME"),pass=System.getenv("DB_TEST_PASSWORD");
        try {
            try(var c=DriverManager.getConnection(base,user,pass);var st=c.createStatement()){
                st.execute("CREATE DATABASE "+schema+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin");
            }
            String url=base+"/"+schema+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
            Flyway.configure().dataSource(url,user,pass).locations("classpath:db/migration").target(Integer.toString(target-1)).load().migrate();
            try(var c=DriverManager.getConnection(url,user,pass);var st=c.createStatement()){
                st.execute("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES ('v23-preserved','v23-preserved','迁移哨兵','not-a-real-password-hash','active')");
                for(int i=1;i<=4;i++){
                    String scope=i==1?"peer_inbound":"peer_service";
                    String protection=i==1?"REPEAT('a',64)":"NULL",exemption=i==1?"REPEAT('b',64)":"NULL";
                    st.execute("INSERT INTO guard_capability(public_id,capability_key,version,platform,level,payload_json,created_by,scope,protection_set_sha256,exemption_evidence_sha256) SELECT 'b1000000-0000-4000-8000-00000000000"+i+"','v23-preserved-"+i+"','1','macos','lab_auto','{\"sentinel\":"+i+"}',id,'"+scope+"',"+protection+","+exemption+" FROM sys_user WHERE user_key='v23-preserved'");
                }
                var history=snapshot(c,"SELECT * FROM flyway_schema_history ORDER BY installed_rank");
                var accounts=snapshot(c,"SELECT * FROM sys_user ORDER BY id");
                var capabilities=snapshot(c,"SELECT * FROM guard_capability ORDER BY id");
                var flyway=Flyway.configure().dataSource(url,user,pass).locations("classpath:db/migration").target(Integer.toString(target)).load();
                assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);flyway.validate();
                assertThat(snapshot(c,"SELECT * FROM flyway_schema_history WHERE installed_rank<="+(target-1)+" ORDER BY installed_rank")).isEqualTo(history);
                assertThat(snapshot(c,"SELECT * FROM sys_user ORDER BY id")).isEqualTo(accounts);
                assertThat(snapshot(c,"SELECT * FROM guard_capability ORDER BY id")).isEqualTo(capabilities);
                assertThat(snapshot(c,"SELECT version,success FROM flyway_schema_history WHERE version='"+target+"'")).containsExactly(List.of(Integer.toString(target),"1"));
                assertThat(snapshot(c,"SELECT COUNT(*) FROM guard_replay_run")).containsExactly(List.of("0"));
            }
        } finally {
            try(var c=DriverManager.getConnection(base,user,pass);var st=c.createStatement()){st.execute("DROP DATABASE IF EXISTS "+schema);}
        }
    }
    /** 只在随机隔离 schema 内比较原行；测试不读取或修改业务库。 */
    private List<List<String>> snapshot(Connection c,String sql)throws SQLException{
        List<List<String>> rows=new ArrayList<>();
        try(var st=c.createStatement();var r=st.executeQuery(sql)){
            while(r.next()){
                List<String> row=new ArrayList<>();
                for(int i=1;i<=r.getMetaData().getColumnCount();i++)row.add(r.getString(i));
                rows.add(row);
            }
        }
        return rows;
    }
    @Test void migrationPreservesPriorSchemaAndEnforcesGuardConstraints() throws Exception {
        String schema="cyber_guard_mig_p4_"+UUID.randomUUID().toString().replace("-","");
        String base=System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");String user=System.getenv("DB_TEST_USERNAME"),pass=System.getenv("DB_TEST_PASSWORD");
        try {
            try(var c=DriverManager.getConnection(base,user,pass);var st=c.createStatement()){st.execute("CREATE DATABASE "+schema+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin");}
            String url=base+"/"+schema+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
            Flyway.configure().dataSource(url,user,pass).locations("classpath:db/migration").target("20").load().migrate();
            try(var c=DriverManager.getConnection(url,user,pass);var st=c.createStatement()){
                st.execute("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES ('p4-preserved','p4-preserved','迁移哨兵','not-a-real-password-hash','active')");
                st.execute("INSERT INTO guard_capability(public_id,capability_key,version,platform,level,payload_json,created_by) SELECT 'b1000000-0000-4000-8000-000000000001','pre-v22','1','macos','lab_auto','{}',id FROM sys_user WHERE user_key='p4-preserved'");
            }
            // 保留此测试的 V20→V24 历史口径；后续 lab 迁移由 GuardLabMigrationIntegrationTest 独立覆盖。
            var flyway=Flyway.configure().dataSource(url,user,pass).locations("classpath:db/migration").target("24").load();flyway.migrate();flyway.validate();
            try(var c=DriverManager.getConnection(url,user,pass);var st=c.createStatement()){
                try(var r=st.executeQuery("SELECT VERSION()")){r.next();assertThat(r.getString(1)).startsWith("8.");}
                try(var r=st.executeQuery("SELECT password_hash FROM sys_user WHERE user_key='p4-preserved'")){r.next();assertThat(r.getString(1)).isEqualTo("not-a-real-password-hash");}
                try(var r=st.executeQuery("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name LIKE 'guard_%'")){r.next();assertThat(r.getInt(1)).isEqualTo(39);}
                try(var r=st.executeQuery("SELECT COUNT(*) FROM flyway_schema_history WHERE success=1")){r.next();assertThat(r.getInt(1)).isEqualTo(24);}
                // V22 前登记的能力只能是单服务范围，不因迁移获得全入站资格。
                try(var r=st.executeQuery("SELECT scope,protection_set_sha256,exemption_evidence_sha256 FROM guard_capability WHERE capability_key='pre-v22'")){r.next();assertThat(r.getString(1)).isEqualTo("peer_service");assertThat(r.getString(2)).isNull();assertThat(r.getString(3)).isNull();}
                assertThatThrownBy(()->st.execute("UPDATE guard_capability SET scope='peer_inbound' WHERE capability_key='pre-v22'")).hasMessageContaining("ck_guard_capability_scope");
                assertThatThrownBy(()->st.execute("UPDATE guard_capability SET protection_set_sha256=REPEAT('a',64) WHERE capability_key='pre-v22'")).hasMessageContaining("ck_guard_capability_scope");
                assertThatThrownBy(()->st.execute("INSERT INTO guard_target_budget(public_id,budget_target_id,charged_ms,cycle_started_at) VALUES (UUID(),999999,120001,UTC_TIMESTAMP(6))")).isInstanceOf(SQLException.class);
                try(var r=st.executeQuery("SELECT COUNT(*) FROM guard_asset_binding")){r.next();assertThat(r.getInt(1)).isZero();}
            }
        } finally {
            try(var c=DriverManager.getConnection(base,user,pass);var st=c.createStatement()){st.execute("DROP DATABASE IF EXISTS "+schema);}
        }
    }
}
