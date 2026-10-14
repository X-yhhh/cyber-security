package com.xyh.cybersecurity.database;

import com.xyh.cybersecurity.iam.IamFixtures;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** DB-11 空库与 V26 单步升级证明；仅创建/清理随机隔离 schema，不连接业务 schema。 */
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
@org.junit.jupiter.api.extension.ExtendWith(IsolatedDatabaseSchemas.class)
class ConsoleMigrationIntegrationTest {
    static final String EMPTY=IsolatedDatabaseSchemas.name(ConsoleMigrationIntegrationTest.class,"console_empty");
    static final String UPGRADE=IsolatedDatabaseSchemas.name(ConsoleMigrationIntegrationTest.class,"console_upgrade");
    static final Map<String,Set<String>> ADDED=Map.of(
            "sys_role",Set.of("builtin","revision"),"asset",Set.of("display_name","notes"),
            "sensor_agent",Set.of("display_name","notes"),"guard_executor",Set.of("display_name","notes","updated_at"),
            "guard_dataset",Set.of("display_name","notes","status","revision","updated_at"),
            "guard_model",Set.of("display_name","notes","revision","updated_at"),
            "guard_decision_policy",Set.of("display_name","notes","updated_at"),"guard_release_bundle",Set.of("updated_at"));
    static DriverManagerDataSource source(String schema){return new DriverManagerDataSource(
            System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","")+"/"+schema+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true",
            System.getenv("DB_TEST_USERNAME"),System.getenv("DB_TEST_PASSWORD"));}

    @Test void emptyDatabaseMigratesToLatestWithExactlyTheFrozenBuiltinMatrix(){
        var source=source(EMPTY);var migration=Flyway.configure().dataSource(source).load();
        assertThat(migration.migrate().migrationsExecuted).isEqualTo(27);migration.validate();
        assertBaseline(new JdbcTemplate(source));
    }

    @Test void v26SingleStepAddsOnlyProjectionColumnsAndPreservesAllExistingFields(){
        var source=source(UPGRADE);Flyway.configure().dataSource(source).target("26").load().migrate();
        var jdbc=new JdbcTemplate(source);seed(jdbc);
        List<String> tables=new ArrayList<>(ADDED.keySet());tables.addAll(List.of("sys_user","sys_user_role","sys_permission","sys_role_permission","audit_log","api_client"));
        Map<String,List<Map<String,Object>>> before=new HashMap<>();
        for(String table:tables)before.put(table,jdbc.queryForList("SELECT * FROM "+table));
        var history=jdbc.queryForList("SELECT * FROM flyway_schema_history ORDER BY installed_rank");
        var flyway=Flyway.configure().dataSource(source).load();assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);flyway.validate();
        for(String table:tables){
            var after=jdbc.queryForList("SELECT * FROM "+table);
            after.forEach(row->ADDED.getOrDefault(table,Set.of()).forEach(row::remove));
            assertThat(after).as("V27 不改 %s 原字段",table).isEqualTo(before.get(table));
        }
        assertThat(jdbc.queryForList("SELECT * FROM flyway_schema_history WHERE version<>'27' ORDER BY installed_rank")).isEqualTo(history);
        for(String table:List.of("asset","sensor_agent","guard_executor","guard_dataset","guard_model","guard_decision_policy")){
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM "+table+" WHERE display_name IS NOT NULL OR notes IS NOT NULL",Long.class)).isZero();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name IN ('display_name','notes') AND is_nullable='YES'",Long.class,table)).isEqualTo(2);
        }
        assertThat(jdbc.queryForObject("SELECT status FROM guard_dataset",String.class)).isEqualTo("active");
        assertThat(jdbc.queryForObject("SELECT revision FROM guard_model",Long.class)).isEqualTo(1);
        assertBaseline(jdbc);
    }

    private static void assertBaseline(JdbcTemplate jdbc){
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sys_role WHERE builtin=TRUE AND revision=1",Integer.class)).isEqualTo(9);
        for(var entry:IamFixtures.MATRIX.entrySet())assertThat(jdbc.queryForList(
                "SELECT p.permission_key FROM sys_role r JOIN sys_role_permission rp ON rp.role_id=r.id JOIN sys_permission p ON p.id=rp.permission_id WHERE r.role_key=?",String.class,entry.getKey()))
                .containsExactlyInAnyOrderElementsOf(entry.getValue());
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sys_role WHERE status='active'",Integer.class)).isEqualTo(6);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sys_role_permission rp JOIN sys_role r ON r.id=rp.role_id WHERE r.status='disabled'",Integer.class)).isZero();
    }

    /** 无权重、无遥测的最小冻结事实，确保新增可空列不回填旧资料或改变哈希。 */
    private static void seed(JdbcTemplate j){
        String hash=new BCryptPasswordEncoder(4).encode("isolated-v27-admin-password");
        j.update("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES('admin-fixture','admin','保留管理员',?,'active')",hash);
        long user=j.queryForObject("SELECT id FROM sys_user WHERE username='admin'",Long.class);
        j.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key='platform_admin'",user);
        j.update("INSERT INTO asset(asset_key,asset_type,environment,criticality,owner,status,labels_json) VALUES('v27-fixture','host','lab','medium','fixture','active','{}')");
        long asset=j.queryForObject("SELECT id FROM asset",Long.class);
        j.update("INSERT INTO sensor_agent(agent_key,asset_id,platform,agent_version,capabilities_json,credential_ref,status,registered_at) VALUES('v27-fixture',?,'macos','fixture','[]','test-reference','active',UTC_TIMESTAMP(3))",asset);
        j.update("INSERT INTO api_client(client_key,client_type,secret_ref,scope_json,status) VALUES('v27-executor','executor','test-reference','{}','active')");
        long client=j.queryForObject("SELECT id FROM api_client",Long.class);
        j.update("INSERT INTO guard_executor(public_id,asset_id,api_client_id,platform,adapter_version) VALUES(?,?,?,'macos','fixture')",id(),asset,client);
        j.update("INSERT INTO guard_dataset(public_id,dataset_key,version,manifest_ref,manifest_sha256,payload_json) VALUES(?,'v27-data','1','fixture.json',?,'{}')",id(),"a".repeat(64));
        j.update("INSERT INTO guard_contract(public_id,contract_version,profile_sha256,schema_set_sha256,extractor_sha256,status) VALUES(?,'fixture',?,?,?,'frozen')",id(),"a".repeat(64),"b".repeat(64),"c".repeat(64));
        long contract=j.queryForObject("SELECT id FROM guard_contract",Long.class);
        j.update("INSERT INTO guard_model(public_id,model_key,version,manifest_ref,manifest_sha256,artifact_sha256,contract_id,manifest_json,created_by) VALUES(?,'v27-model','1','fixture.json',?,?,?,'{\"candidateOnly\":true}',?)",id(),"a".repeat(64),"b".repeat(64),contract,user);
        long model=j.queryForObject("SELECT id FROM guard_model",Long.class);
        j.update("INSERT INTO guard_evaluation_plan(public_id,plan_key,version,plan_sha256,payload_json,created_by) VALUES(?,'v27-plan','1',?,'{}',?)",id(),"a".repeat(64),user);
        long plan=j.queryForObject("SELECT id FROM guard_evaluation_plan",Long.class);
        j.update("INSERT INTO guard_decision_policy(public_id,policy_key,version,model_id,plan_id,decision_contract_version,definition_json,definition_sha256,created_by) VALUES(?,'v27-policy','1',?,?,'fixture','{}',?,?)",id(),model,plan,"a".repeat(64),user);
        long policy=j.queryForObject("SELECT id FROM guard_decision_policy",Long.class);
        j.update("INSERT INTO guard_release_bundle(public_id,bundle_key,version,model_id,policy_id,contract_id,plan_id,environment,subject_sha256,subject_json,requested_by) VALUES(?,'v27-bundle','1',?,?,?,?,'lab',?,'{}',?)",id(),model,policy,contract,plan,"a".repeat(64),user);
        j.update("INSERT INTO audit_log(occurred_at,actor_type,actor_id,action,resource_type,resource_id,outcome) VALUES(UTC_TIMESTAMP(3),'human',?,'fixture.preserved','fixture','preserved','success')",Long.toString(user));
    }
}
