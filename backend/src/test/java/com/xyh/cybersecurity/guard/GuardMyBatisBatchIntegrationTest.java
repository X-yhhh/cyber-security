package com.xyh.cybersecurity.guard;

import org.apache.ibatis.session.Configuration;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import java.sql.DriverManager;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;

/** 只在本类创建的随机 MySQL 库验证批量键回填、冲突原子性、NULL 和双向事务可见性。 */
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
class GuardMyBatisBatchIntegrationTest {
    static final String SCHEMA="cyber_guard_update_"+UUID.randomUUID().toString().replace("-","");
    static boolean created;
    static String base(){return System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","");}
    static String user(){return System.getenv("DB_TEST_USERNAME");}
    static String password(){return System.getenv("DB_TEST_PASSWORD");}

    @BeforeAll static void createOwnSchema()throws Exception{
        try(var connection=DriverManager.getConnection(base(),user(),password());var statement=connection.createStatement()){
            statement.execute("CREATE DATABASE "+SCHEMA+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin");created=true;
        }
    }
    @AfterAll static void dropOwnSchema()throws Exception{
        if(!created)return;
        try(var connection=DriverManager.getConnection(base(),user(),password());var statement=connection.createStatement()){
            statement.execute("DROP DATABASE "+SCHEMA);
        }
    }

    JdbcTemplate jdbc;
    GuardStore store;
    TransactionTemplate transaction;

    @BeforeEach void prepareMapper()throws Exception{
        var dataSource=new DriverManagerDataSource(base()+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true",user(),password());
        jdbc=new JdbcTemplate(dataSource);
        jdbc.execute("DROP TABLE IF EXISTS guard_episode");
        jdbc.execute("CREATE TABLE guard_episode (id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,public_id VARCHAR(36) UNIQUE,revision BIGINT NOT NULL,service_port INT NULL,family VARCHAR(96) NOT NULL) ENGINE=InnoDB");
        jdbc.update("INSERT INTO guard_episode(id,revision,service_port,family) VALUES (1,1,80,'one'),(2,1,443,'two'),(3,1,53,'three')");
        var configuration=new Configuration();configuration.addMapper(GuardMapper.class);
        var factory=new SqlSessionFactoryBean();factory.setDataSource(dataSource);factory.setConfiguration(configuration);factory.afterPropertiesSet();
        var sessions=new SqlSessionTemplate(Objects.requireNonNull(factory.getObject()));
        store=new GuardStore(sessions.getMapper(GuardMapper.class),null);
        transaction=new TransactionTemplate(new DataSourceTransactionManager(dataSource));
    }

    @Test void joinedUpdateSharesTransactionAndInvalidatesCachedReads(){
        transaction.execute(status->{
            assertThat(number(store.get("guard_episode",1),"revision")).isEqualTo(1L);
            store.updateAll("guard_episode",List.of(map("id",1L,"revision",4L,"service_port",null,"family","中文'quoted"),
                    map("id",2L,"revision",5L,"service_port",8080,"family","second")));
            var changed=store.get("guard_episode",1);
            assertThat(number(changed,"revision")).isEqualTo(4L);
            assertThat(changed.get("service_port")).isNull();
            assertThat(changed.get("family")).isEqualTo("中文'quoted");
            assertThat(number(store.get("guard_episode",2),"service_port")).isEqualTo(8080L);
            assertThat(number(store.get("guard_episode",3),"revision")).isEqualTo(1L);
            // 相同值与未命中行保留旧 UPDATE 的无害语义，不要求驱动返回固定受影响行数。
            store.updateAll("guard_episode",List.of(map("id",2L,"revision",5L),map("id",999L,"revision",2L)));
            status.setRollbackOnly();return null;
        });
        assertThat(jdbc.queryForObject("SELECT revision FROM guard_episode WHERE id=1",Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT service_port FROM guard_episode WHERE id=1",Integer.class)).isEqualTo(80);
        assertThat(jdbc.queryForObject("SELECT revision FROM guard_episode WHERE id=2",Long.class)).isEqualTo(1L);
        assertThatThrownBy(()->store.updateAll("guard_decision",List.of(map("id",1L,"decision","alert"))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Immutable fact");
    }

    @Test void multiRowGeneratedKeysAndSingleWritesShareOneTransaction(){
        transaction.execute(status->{
            var single=store.add("guard_episode",map("revision",1L,"family","single"));
            long singleId=number(single,"id");
            var rows=new ArrayList<Map<String,Object>>();
            for(int i=0;i<501;i++)rows.add(map("revision",2L,"family","batch-"+i));
            store.addAllReturning("guard_episode",rows);
            assertThat(rows.stream().map(r->number(r,"id")).distinct().count()).isEqualTo(501);
            for(var row:rows)assertThat(store.get("guard_episode",number(row,"id")).get("public_id")).isEqualTo(row.get("public_id"));
            store.updateAll("guard_episode",List.of(map("id",singleId,"revision",3L)));
            assertThat(number(store.get("guard_episode",singleId),"revision")).isEqualTo(3L);
            store.update("guard_episode",number(rows.getLast(),"id"),map("revision",4L));
            assertThat(number(store.get("guard_episode",number(rows.getLast(),"id")),"revision")).isEqualTo(4L);
            status.setRollbackOnly();return null;
        });
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_episode",Long.class)).isEqualTo(3L);
    }

    @Test void uniqueConflictInLaterChunkRollsBackEveryEarlierWrite(){
        var rows=new ArrayList<Map<String,Object>>();
        for(int i=0;i<501;i++)rows.add(map("public_id",id(),"revision",2L,"family","conflict-"+i));
        rows.getLast().put("public_id",rows.getFirst().get("public_id"));
        assertThatThrownBy(()->transaction.execute(status->{
            store.update("guard_episode",1L,map("revision",99L));
            store.addAllReturning("guard_episode",rows);return null;
        })).isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_episode",Long.class)).isEqualTo(3L);
        assertThat(number(store.get("guard_episode",1),"revision")).isEqualTo(1L);
    }
}
