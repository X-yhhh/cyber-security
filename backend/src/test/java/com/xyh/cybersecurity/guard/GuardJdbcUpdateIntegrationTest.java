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

/** 只在本类创建的随机 MySQL 库验证批量更新、NULL、事务回滚及 MyBatis 一级缓存可见性。 */
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
class GuardJdbcUpdateIntegrationTest {
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

    @Test void joinedUpdateSharesTransactionAndInvalidatesCachedReads()throws Exception{
        var dataSource=new DriverManagerDataSource(base()+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true",user(),password());
        var jdbc=new JdbcTemplate(dataSource);
        jdbc.execute("CREATE TABLE guard_episode (id BIGINT UNSIGNED PRIMARY KEY,revision BIGINT NOT NULL,service_port INT NULL,family VARCHAR(96) NOT NULL) ENGINE=InnoDB");
        jdbc.update("INSERT INTO guard_episode(id,revision,service_port,family) VALUES (1,1,80,'one'),(2,1,443,'two'),(3,1,53,'three')");
        var configuration=new Configuration();configuration.addMapper(GuardMapper.class);
        var factory=new SqlSessionFactoryBean();factory.setDataSource(dataSource);factory.setConfiguration(configuration);factory.afterPropertiesSet();
        var sessions=new SqlSessionTemplate(Objects.requireNonNull(factory.getObject()));
        var store=new GuardStore(sessions.getMapper(GuardMapper.class),null,jdbc,sessions);
        var transaction=new TransactionTemplate(new DataSourceTransactionManager(dataSource));

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
}
