package com.xyh.cybersecurity.guard;

import java.util.List;
import java.util.Collections;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.math.BigInteger;
import java.time.LocalDateTime;
import org.junit.jupiter.api.Test;
import static com.xyh.cybersecurity.guard.GuardJson.map;
import static org.assertj.core.api.Assertions.*;

/** 批量 MyBatis 只能使用内部表列白名单，业务字符串始终保留在参数中。 */
class GuardBulkSqlTest {
    private static final org.apache.ibatis.session.Configuration CONFIG=new org.apache.ibatis.session.Configuration();
    static { CONFIG.addMapper(GuardMapper.class); }
    private record BoundPlan(String sql,List<Object> arguments){}
    private static BoundPlan insert(String table,List<Map<String,Object>> rows){return bound("insertAll",GuardMapper.Sql.insertAllPlan(table,rows));}
    private static BoundPlan update(String table,List<Map<String,Object>> rows){return bound("updateAll",GuardMapper.Sql.updateAllPlan(table,rows));}
    /** 检查 mapper 实际 BoundSql 与绑定值，避免只测试未被调用的字符串生成器。 */
    private static BoundPlan bound(String method,GuardMapper.FlatPlan plan){
        var parameters=map("plan",plan);
        var bound=CONFIG.getMappedStatement(GuardMapper.class.getName()+"."+method).getBoundSql(parameters);
        var arguments=new ArrayList<Object>();
        for(var binding:bound.getParameterMappings()){
            String property=binding.getProperty();
            arguments.add(bound.hasAdditionalParameter(property)?bound.getAdditionalParameter(property):CONFIG.newMetaObject(parameters).getValue(property));
        }
        return new BoundPlan(bound.getSql().replaceAll("\\s+"," ").replaceAll("\\s*,\\s*",",").replace("( ","(").replace(" )",")"),arguments);
    }
    @Test void bindsValuesWithoutEmbeddingThemAndKeepsColumnOrder(){
        var rows=List.of(map("asset_id",1L,"status","'unsafe-value'"),map("asset_id",2L,"status","active"));
        var plan=insert("guard_executor",rows);
        assertThat(plan.arguments()).containsExactly(1L,"'unsafe-value'",2L,"active");
        assertThat(plan.sql()).isEqualTo("INSERT INTO guard_executor (`asset_id`,`status`) VALUES (?,?),(?,?)");
        assertThat(plan.sql()).doesNotContain("unsafe-value");
    }
    @Test void rejectsUnknownIdentifiersAndInconsistentRows(){
        assertThatThrownBy(()->insert("guard_executor; SELECT 1",List.of(map("id",1L)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->insert("guard_executor",List.of(map("id) VALUES (1)",1L)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->insert("guard_executor",List.of(map("id",1L),map("status","active")))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->insert("guard_executor",List.of())).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void indexedQueryPreservesPointLookupAndBoundKeyOrder(){
        var key=map("episode_id",7L,"parent_connection_id","parent-value","source","model","rule_id","");
        var plan=bound("indexedKeys",GuardMapper.Sql.indexedKeysPlan("guard_episode_evidence",List.of(key),true));
        assertThat(plan.sql()).contains("FORCE INDEX (uk_guard_episode_parent)","STRAIGHT_JOIN guard_observation").endsWith(" FOR UPDATE").doesNotContain("parent-value");
        assertThat(plan.arguments()).containsExactly(7L,"parent-value","model","");
        assertThatThrownBy(()->GuardMapper.Sql.indexedKeysPlan("guard_episode_evidence",List.of(map("episode_id",7L)),true)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->GuardMapper.Sql.indexedKeysPlan("asset",List.of(key),true)).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void episodePortGroupingBindsFixedColumnsOnceAndKeepsEveryUniqueIndexPredicate(){
        var keys=new ArrayList<Map<String,Object>>();for(int port=100;port<108;port++)keys.add(episodeKey(port));
        var plan=bound("indexedKeys",GuardMapper.Sql.indexedKeysPlan("guard_episode",keys,true));
        assertThat(plan.sql()).contains("CROSS JOIN","STRAIGHT_JOIN guard_episode t FORCE INDEX (uk_guard_episode)")
                .endsWith(" FOR UPDATE").doesNotContain("boot-value","peer-value","dos_flood");
        for(String column:episodeKey(100).keySet())assertThat(plan.sql()).contains("t.`"+column+"`=k.`"+column+"`");
        assertThat(plan.sql()).contains("c.`transport`,p.`service_port_key`,c.`family`");
        var expected=new ArrayList<Object>(List.of(1L,2L,"boot-value","peer-value",3L,"inbound","tcp",
                "dos_flood","peer_service","model","",4L,LocalDateTime.of(2026,10,11,0,0)));
        for(int port=100;port<108;port++)expected.add(port);
        assertThat(plan.arguments()).containsExactlyElementsOf(expected);
        assertThat(plan.sql().chars().filter(c->c=='?').count()).isEqualTo(expected.size());
    }
    @Test void episodePortGroupingNeverCombinesDifferentFixedColumnsOrDropsRepeatedPorts(){
        for(String changed:episodeKey(100).keySet()){
            if(changed.equals("service_port_key"))continue;
            var keys=new ArrayList<Map<String,Object>>();
            for(int group=0;group<2;group++)for(int port=100;port<108;port++){
                var key=episodeKey(port);Object value=key.get(changed);
                if(group==1)key.put(changed,value instanceof Number n?n.longValue()+10:
                        value instanceof LocalDateTime time?time.plusSeconds(30):value+"-other");
                keys.add(key);
            }
            // 重复完整键仍保留同样的 SQL 行数语义；分组仅消除公共绑定值。
            keys.add(new LinkedHashMap<>(keys.getLast()));
            var plan=bound("indexedKeys",GuardMapper.Sql.indexedKeysPlan("guard_episode",keys,false));
            var expected=new ArrayList<Object>();
            for(int group=0;group<2;group++){
                var fixed=keys.get(group*8);fixed.forEach((column,value)->{if(!column.equals("service_port_key"))expected.add(value);});
                for(int port=100;port<108;port++)expected.add(port);
                if(group==1)expected.add(107);
            }
            assertThat(plan.sql()).as(changed).contains("CROSS JOIN").doesNotContain(" FOR UPDATE");
            assertThat(plan.arguments()).as(changed).containsExactlyElementsOf(expected);
            assertThat(plan.sql().chars().filter(c->c=='?').count()).as(changed).isEqualTo(expected.size());
        }
    }
    @Test void consoleListSortsOnlyKeysBeforeJoiningWideRows(){
        var sql=GuardMapper.Sql.consoleList(map("table","guard_decision","where",map("decision","alert"),"actor",1L,"permission","detection.read",
                "filter",map("sort","updatedAt","from",null,"until",null,"prefix",null),"active",false,"beforeId",9L,"beforeTime",LocalDateTime.of(2026,10,1,0,0)));
        String time="t.created_at";
        assertThat(sql).startsWith("SELECT t.*,k.query_sort_time FROM (SELECT t.id,"+time+" query_sort_time FROM guard_decision t WHERE 1=1 AND t.`decision`=#{where.decision}")
                .contains(" AND EXISTS(SELECT 1 FROM sys_user_role ur"," AND ("+time+"<#{beforeTime} OR ("+time+"=#{beforeTime} AND t.id<#{beforeId}))")
                .endsWith(" ORDER BY "+time+" DESC,t.id DESC LIMIT #{limit}) k STRAIGHT_JOIN guard_decision t ON t.id=k.id ORDER BY k.query_sort_time DESC,k.id DESC");
        assertThat(sql.indexOf("t.*")).isEqualTo(sql.lastIndexOf("t.*"));
    }
    @Test void episodePortGroupingFallsBackWhenSharedColumnsDoNotReduceTheQuery(){
        var keys=new ArrayList<Map<String,Object>>();
        for(int i=0;i<20;i++){var key=episodeKey(i);key.put("peer_key","peer-"+i);keys.add(key);}
        var plan=bound("indexedKeys",GuardMapper.Sql.indexedKeysPlan("guard_episode",keys,true));
        assertThat(plan.sql()).doesNotContain("CROSS JOIN").endsWith(" FOR UPDATE");
        assertThat(plan.arguments()).containsExactlyElementsOf(keys.stream().flatMap(k->k.values().stream()).toList());
        // 只有两个键共享公共列时，新增嵌套 SQL 比原键表更长，也应回退。
        keys.getLast().put("peer_key","peer-18");
        plan=bound("indexedKeys",GuardMapper.Sql.indexedKeysPlan("guard_episode",keys,true));
        assertThat(plan.sql()).doesNotContain("CROSS JOIN");
        assertThat(plan.arguments()).containsExactlyElementsOf(keys.stream().flatMap(k->k.values().stream()).toList());
    }
    @Test void episodePortGroupingRejectsIncompleteNullExtraAndOversizedKeys(){
        var key=episodeKey(100);key.remove("bucket_start");
        assertThatThrownBy(()->GuardMapper.Sql.indexedKeysPlan("guard_episode",List.of(key),true)).isInstanceOf(IllegalArgumentException.class);
        var withNull=episodeKey(100);withNull.put("service_port_key",null);
        assertThatThrownBy(()->GuardMapper.Sql.indexedKeysPlan("guard_episode",List.of(withNull),true)).isInstanceOf(IllegalArgumentException.class);
        var withExtra=episodeKey(100);withExtra.put("service_port_key OR 1=1",100);
        assertThatThrownBy(()->GuardMapper.Sql.indexedKeysPlan("guard_episode",List.of(withExtra),true)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->GuardMapper.Sql.indexedKeysPlan("guard_episode",Collections.nCopies(501,episodeKey(100)),true)).isInstanceOf(IllegalArgumentException.class);
    }
    private static Map<String,Object> episodeKey(int port){
        return map("asset_id",1L,"sensor_id",2L,"boot_id","boot-value","peer_key","peer-value","key_epoch",3L,
                "direction","inbound","transport","tcp","service_port_key",port,"family","dos_flood","scope","peer_service",
                "source","model","rule_id","","bundle_id",4L,"bucket_start",LocalDateTime.of(2026,10,11,0,0));
    }
    @Test void joinedUpdateBindsAllValuesAndDrivesPrimaryKeyLookups(){
        var rows=List.of(map("revision",2L,"id",7L,"family","'unsafe-value'"),
                map("revision",3L,"id",9L,"family",null));
        var plan=update("guard_episode",rows);
        assertThat(plan.arguments()).containsExactly(7L,2L,"'unsafe-value'",9L,3L,null);
        assertThat(plan.sql()).isEqualTo("UPDATE (SELECT ? AS `id`,? AS `revision`,? AS `family` UNION ALL SELECT ? AS `id`,? AS `revision`,? AS `family`) k STRAIGHT_JOIN guard_episode t FORCE INDEX (PRIMARY) ON t.`id`=k.`id` SET t.`revision`=k.`revision`,t.`family`=k.`family`");
        assertThat(plan.sql()).doesNotContain("unsafe-value","CASE");
    }
    @Test void joinedUpdateRejectsUnsafeIdentifiersMissingIdsAndDuplicateNumericIds(){
        assertThatThrownBy(()->update("guard_episode; DROP TABLE asset",List.of(map("id",1L,"revision",2L)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->update("guard_episode",List.of(map("id",1L,"revision`=0 --",2L)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->update("guard_episode",List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->update("guard_episode",List.of(map("id",1L)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->update("guard_episode",List.of(map("revision",2L)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->update("guard_episode",List.of(map("id",null,"revision",2L)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->update("guard_episode",List.of(map("id",1L,"revision",2L),map("id",2L,"family","x")))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->update("guard_episode",List.of(map("id",1L,"revision",2L),map("id",BigInteger.ONE,"revision",3L)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->update("guard_episode",Collections.nCopies(501,map("id",1L,"revision",2L)))).isInstanceOf(IllegalArgumentException.class);
    }
}
