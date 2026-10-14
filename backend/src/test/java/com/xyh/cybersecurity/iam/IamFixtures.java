package com.xyh.cybersecurity.iam;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.*;

/** B1/B2/T1 共享的隔离库角色夹具：拒绝业务库，仅生成六个单角色与一个合法组合账号。 */
public final class IamFixtures {
    public static final Map<String,Set<String>> MATRIX=Map.of(
            "platform_admin",Set.of("resource.read","authorization.request","asset.manage","sensor.manage","audit.read","ops.read","iam.manage"),
            "security_analyst",Set.of("resource.read","detection.read","event.manage","feedback.label","action.read","action.request"),
            "security_reviewer",Set.of("resource.read","detection.read","action.read","action.revoke","automation.stop","authorization.approve","evaluation.read","policy.approve","bundle.approve","ops.read"),
            "model_operator",Set.of("resource.read","dataset.manage","model.manage","model.validate","evaluation.read","evaluation.run","policy.draft","bundle.request"),
            "evidence_reviewer",Set.of("resource.read","detection.read","feedback.review","evaluation.read"),
            "auditor",Set.of("resource.read","detection.read","action.read","evaluation.read","audit.read","ops.read"));

    private IamFixtures() { }
    public record Account(long id,String username,List<String> roles) { }

    /** 口令由测试调用方注入，不写入夹具产物；返回值只含用户名、用户 ID 和角色。 */
    public static Map<String,Account> seed(JdbcTemplate jdbc,PasswordEncoder encoder,String password) {
        assertIsolated(jdbc);
        Map<String,Account> result=new LinkedHashMap<>();
        for(String role:new TreeSet<>(MATRIX.keySet())) result.put(role,account(jdbc,encoder,password,List.of(role)));
        result.put("combined",account(jdbc,encoder,password,List.of("platform_admin","model_operator")));
        return result;
    }

    public static Account account(JdbcTemplate jdbc,PasswordEncoder encoder,String password,List<String> roles) {
        assertIsolated(jdbc);
        String key=UUID.randomUUID().toString(),name="iam-"+key;
        jdbc.update("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES(?,?,?,?, 'active')",
                key,name,"隔离角色夹具",encoder.encode(password));
        long id=jdbc.queryForObject("SELECT id FROM sys_user WHERE user_key=?",Long.class,key);
        for(String role:roles) jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key=?",id,role);
        return new Account(id,name,roles);
    }

    private static void assertIsolated(JdbcTemplate jdbc) {
        String schema=jdbc.queryForObject("SELECT DATABASE()",String.class);
        if(schema==null || !schema.matches("cyber_it_[a-z0-9_]+_[0-9a-f]{32}"))
            throw new IllegalStateException("角色夹具只允许写入本次随机隔离 schema");
    }
}
