package com.xyh.cybersecurity.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.database.IsolatedDatabaseSchemas;
import com.xyh.cybersecurity.guard.GuardMapper;
import jakarta.servlet.http.Cookie;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import java.util.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** 在随机 MySQL schema 通过真实 session/CSRF 覆盖 B1；不启动业务库或防火墙。 */
@SpringBootTest(properties={"cyber.security.local-admin-bootstrap.enabled=false","cyber.ingest.consumer.enabled=false",
        "cyber.ingest.outbox-relay.enabled=false"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
@org.junit.jupiter.api.extension.ExtendWith(IsolatedDatabaseSchemas.class)
class IamIntegrationTest {
    static final String SCHEMA=IsolatedDatabaseSchemas.name(IamIntegrationTest.class,"iam");
    static final String PASSWORD="isolated-iam-password";
    @BeforeAll static void migrate() {
        Flyway.configure().dataSource(url(),System.getenv("DB_TEST_USERNAME"),System.getenv("DB_TEST_PASSWORD")).load().migrate();
    }
    static String url() { return System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","")+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true"; }
    @DynamicPropertySource static void properties(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url",IamIntegrationTest::url);
        r.add("spring.datasource.username",() -> System.getenv("DB_TEST_USERNAME"));
        r.add("spring.datasource.password",() -> System.getenv("DB_TEST_PASSWORD"));
        r.add("spring.flyway.enabled",() -> false);
        r.add("cyber.security.login-throttle.hmac-key",() -> "isolated-iam-test-hmac-at-least-32-bytes");
    }
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder encoder;
    @Autowired GuardMapper guard;
    @Autowired IamMapper mapper;
    static Map<String,IamFixtures.Account> accounts;
    @BeforeEach void fixtures() {
        if(accounts==null) accounts=IamFixtures.seed(jdbc,encoder,PASSWORD);
    }
    record Session(Cookie cookie,String token) { }
    Session login(String username,String password) throws Exception {
        var csrf=mvc.perform(get("/api/v2/auth/csrf")).andReturn();
        JsonNode csrfBody=expect(csrf,200);
        var response=mvc.perform(post("/api/v2/auth/login").cookie(csrf.getResponse().getCookie("SESSION"))
                .header("X-CSRF-TOKEN",csrfBody.path("token").asText()).header("Idempotency-Key",id())
                .contentType("application/json").content(canonical(object("username",username,"password",password)))).andReturn();
        expect(response,200);
        Cookie cookie=response.getResponse().getCookie("SESSION");
        assertThat(cookie).isNotNull();
        JsonNode token=expect(mvc.perform(get("/api/v2/auth/csrf").cookie(cookie)).andReturn(),200);
        return new Session(cookie,token.path("token").asText());
    }
    Session role(String key) throws Exception { return login(accounts.get(key).username(),PASSWORD); }
    MvcResult send(MockHttpServletRequestBuilder request,Session session,JsonNode body,String key,String revision) throws Exception {
        if(session!=null) request.cookie(session.cookie()).header("X-CSRF-TOKEN",session.token());
        if(key!=null) request.header("Idempotency-Key",key);
        if(revision!=null) request.header("If-Match",revision);
        if(body!=null) request.contentType("application/json").content(canonical(body));
        return mvc.perform(request).andReturn();
    }
    JsonNode expect(MvcResult result,int status) throws Exception {
        // 失败信息只包含稳定错误码，防止测试框架打印登录请求或口令。
        JsonNode json=parse(result.getResponse().getContentAsString());
        assertThat(result.getResponse().getStatus()).withFailMessage("expected HTTP %s, actual %s, code=%s",status,
                result.getResponse().getStatus(),json.at("/error/code").asText()).isEqualTo(status);
        assertThat(json.path("requestId").asText()).isNotBlank();
        assertThat(result.getResponse().getHeader("X-Request-Id")).isEqualTo(json.path("requestId").asText());
        return status<400?json.path("data"):json;
    }
    void code(MvcResult result,int status,String code) throws Exception { assertThat(expect(result,status).at("/error/code").asText()).isEqualTo(code); }
    JsonNode create(Session admin,String name) throws Exception {
        return expect(send(post("/api/v2/users"),admin,object("username",name,"displayName",name,"password",PASSWORD),id(),null),201);
    }
    JsonNode binding(Session admin,long user,String role) throws Exception {
        return expect(send(post("/api/v2/users/"+user+"/role-bindings"),admin,
                object("roleKey",role,"scopeType","global","scopeId","*"),id(),null),201);
    }

    /** C1 的公共探针经过真实过滤链；已登录身份也不能重新访问退役人工接口。 */
    @Test void publicProbesRemainAnonymousAndLegacyHumanEndpointsAreClosed() throws Exception {
        for(String path:List.of("/health/live","/health/ready")) {
            assertThat(expect(mvc.perform(get(path)).andReturn(),200).path("status").asText()).isEqualTo("UP");
        }
        code(mvc.perform(get("/api/v1/auth/csrf")).andReturn(),401,"UNAUTHENTICATED");
        Session admin=role("platform_admin");
        for(String path:List.of("/api/v1/auth/csrf","/api/v1/auth/me","/api/v1/health/ready","/api/v1/users")) {
            code(send(get(path),admin,null,null,null),403,"FORBIDDEN");
        }
        code(send(post("/api/v1/auth/login"),admin,object(),id(),null),403,"FORBIDDEN");
    }

    @Test void preservedAdminCanLogInWithV2IamPermission() throws Exception {
        String key="admin-fixture-"+id(),hash=encoder.encode(PASSWORD);
        jdbc.update("INSERT INTO sys_user(user_key,username,display_name,password_hash,status) VALUES(?,'admin','隔离管理员',?,'active')",key,hash);
        long admin=jdbc.queryForObject("SELECT id FROM sys_user WHERE user_key=?",Long.class,key);
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'global','*' FROM sys_role WHERE role_key='platform_admin'",admin);
        Session session=login("admin",PASSWORD);
        assertThat(strings(expect(send(get("/api/v2/auth/me"),session,null,null,null),200).path("permissions"))).contains("iam.manage");
        expect(send(get("/api/v2/users"),session,null,null,null),200);
        assertThat(jdbc.queryForObject("SELECT password_hash FROM sys_user WHERE id=?",String.class,admin)).isEqualTo(hash);
    }

    @Test void sixRoleMatrixAndCombinedAccountHaveOnlyLiveV2Permissions() throws Exception {
        for(var entry:accounts.entrySet()) {
            var session=role(entry.getKey());
            JsonNode me=expect(send(get("/api/v2/auth/me"),session,null,null,null),200);
            Set<String> expected=new HashSet<>();
            entry.getValue().roles().forEach(r -> expected.addAll(IamFixtures.MATRIX.get(r)));
            assertThat(strings(me.path("permissions"))).containsExactlyInAnyOrderElementsOf(expected);
            assertThat(strings(me.path("roles"))).containsExactlyInAnyOrderElementsOf(entry.getValue().roles());
            assertThat(me.has("passwordHash")).isFalse();assertThat(me.has("sessionId")).isFalse();
            assertThat(me.path("bindings").get(0).path("id").asLong()).isPositive();
        }
        var directory=expect(send(get("/api/v2/roles"),role("auditor"),null,null,null),200);
        assertThat(directory.size()).isEqualTo(6);
        for(JsonNode r:directory) assertThat(strings(r.path("permissions")))
                .containsExactlyInAnyOrderElementsOf(IamFixtures.MATRIX.get(r.path("roleKey").asText()));
        code(send(get("/api/v2/roles"),role("security_analyst"),null,null,null),403,"SCOPE_DENIED");
    }

    @Test void createEditResetDisableEnableAndRevokeSessionsAreAuditedAndIdempotent() throws Exception {
        Session admin=role("platform_admin");
        String name="user-"+id(),key=id();
        JsonNode body=object("username",name,"displayName","创建用户","password",PASSWORD);
        JsonNode created=expect(send(post("/api/v2/users"),admin,body,key,null),201);
        assertThat(expect(send(post("/api/v2/users"),admin,body,key,null),201)).isEqualTo(created);
        code(send(post("/api/v2/users"),admin,object("username",name,"displayName","不同内容","password",PASSWORD),key,null),409,"IDEMPOTENCY_CONFLICT");
        long user=created.path("id").asLong();String path="/api/v2/users/"+user;
        code(send(post("/api/v2/users"),admin,body,id(),null),409,"CONFLICT");
        assertThat(expect(send(get(path+"/role-bindings"),admin,null,null,null),200)).isEmpty();
        String patchKey=id();JsonNode patchBody=object("displayName","更新显示名称");
        var renamed=expect(send(patch(path),admin,patchBody,patchKey,"1"),200);
        assertThat(renamed.path("revision").asInt()).isEqualTo(2);
        assertThat(expect(send(patch(path),admin,patchBody,patchKey,"1"),200)).isEqualTo(renamed);
        code(send(patch(path),admin,patchBody,id(),"1"),409,"REVISION_CONFLICT");
        code(send(patch(path),admin,patchBody,id(),null),409,"REVISION_CONFLICT");
        code(send(patch(path),admin,patchBody,patchKey,"2"),409,"IDEMPOTENCY_CONFLICT");
        Session target=login(name,PASSWORD);
        JsonNode disabled=expect(send(post(path+"/status-changes"),admin,object("status","disabled","reason","隔离停用"),id(),"2"),200);
        expect(send(get("/api/v2/auth/me"),target,null,null,null),401);
        expect(send(post(path+"/status-changes"),admin,object("status","active","reason","隔离启用"),id(),disabled.path("revision").asText()),200);
        target=login(name,PASSWORD);
        String temporary="isolated-new-password",resetKey=id();JsonNode resetBody=object("newPassword",temporary,"reason","隔离重置");
        JsonNode reset=expect(send(post(path+"/password-resets"),admin,resetBody,resetKey,null),200);
        expect(send(get("/api/v2/auth/me"),target,null,null,null),401);
        assertThat(expect(send(post(path+"/password-resets"),admin,resetBody,resetKey,null),200)).isEqualTo(reset);
        login(name,temporary);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE resource_id=? AND action LIKE 'iam.user.%'",Integer.class,Long.toString(user))).isEqualTo(5);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log a WHERE a.resource_id=? AND a.action LIKE 'iam.user.%' AND NOT EXISTS(SELECT 1 FROM audit_resource_scope s WHERE s.audit_id=a.id)",Integer.class,Long.toString(user))).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_idempotency WHERE CAST(response_json AS CHAR) LIKE ?",Integer.class,"%"+temporary+"%")).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE reason LIKE ?",Integer.class,"%"+temporary+"%")).isZero();
    }

    @Test void bindingRevocationUsesStableIdChecksConflictsAndInvalidatesSessions() throws Exception {
        Session admin=role("platform_admin");String name="bindings-"+id();
        long user=create(admin,name).path("id").asLong();
        Session target=login(name,PASSWORD);
        JsonNode bind=object("roleKey","platform_admin","scopeType","global","scopeId","*");String key=id();
        JsonNode first=expect(send(post("/api/v2/users/"+user+"/role-bindings"),admin,bind,key,null),201);
        expect(send(get("/api/v2/auth/me"),target,null,null,null),401);
        assertThat(expect(send(post("/api/v2/users/"+user+"/role-bindings"),admin,bind,key,null),201)).isEqualTo(first);
        code(send(post("/api/v2/users/"+user+"/role-bindings"),admin,bind,id(),null),409,"BINDING_EXISTS");
        binding(admin,user,"model_operator");
        JsonNode conflict=object("roleKey","security_reviewer","scopeType","global","scopeId","*");
        code(send(post("/api/v2/users/"+user+"/role-bindings"),admin,conflict,id(),null),409,"ROLE_CONFLICT");
        target=login(name,PASSWORD);
        String revoke="/api/v2/role-bindings/"+first.path("id").asLong()+"/revocations",revokeKey=id();JsonNode reason=object("reason","隔离撤权");
        JsonNode revoked=expect(send(post(revoke),admin,reason,revokeKey,null),200);
        assertThat(expect(send(post(revoke),admin,reason,revokeKey,null),200)).isEqualTo(revoked);
        expect(send(get("/api/v2/auth/me"),target,null,null,null),401);
        code(send(post(revoke),admin,reason,id(),null),404,"RESOURCE_NOT_FOUND");
        assertThat(expect(send(get("/api/v2/users/"+user+"/role-bindings"),admin,null,null,null),200).size()).isEqualTo(1);
    }

    @Test void selfAdministrationIsForbiddenForEveryManagementWrite() throws Exception {
        Session admin=role("platform_admin");long user=accounts.get("platform_admin").id();
        String path="/api/v2/users/"+user;
        code(send(patch(path),admin,object("displayName","本人"),id(),"1"),403,"SELF_ADMINISTRATION_FORBIDDEN");
        code(send(post(path+"/status-changes"),admin,object("status","disabled","reason","本人"),id(),"1"),403,"SELF_ADMINISTRATION_FORBIDDEN");
        code(send(post(path+"/password-resets"),admin,object("newPassword",PASSWORD,"reason","本人"),id(),null),403,"SELF_ADMINISTRATION_FORBIDDEN");
        code(send(post(path+"/role-bindings"),admin,object("roleKey","model_operator","scopeType","global","scopeId","*"),id(),null),403,"SELF_ADMINISTRATION_FORBIDDEN");
        long binding=mapper.bindings(user).getFirst().get("id") instanceof Number n?n.longValue():0;
        code(send(post("/api/v2/role-bindings/"+binding+"/revocations"),admin,object("reason","本人"),id(),null),403,"SELF_ADMINISTRATION_FORBIDDEN");
    }

    @Test void disabledRolesLegacyScopesAndMissingAssetsFailClosed() throws Exception {
        Session admin=role("platform_admin");long user=create(admin,"scope-"+id()).path("id").asLong();
        String route="/api/v2/users/"+user+"/role-bindings";
        code(send(post(route),admin,object("roleKey","asset_source_admin","scopeType","global","scopeId","*"),id(),null),422,"ROLE_DISABLED");
        code(send(post(route),admin,object("roleKey","auditor","scopeType","data_source","scopeId","1"),id(),null),400,"INVALID_SCOPE");
        code(send(post(route),admin,object("roleKey","auditor","scopeType","asset","scopeId","999999999"),id(),null),404,"RESOURCE_NOT_FOUND");
        code(send(post(route),admin,object("roleKey","unknown","scopeType","global","scopeId","*"),id(),null),422,"ROLE_UNKNOWN");
    }

    @Test void assetScopedAdminCannotReadOrMutateGlobalUsersAndScopeIsAudited() throws Exception {
        Session admin=role("platform_admin");String name="asset-admin-"+id();long user=create(admin,name).path("id").asLong();
        String assetKey=id();jdbc.update("INSERT INTO asset(asset_key,asset_type,environment,criticality,status,labels_json) VALUES(?,'host','research','low','active','{}')",assetKey);
        long asset=jdbc.queryForObject("SELECT id FROM asset WHERE asset_key=?",Long.class,assetKey);
        JsonNode bound=expect(send(post("/api/v2/users/"+user+"/role-bindings"),admin,
                object("roleKey","platform_admin","scopeType","asset","scopeId",Long.toString(asset)),id(),null),201);
        Session scoped=login(name,PASSWORD);long target=accounts.get("model_operator").id();
        code(send(get("/api/v2/users"),scoped,null,null,null),403,"SCOPE_DENIED");
        code(send(get("/api/v2/users/"+target),scoped,null,null,null),404,"RESOURCE_NOT_FOUND");
        code(send(patch("/api/v2/users/"+target),scoped,object("displayName","范围外"),id(),"1"),404,"RESOURCE_NOT_FOUND");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log a JOIN audit_resource_scope s ON s.audit_id=a.id WHERE a.action='iam.binding.create' AND a.resource_id=? AND s.scope_type='asset' AND s.scope_id=?",Integer.class,bound.path("id").asText(),Long.toString(asset))).isEqualTo(1);
    }

    @Test void livePermissionQueriesAgreeWithGuardAndIgnoreDisabledFactsAndLegacyScopes() throws Exception {
        var account=IamFixtures.account(jdbc,encoder,PASSWORD,List.of("model_operator"));Session session=login(account.username(),PASSWORD);
        long role=jdbc.queryForObject("SELECT id FROM sys_role WHERE role_key='model_operator'",Long.class);
        try {
            jdbc.update("UPDATE sys_permission SET status='disabled' WHERE permission_key='model.manage'");
            assertThat(guard.permitted(account.id(),"model.manage","global","*")).isFalse();
            assertThat(strings(expect(send(get("/api/v2/auth/me"),session,null,null,null),200).path("permissions"))).doesNotContain("model.manage");
            jdbc.update("UPDATE sys_permission SET status='active' WHERE permission_key='model.manage'");
            jdbc.update("UPDATE sys_role SET status='disabled' WHERE id=?",role);
            assertThat(guard.permitted(account.id(),"model.manage","global","*")).isFalse();
            assertThat(expect(send(get("/api/v2/auth/me"),session,null,null,null),200).path("permissions")).isEmpty();
        } finally { jdbc.update("UPDATE sys_role SET status='active' WHERE id=?",role);jdbc.update("UPDATE sys_permission SET status='active' WHERE permission_key='model.manage'"); }
        jdbc.update("UPDATE sys_user_role SET scope_type='model_registry',scope_id='legacy' WHERE user_id=?",account.id());
        assertThat(guard.permitted(account.id(),"model.manage","global","*")).isFalse();
        JsonNode me=expect(send(get("/api/v2/auth/me"),session,null,null,null),200);
        assertThat(me.path("permissions")).isEmpty();assertThat(me.path("bindings")).isEmpty();
        jdbc.update("UPDATE sys_user SET status='disabled' WHERE id=?",account.id());
        code(send(get("/api/v2/auth/me"),session,null,null,null),401,"UNAUTHENTICATED");
    }

    @Test void cursorBindsCallerAndFiltersAndPrefixEscapesWildcards() throws Exception {
        Session admin=role("platform_admin");String prefix="page-"+id();
        for(int i=0;i<3;i++) create(admin,prefix+i);
        JsonNode first=expect(send(get("/api/v2/users").param("q",prefix).param("status","active").param("limit","2"),admin,null,null,null),200);
        assertThat(first.path("items").size()).isEqualTo(2);String cursor=first.path("nextCursor").asText();
        JsonNode second=expect(send(get("/api/v2/users").param("q",prefix).param("status","active").param("cursor",cursor),admin,null,null,null),200);
        assertThat(second.path("items").size()).isEqualTo(1);assertThat(second.path("nextCursor").isNull()).isTrue();
        code(send(get("/api/v2/users").param("q",prefix+"x").param("status","active").param("cursor",cursor),admin,null,null,null),400,"INVALID_CURSOR");
        code(send(get("/api/v2/users").param("q",prefix).param("status","active").param("cursor",cursor),role("combined"),null,null,null),400,"INVALID_CURSOR");
        assertThat(expect(send(get("/api/v2/users").param("q","%"),admin,null,null,null),200).path("items")).isEmpty();
        code(send(get("/api/v2/users").param("status","bad"),admin,null,null,null),400,"INVALID_QUERY");
        code(send(get("/api/v2/users").param("q","a","b"),admin,null,null,null),400,"INVALID_QUERY");
        code(send(get("/api/v2/users").param("other","x"),admin,null,null,null),400,"INVALID_QUERY");
        code(send(get("/api/v2/users").param("limit","0"),admin,null,null,null),400,"INVALID_PAGE_SIZE");
        expect(send(get("/api/v2/users").param("limit","bad"),admin,null,null,null),400);
    }

    @ParameterizedTest
    @ValueSource(strings={"/users","/users/99999999","/users/99999999/role-bindings","/roles","/auth/me"})
    void unauthenticatedReadsRequireSession(String path) throws Exception { expect(mvc.perform(get("/api/v2"+path)).andReturn(),401); }

    @Test void writesRequireCsrfIdempotencyAndPermissionAndRejectUnknownFields() throws Exception {
        Session admin=role("platform_admin"),analyst=role("security_analyst");
        JsonNode body=object("username","denied-"+id(),"displayName","受拒","password",PASSWORD);
        code(mvc.perform(post("/api/v2/users").cookie(admin.cookie()).header("Idempotency-Key",id()).contentType("application/json").content(canonical(body))).andReturn(),403,"CSRF_INVALID");
        expect(send(post("/api/v2/users"),admin,body,null,null),400);
        code(send(post("/api/v2/users"),analyst,body,id(),null),403,"SCOPE_DENIED");
        ((com.fasterxml.jackson.databind.node.ObjectNode)body).put("admin",true);
        expect(send(post("/api/v2/users"),admin,body,id(),null),400);
        code(send(get("/api/v2/users/99999999"),admin,null,null,null),404,"RESOURCE_NOT_FOUND");
        expect(send(get("/api/v2/users/bad"),admin,null,null,null),400);
        code(send(post("/api/v1/users"),admin,object("username","legacy-"+id(),"displayName","旧接口","password",PASSWORD),id(),null),403,"FORBIDDEN");
    }

    @Test void authPasswordRevokesSessionAndLogoutDoesNotReviveIt() throws Exception {
        var account=IamFixtures.account(jdbc,encoder,PASSWORD,List.of("auditor"));Session user=login(account.username(),PASSWORD);
        String changed="isolated-self-password";
        var denied=send(post("/api/v2/auth/password"),user,object("currentPassword","incorrect-password","newPassword",changed),id(),null);
        code(denied,400,"CURRENT_PASSWORD_INVALID");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log a JOIN audit_resource_scope s ON s.audit_id=a.id WHERE a.request_id=? AND a.action='auth.password.change' AND s.scope_type='global'",Integer.class,denied.getResponse().getHeader("X-Request-Id"))).isEqualTo(1);
        expect(send(post("/api/v2/auth/password"),user,object("currentPassword",PASSWORD,"newPassword","short"),id(),null),400);
        expect(send(post("/api/v2/auth/password"),user,object("currentPassword",PASSWORD,"newPassword",changed),id(),null),200);
        expect(send(get("/api/v2/auth/me"),user,null,null,null),401);
        user=login(account.username(),changed);
        expect(send(post("/api/v2/auth/logout"),user,object(),id(),null),200);
        expect(send(get("/api/v2/auth/me"),user,null,null,null),401);
    }

    @Test void loginRetriesDoNotCreateSessionsOrDuplicateAuditAndFailureThrottlePersists() throws Exception {
        var account=IamFixtures.account(jdbc,encoder,PASSWORD,List.of("auditor"));
        var bootstrap=mvc.perform(get("/api/v2/auth/csrf")).andReturn();
        var csrf=expect(bootstrap,200);Session before=new Session(bootstrap.getResponse().getCookie("SESSION"),csrf.path("token").asText());
        String key=id();JsonNode body=object("username",account.username(),"password",PASSWORD);
        var login=send(post("/api/v2/auth/login"),before,body,key,null);JsonNode first=expect(login,200);
        Session after=new Session(login.getResponse().getCookie("SESSION"),before.token());
        assertThat(expect(send(post("/api/v2/auth/login"),after,body,key,null),200)).isEqualTo(first);
        code(send(post("/api/v2/auth/login"),after,object("username",account.username(),"password","different-password"),key,null),409,"IDEMPOTENCY_CONFLICT");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE actor_id=? AND action='auth.login' AND outcome='success'",Integer.class,Long.toString(account.id()))).isEqualTo(1);
        var anonymous=mvc.perform(get("/api/v2/auth/csrf")).andReturn();Session failed=new Session(anonymous.getResponse().getCookie("SESSION"),expect(anonymous,200).path("token").asText());
        for(int i=0;i<5;i++) code(send(post("/api/v2/auth/login"),failed,object("username",account.username(),"password","wrong-password"),id(),null),401,"AUTHENTICATION_FAILED");
        code(send(post("/api/v2/auth/login"),failed,body,id(),null),429,"LOGIN_RATE_LIMITED");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log a WHERE a.action='auth.login' AND a.outcome='denied' AND EXISTS(SELECT 1 FROM audit_resource_scope s WHERE s.audit_id=a.id)",Integer.class)).isGreaterThanOrEqualTo(6);
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "security_reviewer,platform_admin", "platform_admin,security_reviewer",
            "security_reviewer,security_analyst", "security_analyst,security_reviewer",
            "security_reviewer,model_operator", "model_operator,security_reviewer",
            "evidence_reviewer,security_analyst", "security_analyst,evidence_reviewer",
            "auditor,platform_admin", "auditor,security_reviewer", "auditor,model_operator",
            "auditor,security_analyst", "auditor,evidence_reviewer", "evidence_reviewer,auditor"})
    void roleConflictsApplyAcrossScopesAndInEitherDirection(String existing,String added) throws Exception {
        Session admin=role("platform_admin");
        var user=IamFixtures.account(jdbc,encoder,PASSWORD,List.of(existing));
        String assetKey=id();jdbc.update("INSERT INTO asset(asset_key,asset_type,environment,criticality,status,labels_json) VALUES(?,'host','research','low','active','{}')",assetKey);
        long asset=jdbc.queryForObject("SELECT id FROM asset WHERE asset_key=?",Long.class,assetKey);
        code(send(post("/api/v2/users/"+user.id()+"/role-bindings"),admin,
                object("roleKey",added,"scopeType","asset","scopeId",Long.toString(asset)),id(),null),409,"ROLE_CONFLICT");
    }

    @Test void lastGlobalAdministratorCannotBeDisabledOrRevokedByDelegatedIamPermission() throws Exception {
        // 用隔离的直接权限委托构造保护边界；不扩展正式六角色矩阵。
        var delegate=IamFixtures.account(jdbc,encoder,PASSWORD,List.of("evidence_reviewer"));
        var target=IamFixtures.account(jdbc,encoder,PASSWORD,List.of("platform_admin"));
        long role=jdbc.queryForObject("SELECT id FROM sys_role WHERE role_key='evidence_reviewer'",Long.class);
        long permission=jdbc.queryForObject("SELECT id FROM sys_permission WHERE permission_key='iam.manage'",Long.class);
        List<Long> original=jdbc.queryForList("SELECT DISTINCT u.id FROM sys_user u JOIN sys_user_role ur ON ur.user_id=u.id JOIN sys_role r ON r.id=ur.role_id WHERE u.status='active' AND r.role_key='platform_admin' AND ur.scope_type='global' AND ur.scope_id='*' AND u.id<>?",Long.class,target.id());
        try {
            jdbc.update("INSERT INTO sys_role_permission(role_id,permission_id) VALUES(?,?)",role,permission);
            for(long user:original) jdbc.update("UPDATE sys_user SET status='disabled' WHERE id=?",user);
            Session session=login(delegate.username(),PASSWORD);
            code(send(post("/api/v2/users/"+target.id()+"/status-changes"),session,object("status","disabled","reason","最后管理员"),id(),"1"),409,"LAST_ADMIN_REQUIRED");
            long binding=number(mapper.bindings(target.id()).getFirst(),"id");
            code(send(post("/api/v2/role-bindings/"+binding+"/revocations"),session,object("reason","最后管理员"),id(),null),409,"LAST_ADMIN_REQUIRED");
            assertThat(mapper.user(target.id()).get("status")).isEqualTo("active");
        } finally {
            for(long user:original) jdbc.update("UPDATE sys_user SET status='active' WHERE id=?",user);
            jdbc.update("DELETE FROM sys_role_permission WHERE role_id=? AND permission_id=?",role,permission);
        }
    }

    @Test void concurrentMutualDisablesCannotRemoveEveryAdministrator() throws Exception {
        var left=IamFixtures.account(jdbc,encoder,PASSWORD,List.of("platform_admin"));
        var right=IamFixtures.account(jdbc,encoder,PASSWORD,List.of("platform_admin"));
        var leftSession=login(left.username(),PASSWORD);var rightSession=login(right.username(),PASSWORD);
        var start=new java.util.concurrent.CountDownLatch(1);
        try(var pool=java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var futures=List.of(
                    pool.submit(() -> { start.await();return send(post("/api/v2/users/"+right.id()+"/status-changes"),leftSession,object("status","disabled","reason","并发撤权"),id(),"1").getResponse().getStatus(); }),
                    pool.submit(() -> { start.await();return send(post("/api/v2/users/"+left.id()+"/status-changes"),rightSession,object("status","disabled","reason","并发撤权"),id(),"1").getResponse().getStatus(); }));
            start.countDown();var statuses=new ArrayList<Integer>();
            for(var future:futures) statuses.add(future.get(15,java.util.concurrent.TimeUnit.SECONDS));
            assertThat(statuses).contains(200);assertThat(statuses.stream().filter(s -> s==200).count()).isEqualTo(1);
            assertThat(statuses).allMatch(s -> s==200 || s==401 || s==403);
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sys_user WHERE id IN (?,?) AND status='active'",Integer.class,left.id(),right.id())).isEqualTo(1);
        }
    }

    @Test void everyManagementRouteRejectsUnauthorizedAndOutOfScopeCallers() throws Exception {
        Session analyst=role("security_analyst");
        long user=accounts.get("model_operator").id();String base="/api/v2/users/"+user;
        var bootstrap=mvc.perform(get("/api/v2/auth/csrf")).andReturn();
        Session anonymous=new Session(bootstrap.getResponse().getCookie("SESSION"),expect(bootstrap,200).path("token").asText());
        for(Session denied:List.of(analyst,anonymous)) {
            int status=denied==analyst?403:401;
            expect(send(patch(base),denied,object("displayName","拒绝"),id(),"1"),status);
            expect(send(post(base+"/status-changes"),denied,object("status","disabled","reason","拒绝"),id(),"1"),status);
            expect(send(post(base+"/password-resets"),denied,object("newPassword",PASSWORD,"reason","拒绝"),id(),null),status);
            expect(send(post(base+"/role-bindings"),denied,object("roleKey","auditor","scopeType","global","scopeId","*"),id(),null),status);
            expect(send(post("/api/v2/role-bindings/99999999/revocations"),denied,object("reason","拒绝"),id(),null),status);
        }
    }

    private static List<String> strings(JsonNode node) { List<String> result=new ArrayList<>();node.forEach(n -> result.add(n.asText()));return result; }
}
