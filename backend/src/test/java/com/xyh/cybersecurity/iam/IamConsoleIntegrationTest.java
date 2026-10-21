package com.xyh.cybersecurity.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.xyh.cybersecurity.database.IsolatedDatabaseSchemas;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import java.util.*;
import java.util.concurrent.*;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.iam.ConsoleHttpTestSupport.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** B4 身份验收只写入本次随机 schema：角色、用户、冲突、撤会话、幂等和审计均走真实 HTTP。 */
@SpringBootTest(properties={"cyber.security.local-admin-bootstrap.enabled=false","cyber.ingest.consumer.enabled=false",
        "cyber.ingest.outbox-relay.enabled=false"})
@AutoConfigureMockMvc(print=MockMvcPrint.NONE)
@EnabledIfEnvironmentVariable(named="DB_TEST_BASE_URL",matches=".+")
@org.junit.jupiter.api.extension.ExtendWith(IsolatedDatabaseSchemas.class)
class IamConsoleIntegrationTest {
    static final String SCHEMA=IsolatedDatabaseSchemas.name(IamConsoleIntegrationTest.class,"console_iam");
    static final String FIXTURE_LOGIN="isolated-console-password";
    static String url(){return System.getenv("DB_TEST_BASE_URL").replaceAll("/+$","")+"/"+SCHEMA+"?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";}
    @BeforeAll static void migrate(){Flyway.configure().dataSource(url(),System.getenv("DB_TEST_USERNAME"),System.getenv("DB_TEST_PASSWORD")).load().migrate();}
    @DynamicPropertySource static void properties(DynamicPropertyRegistry r){
        r.add("spring.datasource.url",IamConsoleIntegrationTest::url);r.add("spring.datasource.username",()->System.getenv("DB_TEST_USERNAME"));
        r.add("spring.datasource.password",()->System.getenv("DB_TEST_PASSWORD"));r.add("spring.flyway.enabled",()->false);
        r.add("cyber.security.login-throttle.hmac-key",()->"isolated-console-hmac-key-at-least-32-bytes");
    }
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder encoder;
    @Autowired IamMapper mapper;
    static Map<String,IamFixtures.Account> accounts;
    @BeforeEach void seed(){if(accounts==null)accounts=IamFixtures.seed(jdbc,encoder,FIXTURE_LOGIN);}
    @AfterEach void clearCustomRoles(){
        jdbc.update("DELETE ur FROM sys_user_role ur JOIN sys_role r ON r.id=ur.role_id WHERE r.builtin=FALSE");
        jdbc.update("DELETE rp FROM sys_role_permission rp JOIN sys_role r ON r.id=rp.role_id WHERE r.builtin=FALSE");
        jdbc.update("DELETE FROM sys_role WHERE builtin=FALSE");
    }
    Session role(String role) throws Exception{return login(mvc,accounts.get(role).username(),FIXTURE_LOGIN);}
    JsonNode custom(Session admin,String key,List<String> permissions) throws Exception {
        return expect(send(mvc,post("/api/v2/roles"),admin,
                object("roleKey",key,"name","隔离自定义角色","description","仅用于 B4 验收","permissions",permissions),id(),null),201);
    }
    String key(){return "custom_"+id().replace("-","");}
    JsonNode bind(Session admin,long user,String role) throws Exception {
        return expect(send(mvc,post("/api/v2/users/"+user+"/role-bindings"),admin,
                object("roleKey",role,"scopeType","global","scopeId","*"),id(),null),201);
    }

    @ParameterizedTest
    @CsvSource({"authorization.request,authorization.approve","sensor.manage,authorization.approve",
            "policy.draft,policy.approve","bundle.request,bundle.approve","action.request,authorization.approve",
            "feedback.label,feedback.review","evaluation.run,authorization.approve"})
    void allSevenPermissionPairsRejectBothRoleAndUserUnion(String request,String approve) throws Exception {
        Session admin=role("platform_admin");String a=key(),b=key();
        code(send(mvc,post("/api/v2/roles"),admin,object("roleKey",a,"name","冲突角色","description","职责分离负例",
                "permissions",List.of(request,approve)),id(),null),422,"PERMISSION_CONFLICT");
        assertThat(mapper.role(a)).isNull();
        custom(admin,a,List.of(request));custom(admin,b,List.of(approve));
        var user=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());bind(admin,user.id(),a);
        code(send(mvc,post("/api/v2/users/"+user.id()+"/role-bindings"),admin,
                object("roleKey",b,"scopeType","global","scopeId","*"),id(),null),409,"ROLE_CONFLICT");
        assertThat(mapper.bindings(user.id())).hasSize(1);
    }

    @Test void directorySlotLimitDisabledRolesAndPermissionsStayWithinBaseline() throws Exception {
        Session admin=role("platform_admin");
        JsonNode permissions=expect(send(mvc,get("/api/v2/permissions"),admin,null,null,null),200);
        assertThat(permissions.size()).isEqualTo(25);
        Set<String> actual=new HashSet<>();permissions.forEach(p->{actual.add(p.path("permissionKey").asText());assertThat(p.path("description").asText()).isNotBlank();});
        assertThat(actual).isEqualTo(IamPermissionRules.HUMAN);
        String a=key(),b=key(),c=key();String createKey=id();JsonNode body=object("roleKey",a,"name","角色一","description","角色说明","permissions",List.of("resource.read"));
        JsonNode first=expect(send(mvc,post("/api/v2/roles"),admin,body,createKey,null),201);
        assertThat(first.path("builtin").asBoolean()).isFalse();assertThat(first.path("revision").asLong()).isEqualTo(1);
        assertThat(expect(send(mvc,post("/api/v2/roles"),admin,body,createKey,null),201)).isEqualTo(first);
        custom(admin,b,List.of("detection.read"));
        code(send(mvc,post("/api/v2/roles"),admin,object("roleKey",c,"name","角色三","description","超上限","permissions",List.of()),id(),null),409,"ROLE_LIMIT_REACHED");
        String statusKey=id();JsonNode statusBody=object("status","disabled","reason","释放名额");
        JsonNode stopped=expect(send(mvc,post("/api/v2/roles/"+a+"/status-changes"),admin,statusBody,statusKey,"1"),200);
        assertThat(expect(send(mvc,post("/api/v2/roles/"+a+"/status-changes"),admin,statusBody,statusKey,"1"),200)).isEqualTo(stopped);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM audit_log WHERE resource_id=? AND action='iam.role.disabled'",Long.class,a)).isEqualTo(1);
        custom(admin,c,List.of("ops.read"));
        code(send(mvc,post("/api/v2/roles/"+a+"/status-changes"),admin,object("status","active","reason","上限负例"),id(),"2"),409,"ROLE_LIMIT_REACHED");
        JsonNode disabled=expect(send(mvc,get("/api/v2/roles").param("status","disabled"),admin,null,null,null),200);
        assertThat(disabled.size()).isEqualTo(1);assertThat(disabled.get(0).path("roleKey").asText()).isEqualTo(a);
        assertThat(mapper.activeRoles()+2).isEqualTo(10);
    }

    @ParameterizedTest
    @ValueSource(strings={"platform_admin","security_analyst","security_reviewer","model_operator","evidence_reviewer","auditor",
            "response_approver","model_releaser","asset_source_admin"})
    void allExistingBuiltinRolesAreReadOnly(String builtin) throws Exception {
        Session admin=role("platform_admin");
        assertThat(mapper.role(builtin)).isNotNull();
        var before=new HashMap<>(mapper.role(builtin));
        code(send(mvc,patch("/api/v2/roles/"+builtin),admin,object("name","不能改内置"),id(),"1"),403,"BUILTIN_ROLE_READONLY");
        code(send(mvc,post("/api/v2/roles/"+builtin+"/status-changes"),admin,object("status","disabled","reason","不能停用"),id(),"1"),403,"BUILTIN_ROLE_READONLY");
        code(send(mvc,delete("/api/v2/roles/"+builtin),admin,null,id(),"1"),403,"BUILTIN_ROLE_READONLY");
        assertThat(mapper.role(builtin)).isEqualTo(before);
    }

    @Test void roleChangesValidateAffectedUsersAtomicallyAndRevokeSessions() throws Exception {
        Session admin=role("platform_admin");String key=key();custom(admin,key,List.of("resource.read"));
        long user=accounts.get("security_reviewer").id();JsonNode binding=bind(admin,user,key);Session target=role("security_reviewer");
        code(send(mvc,patch("/api/v2/roles/"+key),admin,object("permissions",List.of("policy.draft")),id(),"1"),409,"ROLE_CONFLICT");
        assertThat(mapper.rolePermissions(number(mapper.role(key),"id"))).containsExactly("resource.read");
        assertThat(number(mapper.role(key),"revision")).isEqualTo(1);
        expect(send(mvc,get("/api/v2/auth/me"),target,null,null,null),200);
        String editKey=id();JsonNode edit=object("name","已修改角色","permissions",List.of("resource.read","detection.read"));
        JsonNode changed=expect(send(mvc,patch("/api/v2/roles/"+key),admin,edit,editKey,"1"),200);
        assertThat(expect(send(mvc,patch("/api/v2/roles/"+key),admin,edit,editKey,"1"),200)).isEqualTo(changed);
        expect(send(mvc,get("/api/v2/auth/me"),target,null,null,null),401);
        code(send(mvc,patch("/api/v2/roles/"+key),admin,object("name","过期写入"),id(),"1"),409,"REVISION_CONFLICT");
        target=role("security_reviewer");
        expect(send(mvc,post("/api/v2/roles/"+key+"/status-changes"),admin,object("status","disabled","reason","停用"),id(),"2"),200);
        expect(send(mvc,get("/api/v2/auth/me"),target,null,null,null),401);
        assertThat(mapper.bindings(user)).extracting(r->str(r,"role_key")).contains(key);
        code(send(mvc,delete("/api/v2/roles/"+key),admin,null,id(),"3"),409,"ROLE_IN_USE");
        expect(send(mvc,post("/api/v2/roles/"+key+"/status-changes"),admin,object("status","active","reason","恢复"),id(),"3"),200);
        JsonNode members=expect(send(mvc,get("/api/v2/roles/"+key+"/members"),admin,null,null,null),200);
        assertThat(members.path("items").get(0).path("bindingId").asLong()).isEqualTo(binding.path("id").asLong());
        expect(send(mvc,post("/api/v2/role-bindings/"+binding.path("id").asLong()+"/revocations"),admin,object("reason","删除前撤销绑定"),id(),null),200);
        String deleteKey=id();JsonNode deleted=expect(send(mvc,delete("/api/v2/roles/"+key),admin,null,deleteKey,"4"),200);
        assertThat(expect(send(mvc,delete("/api/v2/roles/"+key),admin,null,deleteKey,"4"),200)).isEqualTo(deleted);
        assertThat(mapper.role(key)).isNull();
        assertThat(jdbc.queryForObject("SELECT reason FROM audit_log WHERE action='iam.role.delete' AND resource_id=?",String.class,key))
                .contains(key,"resource.read","detection.read");
    }

    @Test void enablingDisabledRoleRechecksCurrentUserUnionAndAuditorCannotStackCustomRole() throws Exception {
        Session admin=role("platform_admin");String key=key();custom(admin,key,List.of("policy.draft"));
        var user=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());bind(admin,user.id(),key);
        expect(send(mvc,post("/api/v2/roles/"+key+"/status-changes"),admin,object("status","disabled","reason","停用"),id(),"1"),200);
        bind(admin,user.id(),"security_reviewer");
        code(send(mvc,post("/api/v2/roles/"+key+"/status-changes"),admin,object("status","active","reason","冲突负例"),id(),"2"),409,"ROLE_CONFLICT");
        assertThat(str(mapper.role(key),"status")).isEqualTo("disabled");
        String readonly=key();custom(admin,readonly,List.of("resource.read"));
        code(send(mvc,post("/api/v2/users/"+accounts.get("auditor").id()+"/role-bindings"),admin,
                object("roleKey",readonly,"scopeType","global","scopeId","*"),id(),null),409,"ROLE_CONFLICT");
    }

    @Test void usernameChangeRevokesOldSessionAndUserDeletionRequiresNoReferences() throws Exception {
        Session admin=role("platform_admin");var user=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());
        Session target=login(mvc,user.username(),FIXTURE_LOGIN);String path="/api/v2/users/"+user.id(),name="renamed-"+id();
        JsonNode update=object("username",name,"displayName","修改资料");String key=id();
        JsonNode changed=expect(send(mvc,patch(path),admin,update,key,"1"),200);
        assertThat(changed.path("username").asText()).isEqualTo(name);
        assertThat(expect(send(mvc,patch(path),admin,update,key,"1"),200)).isEqualTo(changed);
        expect(send(mvc,get("/api/v2/auth/me"),target,null,null,null),401);
        expect(send(mvc,get("/api/v2/auth/me"),login(mvc,name,FIXTURE_LOGIN),null,null,null),200);
        code(send(mvc,delete(path),admin,null,id(),"2"),409,"USER_IN_USE");
        var unused=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());String deleteKey=id(),unusedPath="/api/v2/users/"+unused.id();
        JsonNode deleted=expect(send(mvc,delete(unusedPath),admin,null,deleteKey,"1"),200);
        assertThat(expect(send(mvc,delete(unusedPath),admin,null,deleteKey,"1"),200)).isEqualTo(deleted);
        assertThat(mapper.user(unused.id())).isNull();
        code(send(mvc,delete("/api/v2/users/"+accounts.get("security_analyst").id()),admin,null,id(),"1"),409,"USER_IN_USE");
        code(send(mvc,delete("/api/v2/users/"+accounts.get("platform_admin").id()),admin,null,id(),"1"),403,"SELF_ADMINISTRATION_FORBIDDEN");
        code(send(mvc,patch(path),admin,object("username",accounts.get("auditor").username()),id(),"2"),409,"CONFLICT");
        assertThat(str(mapper.user(user.id()),"username")).isEqualTo(name);
    }

    @Test void userAndRoleQueriesBindTimeSearchAndSortBeforePagination() throws Exception {
        Session admin=role("platform_admin");String prefix="查询%_"+id();List<Long> ids=new ArrayList<>();
        for(int i=0;i<3;i++){
            var user=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());ids.add(user.id());
            jdbc.update("UPDATE sys_user SET display_name=?,created_at=?,updated_at=? WHERE id=?",prefix+i,
                    "2026-01-0"+(i+1)+" 00:00:00","2026-02-0"+(3-i)+" 00:00:00",user.id());
        }
        var noise=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());jdbc.update("UPDATE sys_user SET display_name=? WHERE id=?","查询XYZ"+id(),noise.id());
        String path="/api/v2/users";
        JsonNode first=expect(send(mvc,get(path).param("q",prefix).param("from","2026-01-01T00:00:00Z")
                .param("until","2026-01-04T00:00:00Z").param("sort","updatedAt").param("limit","1"),admin,null,null,null),200);
        assertThat(first.path("items").get(0).path("id").asLong()).isEqualTo(ids.getFirst());
        String cursor=first.path("nextCursor").asText();assertThat(cursor).isNotBlank();
        JsonNode next=expect(send(mvc,get(path).param("q",prefix).param("from","2026-01-01T00:00:00Z")
                .param("until","2026-01-04T00:00:00Z").param("sort","updatedAt").param("limit","2").param("cursor",cursor),admin,null,null,null),200);
        assertThat(next.path("items").size()).isEqualTo(2);
        assertThat(next.path("items").get(0).path("id").asLong()).isEqualTo(ids.get(1));
        code(send(mvc,get(path).param("q",prefix).param("sort","createdAt").param("cursor",cursor),admin,null,null,null),400,"INVALID_CURSOR");
        code(send(mvc,get(path).param("from","2026-01-02T00:00:00Z").param("until","2026-01-01T00:00:00Z"),admin,null,null,null),400,"INVALID_QUERY");
        code(send(mvc,get(path).param("sort","username"),admin,null,null,null),400,"INVALID_QUERY");
        code(send(mvc,get(path).param("q"," "),admin,null,null,null),400,"INVALID_QUERY");
        String roleKey=key();custom(admin,roleKey,List.of("resource.read"));
        assertThat(expect(send(mvc,get("/api/v2/roles").param("q",roleKey).param("sort","updatedAt"),admin,null,null,null),200).size()).isEqualTo(1);
    }

    @Test void allNewIamRoutesRequireHumanSessionAndPermissionAndValidateInput() throws Exception {
        Session admin=role("platform_admin"),auditor=role("auditor");String role=key();custom(admin,role,List.of());
        var user=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());
        for(String path:List.of("/api/v2/permissions","/api/v2/roles/"+role+"/members")){
            expect(mvc.perform(get(path)).andReturn(),401);code(send(mvc,get(path),auditor,null,null,null),403,"SCOPE_DENIED");
            code(send(mvc,get(path).param("unexpected","true"),admin,null,null,null),400,"INVALID_QUERY");
        }
        record Request(String method,String path,JsonNode body){ }
        for(Request r:List.of(new Request("PATCH","/api/v2/roles/"+role,object("name","权限负例")),
                new Request("POST","/api/v2/roles/"+role+"/status-changes",object("status","disabled","reason","权限负例")),
                new Request("DELETE","/api/v2/roles/"+role,null),new Request("DELETE","/api/v2/users/"+user.id(),null),
                new Request("PATCH","/api/v2/users/"+user.id(),object("displayName","权限负例")))){
            expect(send(mvc,request(r.method(),r.path()).with(csrf()),null,r.body(),id(),"1"),401);
            code(send(mvc,request(r.method(),r.path()),auditor,r.body(),id(),"1"),403,"SCOPE_DENIED");
            code(send(mvc,request(r.method(),r.path()),admin,r.body(),id(),null),409,"REVISION_CONFLICT");
            code(send(mvc,request(r.method(),r.path()),admin,r.body(),id(),"0"),409,"REVISION_CONFLICT");
            code(send(mvc,request(r.method(),r.path()),admin,r.body(),"invalid-key","1"),400,"INVALID_UUID");
            if(!r.method().equals("DELETE"))code(send(mvc,request(r.method(),r.path()),admin,object("unexpected",true),id(),"1"),400,"UNKNOWN_FIELD");
            String missing=r.path().contains("/roles/")?r.path().replace(role,key()):r.path().replace("/users/"+user.id(),"/users/9223372036854775807");
            code(send(mvc,request(r.method(),missing),admin,r.body(),id(),"1"),404,"RESOURCE_NOT_FOUND");
        }
        expect(mvc.perform(post("/api/v2/roles").with(csrf()).header("Idempotency-Key",id()).contentType("application/json")
                .content(canonical(object("roleKey",key(),"name","无会话","description","负例","permissions",List.of())))).andReturn(),401);
        code(send(mvc,post("/api/v2/roles"),auditor,object("roleKey",key(),"name","越权","description","负例","permissions",List.of()),id(),null),403,"SCOPE_DENIED");
        for(String permission:List.of("machine.command.claim","unknown.permission"))
            code(send(mvc,post("/api/v2/roles"),admin,object("roleKey",key(),"name","非法权限","description","负例","permissions",List.of(permission)),id(),null),400,"INVALID_REQUEST");
        code(send(mvc,patch("/api/v2/roles/"+role),admin,object("permissions",List.of("resource.read","resource.read")),id(),"1"),400,"INVALID_REQUEST");
        code(send(mvc,patch("/api/v2/users/"+user.id()),admin,object("username","invalid name"),id(),"1"),400,"INVALID_REQUEST");
        code(send(mvc,patch("/api/v2/roles/"+key()),admin,object("name","不存在"),id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,delete("/api/v2/users/9223372036854775807"),admin,null,id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,get("/api/v2/roles/"+key()+"/members"),admin,null,null,null),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,get("/api/v2/roles/"+role+"/members").param("limit","0"),admin,null,null,null),400,"INVALID_PAGE_SIZE");
    }

    @Test void memberCursorBindsRoleActorAndCeilingAndNeverReturnsLaterBindings() throws Exception {
        Session admin=role("platform_admin");String role=key(),otherRole=key();custom(admin,role,List.of("resource.read"));custom(admin,otherRole,List.of());
        List<Long> users=new ArrayList<>();
        for(int i=0;i<3;i++){var user=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());users.add(user.id());bind(admin,user.id(),role);}
        String path="/api/v2/roles/"+role+"/members";
        JsonNode first=expect(send(mvc,get(path).param("limit","1"),admin,null,null,null),200);
        assertThat(first.path("items").get(0).path("id").asLong()).isEqualTo(users.getLast());String cursor=first.path("nextCursor").asText();
        var late=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());bind(admin,late.id(),role);
        JsonNode next=expect(send(mvc,get(path).param("limit","2").param("cursor",cursor),admin,null,null,null),200);
        assertThat(next.path("items").size()).isEqualTo(2);assertThat(next.path("items").get(0).path("id").asLong()).isEqualTo(users.get(1));
        assertThat(next.path("items").get(1).path("id").asLong()).isEqualTo(users.getFirst());assertThat(next.path("nextCursor").isNull()).isTrue();
        code(send(mvc,get("/api/v2/roles/"+otherRole+"/members").param("cursor",cursor),admin,null,null,null),400,"INVALID_CURSOR");
        var second=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of("platform_admin"));Session another=login(mvc,second.username(),FIXTURE_LOGIN);
        code(send(mvc,get(path).param("cursor",cursor),another,null,null,null),400,"INVALID_CURSOR");
    }

    @Test void concurrentRoleCreationCannotExceedTwoEnabledCustomRoles() throws Exception {
        Session first=role("platform_admin");custom(first,key(),List.of("resource.read"));
        var other=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of("platform_admin"));Session second=login(mvc,other.username(),FIXTURE_LOGIN);
        var start=new CountDownLatch(1);
        try(var pool=Executors.newFixedThreadPool(2)){
            var a=pool.submit(()->{start.await();return send(mvc,post("/api/v2/roles"),first,object("roleKey",key(),"name","并发角色一","description","名额验收","permissions",List.of()),id(),null);});
            var b=pool.submit(()->{start.await();return send(mvc,post("/api/v2/roles"),second,object("roleKey",key(),"name","并发角色二","description","名额验收","permissions",List.of()),id(),null);});
            start.countDown();var results=List.of(a.get(30,TimeUnit.SECONDS),b.get(30,TimeUnit.SECONDS));
            assertThat(results.stream().map(r->r.getResponse().getStatus()).sorted().toList()).containsExactly(201,409);
            code(results.stream().filter(r->r.getResponse().getStatus()==409).findFirst().orElseThrow(),409,"ROLE_LIMIT_REACHED");
        }
        assertThat(mapper.activeRoles()+2).isEqualTo(10);
    }

    @Test void businessForeignKeyPreventsUserDeletionWithoutRemovingFacts() throws Exception {
        Session admin=role("platform_admin");var user=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());String plan=id();
        jdbc.update("INSERT INTO guard_evaluation_plan(public_id,plan_key,version,plan_sha256,payload_json,created_by) VALUES(?,?,'1',?,'{}',?)",plan,id(),"a".repeat(64),user.id());
        long users=jdbc.queryForObject("SELECT COUNT(*) FROM sys_user",Long.class),plans=jdbc.queryForObject("SELECT COUNT(*) FROM guard_evaluation_plan",Long.class);
        code(send(mvc,delete("/api/v2/users/"+user.id()),admin,null,id(),"1"),409,"USER_IN_USE");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM sys_user",Long.class)).isEqualTo(users);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM guard_evaluation_plan",Long.class)).isEqualTo(plans);
        assertThat(mapper.user(user.id())).isNotNull();
    }

    @Test void assetScopedIamPermissionCannotManageGlobalIdentityObjects() throws Exception {
        Session admin=role("platform_admin");String custom=key();custom(admin,custom,List.of());var target=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());
        String asset=id();jdbc.update("INSERT INTO asset(public_id,asset_key,asset_type,environment,criticality,status,labels_json) VALUES(?,?,'host','lab','medium','active','{}')",asset,id());
        long aid=jdbc.queryForObject("SELECT id FROM asset WHERE public_id=?",Long.class,asset);var user=IamFixtures.account(jdbc,encoder,FIXTURE_LOGIN,List.of());
        jdbc.update("INSERT INTO sys_user_role(user_id,role_id,scope_type,scope_id) SELECT ?,id,'asset',? FROM sys_role WHERE role_key='platform_admin'",user.id(),Long.toString(aid));
        Session scoped=login(mvc,user.username(),FIXTURE_LOGIN);
        code(send(mvc,get("/api/v2/permissions"),scoped,null,null,null),403,"SCOPE_DENIED");
        code(send(mvc,get("/api/v2/roles"),scoped,null,null,null),403,"SCOPE_DENIED");
        code(send(mvc,get("/api/v2/roles/"+custom+"/members"),scoped,null,null,null),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,post("/api/v2/roles"),scoped,object("roleKey",key(),"name","不能扩大范围","description","负例","permissions",List.of()),id(),null),403,"SCOPE_DENIED");
        code(send(mvc,patch("/api/v2/roles/"+custom),scoped,object("name","越界"),id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,post("/api/v2/roles/"+custom+"/status-changes"),scoped,object("status","disabled","reason","越界"),id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,delete("/api/v2/roles/"+custom),scoped,null,id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,patch("/api/v2/users/"+target.id()),scoped,object("displayName","越界"),id(),"1"),404,"RESOURCE_NOT_FOUND");
        code(send(mvc,delete("/api/v2/users/"+target.id()),scoped,null,id(),"1"),404,"RESOURCE_NOT_FOUND");
    }

    static MockHttpServletRequestBuilder request(String method,String path){return switch(method){case "PATCH"->patch(path);case "POST"->post(path);case "DELETE"->delete(path);default->throw new IllegalArgumentException();};}
}
