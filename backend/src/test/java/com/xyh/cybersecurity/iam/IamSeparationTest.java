package com.xyh.cybersecurity.iam;

import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.guard.*;
import com.xyh.cybersecurity.identity.IdentityPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import java.time.Instant;
import java.util.List;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

/** S1—S7：即使遗留账号同时持有申请和审批权限，真实应用服务仍须逐对象拒绝自批且不写状态。 */
class IamSeparationTest {
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @ParameterizedTest
    @ValueSource(strings={"authorization","config","policy","bundle","action","feedback","lab"})
    void objectApprovalRejectsItsCreatorEvenWithBothPermissions(String kind) {
        var mapper=mock(GuardMapper.class);var store=mock(GuardStore.class);
        when(mapper.permitted(anyLong(),anyString(),anyString(),anyString())).thenReturn(true);
        var access=new GuardAccess(mapper,store);
        var principal=new IdentityPrincipal(7,"fixture","fixture","隔离双权限主体","unused","active",List.of(),List.of());
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(principal,null,List.of()));
        String id=id();var row=map("id",1L,"asset_id",2L,"sensor_id",3L,"revision",1L,"requested_by",7L,"created_by",7L,
                "mode","manual","observed_state","pending","status","pending");
        when(store.external(anyString(),eq(id),anyBoolean())).thenReturn(row);
        when(store.get(eq("sensor_agent"),eq(3L))).thenReturn(map("asset_id",2L));
        when(store.now()).thenReturn(Instant.now());
        var labMapper=mock(GuardLabMapper.class);
        when(labMapper.lock(1)).thenReturn(map("status","registered","manifest_jcs","{}"));
        var decision=object("decision","approve","reason","职责分离负例");
        var admin=new GuardAdministration(store,mapper,access,null);
        var catalog=new GuardCatalog(store,access,null,null,null,null,false);
        assertThatThrownBy(() -> {
            switch(kind) {
                case "authorization" -> admin.approveAuthorization(id,decision,"1");
                case "config" -> admin.approveConfig(id,decision,"1");
                case "policy" -> catalog.reviewPolicy(id,decision,"1");
                case "bundle" -> catalog.approveBundle(id,decision,"1");
                case "action" -> new GuardActions(mapper,store,access,null,null,null,null,null).approve(id,decision,"1");
                case "feedback" -> new GuardCases(store,access).review(id,decision,"1");
                case "lab" -> new GuardLabSessions(store,access,labMapper,null,null,null,null).operate(id,"decisions",decision,"1");
                default -> throw new AssertionError(kind);
            }
        }).isInstanceOfSatisfying(ApiRequestException.class,e -> {
            assertThat(e.status().value()).isEqualTo(403);
            assertThat(e.code()).isEqualTo("APPROVAL_SEPARATION_REQUIRED");
        });
        verify(store,never()).update(anyString(),anyLong(),anyMap());
        verify(store,never()).outbox(anyString(),anyString(),any());
    }
}
