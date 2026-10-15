package com.xyh.cybersecurity.guard;

import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static com.xyh.cybersecurity.guard.GuardJson.*;
import static com.xyh.cybersecurity.guard.GuardTodoMapper.TodoKind.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** BE-22 待办参数边界与跨类别截断契约，独立于数据库测试验证归并排序。 */
class GuardTodosContractTest {
    private final GuardAccess access = mock(GuardAccess.class);
    private final GuardTodoMapper mapper = mock(GuardTodoMapper.class);
    private final LocalDateTime now = LocalDateTime.parse("2026-10-15T12:00:00.123456");

    GuardTodosContractTest() {
        when(access.human()).thenReturn(7L);
        when(mapper.now()).thenReturn(now);
    }

    @Test
    void emptyTodosOmitUnauthorizedCategoriesAndRejectParameters() {
        var service = new GuardTodos(access, mapper);
        assertThat(service.todos(new LinkedMultiValueMap<>())).isEqualTo(object("groups", List.of(), "truncated", false));
        var p = new LinkedMultiValueMap<String, String>(); p.add("limit", "1");
        assertThatThrownBy(() -> service.todos(p)).hasMessageContaining("INVALID_QUERY");
        verify(mapper, never()).todoItems(anyLong(), any(), any(), anyInt());
    }

    @Test
    void machinePrincipalCannotQueryHumanTodos() {
        var context = org.springframework.security.core.context.SecurityContextHolder.createEmptyContext();
        context.setAuthentication(org.springframework.security.authentication.UsernamePasswordAuthenticationToken.authenticated(
                new com.xyh.cybersecurity.identity.MachinePrincipal(1, "fixture", "sensor"), null, List.of()));
        org.springframework.security.core.context.SecurityContextHolder.setContext(context);
        try {
            var humanAccess = new GuardAccess(mock(GuardMapper.class), mock(GuardStore.class));
            assertThatThrownBy(() -> new GuardTodos(humanAccess, mapper).todos(null))
                    .hasMessageContaining("HUMAN_IDENTITY_REQUIRED");
            verifyNoInteractions(mapper);
        } finally {
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
    }

    @Test
    void todosMergeNewestAcrossCategoriesBeforeApplyingTheGlobalLimit() {
        when(mapper.allowed(7, "authorization.approve", false)).thenReturn(true);
        when(mapper.allowed(7, "event.manage", false)).thenReturn(true);
        when(mapper.todoCount(7, AUTHORIZATION, now)).thenReturn(70L);
        when(mapper.todoCount(7, SENSOR_CONFIG, now)).thenReturn(60L);
        when(mapper.todoCount(7, EVENT, now)).thenReturn(1L);
        var auth = new ArrayList<java.util.Map<String, Object>>();
        var config = new ArrayList<java.util.Map<String, Object>>();
        for (int i = 0; i < 70; i++) auth.add(map("public_id", "a-" + i, "asset_public_id", "asset-a", "created_at", now.minusSeconds(i * 2L)));
        for (int i = 0; i < 60; i++) config.add(map("public_id", "c-" + i, "asset_public_id", "asset-a", "detail", "sensor-a", "created_at", now.minusSeconds(i * 2L + 1)));
        when(mapper.todoItems(7, AUTHORIZATION, now, 100)).thenReturn(auth);
        when(mapper.todoItems(7, SENSOR_CONFIG, now, 100)).thenReturn(config);
        var value = new GuardTodos(access, mapper).todos(null);
        assertThat(value.at("/groups/0/kind").asText()).isEqualTo("approve");
        assertThat(value.at("/groups/0/count").asLong()).isEqualTo(130);
        assertThat(value.at("/groups/0/items")).hasSize(100);
        assertThat(value.at("/groups/0/items/0/id").asText()).isEqualTo("a-0");
        assertThat(value.at("/groups/0/items/1/id").asText()).isEqualTo("c-0");
        assertThat(value.at("/groups/0/items/99/id").asText()).isEqualTo("c-49");
        assertThat(value.at("/groups/1/count").asLong()).isEqualTo(1);
        assertThat(value.at("/groups/1/items")).isEmpty();
        assertThat(value.path("truncated").asBoolean()).isTrue();
        verify(mapper, never()).todoItems(eq(7L), eq(EVENT), any(), anyInt());
    }

}
