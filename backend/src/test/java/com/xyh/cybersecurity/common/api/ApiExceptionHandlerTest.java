package com.xyh.cybersecurity.common.api;

import com.xyh.cybersecurity.security.SecurityAuditWriter;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** 验证全局异常映射只返回稳定脱敏消息并透传 request-id。 */
class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler(provider());

    @Test
    void internalErrorDoesNotExposeStackOrDatabaseDetails() {
        MockHttpServletRequest request = request("req-o9-internal");
        ResponseEntity<ApiEnvelope<Void>> response = handler.internalError(
                new IllegalStateException("jdbc:mysql://masked-host/db; credential value omitted"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().error().code()).isEqualTo("INTERNAL_ERROR");
        assertThat(response.getBody().error().message()).isEqualTo("服务暂时无法处理请求");
        assertThat(response.getBody().error().message()).doesNotContain("jdbc", "credential", "masked-host");
        assertThat(response.getBody().requestId()).isEqualTo("req-o9-internal");
    }

    private static MockHttpServletRequest request(String requestId) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(REQUEST_ID_ATTRIBUTE, requestId);
        return request;
    }

    @SuppressWarnings("unchecked")
    private static ObjectProvider<SecurityAuditWriter> provider() {
        ObjectProvider<SecurityAuditWriter> provider = mock(ObjectProvider.class);
        org.mockito.Mockito.when(provider.getIfAvailable()).thenReturn(null);
        return provider;
    }
}
