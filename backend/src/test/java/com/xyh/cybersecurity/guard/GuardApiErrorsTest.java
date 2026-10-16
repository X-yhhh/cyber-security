package com.xyh.cybersecurity.guard;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.xyh.cybersecurity.common.api.ApiRequestException;
import com.xyh.cybersecurity.common.web.RequestIdFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.SQLException;
import java.util.List;

import static com.xyh.cybersecurity.guard.GuardJson.parse;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/** 实际 MVC 错误路径与日志捕获：诊断字段可关联请求，异常原文、SQL 和请求秘密不能进入响应或日志。 */
class GuardApiErrorsTest {
    private final GuardApiErrors handler = new GuardApiErrors();
    private final Logger logger = (Logger) LoggerFactory.getLogger(GuardApiErrors.class);
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private Level previousLevel;

    @BeforeEach void capture() {
        previousLevel = logger.getLevel();
        logger.setLevel(Level.ERROR);
        logs.start();
        logger.addAppender(logs);
    }

    @AfterEach void release() {
        logger.detachAppender(logs);
        logs.stop();
        logger.setLevel(previousLevel);
    }

    @RestController
    static class FailureController {
        @GetMapping("/api/v2/fixture-error")
        void fail() {
            throw new IllegalStateException("sentinel-private SQL and request body",
                    new SQLException("sentinel-private JDBC URL and values", "HY001", 1038));
        }
    }

    @Test void mvcFailureLogsSafeSqlDiagnosticsAndPreservesTheEnvelope() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(new FailureController()).setControllerAdvice(handler)
                .addFilters(new RequestIdFilter()).build();
        var response = mvc.perform(get("/api/v2/fixture-error").header("X-Request-Id", "w4-p1r2-sql")
                .header("Authorization", "sentinel-private").header("Cookie", "session=sentinel-private")
                .queryParam("input", "sentinel-private")).andReturn().getResponse();
        assertThat(response.getStatus()).isEqualTo(500);
        var body = parse(response.getContentAsString());
        assertThat(body.path("requestId").asText()).isEqualTo("w4-p1r2-sql").isEqualTo(response.getHeader("X-Request-Id"));
        assertThat(body.at("/error/code").asText()).isEqualTo("INTERNAL_ERROR");
        assertThat(body.at("/error/retryable").asBoolean()).isTrue();
        assertThat(body.at("/error/details").isEmpty()).isTrue();
        assertThat(body.toString()).doesNotContain("sentinel-private", "SQLException", "HY001", "1038");
        assertThat(logs.list).hasSize(1);
        var event = logs.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.ERROR);
        assertThat(event.getFormattedMessage()).contains("w4-p1r2-sql", "500", "IllegalStateException", "SQLException", "HY001", "1038")
                .doesNotContain("sentinel-private", "fixture-error", "Authorization", "session=", "SQL and request body");
        assertThat(event.getThrowableProxy()).isNull();
    }

    @Test void invalidIncomingRequestIdIsRegeneratedBeforeLogging() throws Exception {
        var mvc = MockMvcBuilders.standaloneSetup(new FailureController()).setControllerAdvice(handler)
                .addFilters(new RequestIdFilter()).build();
        var response = mvc.perform(get("/api/v2/fixture-error").header("X-Request-Id", "sentinel-private\r\ninjected"))
                .andReturn().getResponse();
        String requestId = parse(response.getContentAsString()).path("requestId").asText();
        assertThat(requestId).matches("[a-f0-9-]{36}").isEqualTo(response.getHeader("X-Request-Id"));
        assertThat(logs.list).hasSize(1);
        assertThat(logs.list.getFirst().getFormattedMessage()).contains(requestId).doesNotContain("sentinel-private", "injected", "\r", "\n");
    }

    @ParameterizedTest
    @EnumSource(value = HttpStatus.class, names = {"INTERNAL_SERVER_ERROR", "SERVICE_UNAVAILABLE"})
    void explicitServerErrorsAreLoggedWithoutTheirMessages(HttpStatus status) {
        var response = handler.errorResponse(new ApiRequestException(status, "FIXTURE_UNAVAILABLE", "sentinel-private"), request());
        assertThat(response.getStatusCode()).isEqualTo(status);
        assertThat(response.getBody().at("/error/code").asText()).isEqualTo("FIXTURE_UNAVAILABLE");
        assertThat(logs.list).hasSize(1);
        assertThat(logs.list.getFirst().getFormattedMessage()).contains("w4-p1r2-direct", Integer.toString(status.value()))
                .doesNotContain("sentinel-private");
        assertThat(logs.list.getFirst().getThrowableProxy()).isNull();
    }

    @Test void clientFailuresKeepTheirMappingAndDoNotEmitServerErrorLogs() {
        var exceptions = List.of(ApiRequestException.badRequest("sentinel-private"),
                new AccessDeniedException("sentinel-private"), new DuplicateKeyException("sentinel-private"));
        var expected = List.of(400, 403, 409);
        for (int i = 0; i < exceptions.size(); i++) {
            var response = handler.errorResponse(exceptions.get(i), request());
            assertThat(response.getStatusCode().value()).isEqualTo(expected.get(i));
            assertThat(response.getBody().toString()).doesNotContain("sentinel-private");
        }
        assertThat(logs.list).isEmpty();
    }

    @Test void unsafeSqlStateAndMissingRequestContextAreNotLoggedAsText() {
        handler.errorResponse(new SQLException("sentinel-private", "sentinel-private\r\nstate", 1038), new MockHttpServletRequest());
        assertThat(logs.list).hasSize(1);
        assertThat(logs.list.getFirst().getFormattedMessage()).contains("unknown", "SQLException", "1038")
                .doesNotContain("sentinel-private", "\r", "\n");
    }

    @Test void cyclicCauseChainCannotPreventTheStable500Response() {
        var first = new IllegalStateException("sentinel-private");
        var second = new IllegalArgumentException("sentinel-private", first);
        first.initCause(second);
        assertThat(handler.errorResponse(first, request()).getStatusCode().value()).isEqualTo(500);
        assertThat(logs.list).hasSize(1);
        assertThat(logs.list.getFirst().getFormattedMessage()).doesNotContain("sentinel-private");
    }

    private MockHttpServletRequest request() {
        var request = new MockHttpServletRequest();
        request.setAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE, "w4-p1r2-direct");
        return request;
    }
}
