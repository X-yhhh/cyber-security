package com.xyh.cybersecurity.iam;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.Cookie;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import static com.xyh.cybersecurity.guard.GuardJson.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

/** B4 的真实 session/CSRF HTTP 夹具；失败只打印状态和稳定错误码，禁止打印登录载荷。 */
public final class ConsoleHttpTestSupport {
    private ConsoleHttpTestSupport() { }
    public record Session(Cookie cookie,String token) { }

    public static Session login(MockMvc mvc,String username,String password) throws Exception {
        var initial=mvc.perform(get("/api/v2/auth/csrf")).andReturn();
        JsonNode csrf=expect(initial,200);
        var response=mvc.perform(post("/api/v2/auth/login").cookie(initial.getResponse().getCookie("SESSION"))
                .header("X-CSRF-TOKEN",csrf.path("token").asText()).header("Idempotency-Key",id())
                .contentType("application/json").content(canonical(object("username",username,"password",password)))).andReturn();
        expect(response,200);
        Cookie cookie=response.getResponse().getCookie("SESSION");assertThat(cookie).isNotNull();
        JsonNode csrfPayload=expect(mvc.perform(get("/api/v2/auth/csrf").cookie(cookie)).andReturn(),200);
        return new Session(cookie,csrfPayload.path("token").asText());
    }

    public static MvcResult send(MockMvc mvc,MockHttpServletRequestBuilder request,Session session,
                                 JsonNode body,String key,String revision) throws Exception {
        if(session!=null)request.cookie(session.cookie()).header("X-CSRF-TOKEN",session.token());
        if(body!=null)request.contentType("application/json").content(canonical(body));
        if(key!=null)request.header("Idempotency-Key",key);
        if(revision!=null)request.header("If-Match",revision);
        return mvc.perform(request).andReturn();
    }

    public static JsonNode expect(MvcResult result,int status) throws Exception {
        JsonNode body=parse(result.getResponse().getContentAsString());
        assertThat(result.getResponse().getStatus()).withFailMessage("expected HTTP %s, actual %s, code=%s",status,
                result.getResponse().getStatus(),body.at("/error/code").asText()).isEqualTo(status);
        assertThat(body.path("requestId").asText()).isNotBlank();
        assertThat(result.getResponse().getHeader("X-Request-Id")).isEqualTo(body.path("requestId").asText());
        return status<400?body.path("data"):body;
    }

    public static void code(MvcResult result,int status,String code) throws Exception {
        assertThat(expect(result,status).at("/error/code").asText()).isEqualTo(code);
    }
}
