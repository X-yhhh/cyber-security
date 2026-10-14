package com.xyh.cybersecurity.web;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** 真实安全过滤链验证匿名静态资源不影响 API 认证，默认 profile 不引入公开资源入口。 */
class DeployWebSecurityTest {
    @TempDir Path root;
    @Configuration(proxyBeanMethods = false) @EnableWebSecurity @EnableWebMvc
    static class Security {
        @Bean SecurityFilterChain api(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
                    .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))).build();
        }
    }
    @Test void anonymousPagesStillRequireApiAuthentication() throws Exception {
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        Files.writeString(root.resolve("index.html"), "console");
        Files.setPosixFilePermissions(root.resolve("index.html"), PosixFilePermissions.fromString("rw-------"));
        new WebApplicationContextRunner().withUserConfiguration(Security.class, DeployWebConfiguration.class, DeployWebController.class)
                .withPropertyValues("spring.profiles.active=deploy", "cyber.guard.deploy.web-root="+root).run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    var mvc = MockMvcBuilders.webAppContextSetup(ctx).apply(springSecurity()).build();
                    mvc.perform(get("/login").servletPath("/login")).andExpect(status().isOk());
                    mvc.perform(get("/console/detect/events").servletPath("/console/detect/events")).andExpect(status().isOk());
                    mvc.perform(get("/api/v2/assets").servletPath("/api/v2/assets")).andExpect(status().isUnauthorized());
                    mvc.perform(get("/actuator/metrics").servletPath("/actuator/metrics")).andExpect(status().isUnauthorized());
                    mvc.perform(post("/login").servletPath("/login")).andExpect(status().isForbidden());
                });
    }
    @Test void defaultProfileDoesNotExposeWeb() {
        new WebApplicationContextRunner().withUserConfiguration(DeployWebConfiguration.class, DeployWebController.class)
                .run(ctx -> { assertThat(ctx).hasNotFailed(); assertThat(ctx).doesNotHaveBean(DeployWebController.class); });
    }
}
