package com.xyh.cybersecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.common.web.RequestIdFilter;
import com.xyh.cybersecurity.identity.IdentityUserDetailsService;
import java.time.Clock;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.core.annotation.Order;

import java.io.IOException;

import static com.xyh.cybersecurity.common.web.RequestIdFilter.REQUEST_ID_ATTRIBUTE;

/** 采用默认拒绝、CSRF 保护和 JDBC 服务端会话的浏览器安全链。 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    AbsoluteSessionFilter absoluteSessionFilter(Clock clock, ObjectMapper mapper) {
        return new AbsoluteSessionFilter(clock, mapper);
    }

    @Bean
    FilterRegistrationBean<AbsoluteSessionFilter> absoluteSessionFilterRegistration(AbsoluteSessionFilter filter) {
        FilterRegistrationBean<AbsoluteSessionFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    FilterRegistrationBean<MachineCredentialFilter> machineCredentialFilterRegistration(MachineCredentialFilter filter) {
        FilterRegistrationBean<MachineCredentialFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    MachineRequestSizeFilter machineRequestSizeFilter(ObjectMapper mapper) {
        return new MachineRequestSizeFilter(mapper);
    }

    @Bean
    FilterRegistrationBean<MachineRequestSizeFilter> machineRequestSizeFilterRegistration(MachineRequestSizeFilter filter) {
        FilterRegistrationBean<MachineRequestSizeFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    AuthenticationManager authenticationManager(IdentityUserDetailsService users, PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(encoder);
        provider.setHideUserNotFoundExceptions(true);
        return new ProviderManager(provider);
    }

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    AuthenticationEntryPoint apiAuthenticationEntryPoint(ObjectMapper mapper, SecurityAuditWriter auditWriter) {
        return (request, response, exception) -> {
            auditWriter.denied(request, null, "security.authentication.required", "authentication_required");
            writeError(mapper, request, response, 401, "UNAUTHENTICATED", "需要登录后访问");
        };
    }

    @Bean
    AccessDeniedHandler apiAccessDeniedHandler(ObjectMapper mapper, SecurityAuditWriter auditWriter) {
        return (request, response, exception) -> {
            boolean csrfFailure = exception instanceof CsrfException;
            auditWriter.denied(request,
                    org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication(),
                    csrfFailure ? "security.csrf.denied" : "authorization.denied",
                    csrfFailure ? "csrf_validation_failed" : "permission_denied");
            writeError(mapper, request, response, 403,
                    csrfFailure ? "CSRF_INVALID" : "FORBIDDEN",
                    csrfFailure ? "请求安全校验失败" : "当前身份无权执行此操作");
        };
    }

    @Bean
    @Order(1)
    SecurityFilterChain machineSecurityFilterChain(HttpSecurity http, RequestIdFilter requestIdFilter,
                                                   AuthenticationEntryPoint entryPoint, AccessDeniedHandler deniedHandler,
                                                   MachineCredentialFilter machineCredentialFilter,
                                                   MachineRequestSizeFilter machineRequestSizeFilter) throws Exception {
        http.securityMatcher("/api/v1/machine/**", "/api/v2/machine/**")
                .csrf(csrf -> csrf.disable())
                .securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(cache -> cache.disable())
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                .exceptionHandling(errors -> errors.authenticationEntryPoint(entryPoint).accessDeniedHandler(deniedHandler))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .addFilterBefore(requestIdFilter, org.springframework.security.web.context.SecurityContextHolderFilter.class)
                .addFilterAfter(machineCredentialFilter, org.springframework.security.web.context.SecurityContextHolderFilter.class)
                .addFilterAfter(machineRequestSizeFilter, MachineCredentialFilter.class);
        return http.build();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, RequestIdFilter requestIdFilter,
                                            AuthenticationEntryPoint entryPoint, AccessDeniedHandler deniedHandler,
                                            SecurityContextRepository contextRepository,
                                            AbsoluteSessionFilter absoluteSessionFilter,
                                            MachineCredentialFilter machineCredentialFilter,
                                            MachineRequestSizeFilter machineRequestSizeFilter) throws Exception {
        http
                .csrf(csrf -> csrf.ignoringRequestMatchers("/api/v1/machine/**"))
                .securityContext(context -> context.securityContextRepository(contextRepository))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation(fixation -> fixation.changeSessionId())
                        .maximumSessions(1))
                .requestCache(cache -> cache.disable())
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedHandler))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/health/live", "/api/v1/health/ready",
                                "/api/v1/auth/login", "/api/v1/auth/csrf",
                                "/api/v2/auth/login", "/api/v2/auth/csrf").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/actuator/metrics/**", "/actuator/prometheus").hasAuthority("ops.status.read")
                        .requestMatchers("/api/v1/auth/me", "/api/v1/auth/logout").authenticated()
                        .requestMatchers("/api/v1/**", "/api/v2/**").authenticated()
                        .anyRequest().denyAll())
                .addFilterBefore(requestIdFilter, org.springframework.security.web.context.SecurityContextHolderFilter.class);
        http.addFilterAfter(absoluteSessionFilter, org.springframework.security.web.context.SecurityContextHolderFilter.class);
        http.addFilterAfter(machineCredentialFilter, AbsoluteSessionFilter.class);
        http.addFilterAfter(machineRequestSizeFilter, AbsoluteSessionFilter.class);
        return http.build();
    }

    private static void writeError(ObjectMapper mapper, HttpServletRequest request, HttpServletResponse response,
                                   int status, String code, String message) throws IOException {
        Object requestId = request.getAttribute(REQUEST_ID_ATTRIBUTE);
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        mapper.writeValue(response.getOutputStream(), ApiEnvelope.failure(
                code, message, requestId instanceof String value ? value : "unknown"));
    }
}
