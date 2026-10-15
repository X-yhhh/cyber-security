package com.xyh.cybersecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class AbsoluteSessionFilterTest {

    @Test
    void expiresAuthenticatedSessionAfterAbsoluteLifetimeEvenWhenRecentlyUsed() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-09-23T12:00:00Z"), ZoneOffset.UTC);
        AbsoluteSessionFilter filter = new AbsoluteSessionFilter(clock, new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v2/auth/me");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(AbsoluteSessionFilter.CREATED_AT_ATTRIBUTE,
                clock.instant().minusSeconds(8 * 60 * 60L).toEpochMilli());
        request.setSession(session);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("user", null, java.util.List.of()));
        SecurityContextHolder.setContext(context);
        AtomicBoolean continued = new AtomicBoolean(false);
        FilterChain chain = (req, res) -> continued.set(true);

        try {
            filter.doFilter(request, response, chain);

            assertThat(continued).isFalse();
            assertThat(session.isInvalid()).isTrue();
            assertThat(response.getStatus()).isEqualTo(401);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void allowsSessionWithinAbsoluteLifetime() throws Exception {
        AbsoluteSessionFilter filter = new AbsoluteSessionFilter(Clock.systemUTC(), new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v2/auth/me");
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.getSession().setAttribute(AbsoluteSessionFilter.CREATED_AT_ATTRIBUTE,
                Clock.systemUTC().instant().minusSeconds(60).toEpochMilli());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("user", null, java.util.List.of()));
        SecurityContextHolder.setContext(context);
        AtomicBoolean continued = new AtomicBoolean(false);

        try {
            filter.doFilter(request, response, (req, res) -> continued.set(true));
            assertThat(continued).isTrue();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
