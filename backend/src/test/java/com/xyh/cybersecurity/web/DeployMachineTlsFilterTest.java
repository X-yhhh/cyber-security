package com.xyh.cybersecurity.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class DeployMachineTlsFilterTest {
    @Test void machineRequiresTlsCertificateButBrowserDoesNot() throws Exception {
        var filter = new DeployMachineTlsFilter(new ObjectMapper());
        var request = new MockHttpServletRequest("POST", "/api/v2/machine/sensors/id/heartbeats");
        var denied = new MockHttpServletResponse();
        filter.doFilter(request, denied, new MockFilterChain());
        assertThat(denied.getStatus()).isEqualTo(401);
        assertThat(denied.getContentAsString()).contains("MACHINE_TLS_REQUIRED");
        assertThat(denied.getHeader("X-Request-Id")).isNotBlank();
        request.setSecure(true);
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{mock(X509Certificate.class)});
        var chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        assertThat(chain.getRequest()).isSameAs(request);
        var browser = new MockFilterChain();
        filter.doFilter(new MockHttpServletRequest("GET", "/login"), new MockHttpServletResponse(), browser);
        assertThat(browser.getRequest()).isNotNull();
    }
}
