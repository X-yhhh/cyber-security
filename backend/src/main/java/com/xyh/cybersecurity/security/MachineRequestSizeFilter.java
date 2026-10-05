package com.xyh.cybersecurity.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xyh.cybersecurity.common.api.ApiEnvelope;
import com.xyh.cybersecurity.common.web.RequestIdFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;

/** 在 JSON 解析前限制机器批次请求体，避免超大载荷占用无界内存。 */
public class MachineRequestSizeFilter extends OncePerRequestFilter {

    public static final int MAX_REQUEST_BYTES = 1_048_576;

    private final ObjectMapper objectMapper;

    public MachineRequestSizeFilter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return !request.getRequestURI().startsWith(contextPath + "/api/v1/machine/ingest/")
                && !request.getRequestURI().startsWith(contextPath + "/api/v2/machine/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getContentLengthLong() > MAX_REQUEST_BYTES) {
            reject(request, response);
            return;
        }
        byte[] body = request.getInputStream().readNBytes(MAX_REQUEST_BYTES + 1);
        if (body.length > MAX_REQUEST_BYTES) {
            reject(request, response);
            return;
        }
        chain.doFilter(new BoundedBodyRequest(request, body), response);
    }

    private void reject(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Object value = request.getAttribute(RequestIdFilter.REQUEST_ID_ATTRIBUTE);
        String requestId = value instanceof String id ? id : "unknown";
        response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), ApiEnvelope.failure(
                "PAYLOAD_TOO_LARGE", "机器接入请求体不能超过 1 MiB", requestId));
    }

    private static final class BoundedBodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        private BoundedBodyRequest(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public int getContentLength() {
            return body.length;
        }

        @Override
        public long getContentLengthLong() {
            return body.length;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream input = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public int read() {
                    return input.read();
                }

                @Override
                public boolean isFinished() {
                    return input.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener listener) {
                    if (listener == null) return;
                    try {
                        if (input.available() > 0) listener.onDataAvailable();
                        if (input.available() == 0) listener.onAllDataRead();
                    } catch (IOException exception) {
                        listener.onError(exception);
                    }
                }
            };
        }

        @Override
        public BufferedReader getReader() throws IOException {
            String encoding = getCharacterEncoding();
            Charset charset = encoding == null ? Charset.defaultCharset() : Charset.forName(encoding);
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }
}
