package com.xyh.cybersecurity.security;

import com.xyh.cybersecurity.identity.MachinePrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** 只为 machine 路由验证高熵连接器凭据；不回退到用户 Cookie 或 session。 */
@Component
public final class MachineCredentialFilter extends OncePerRequestFilter {

    private static final Pattern CREDENTIAL = Pattern.compile("Machine mch_([1-9][0-9]*)\\.([A-Za-z0-9_-]{40,64})");
    private final JdbcTemplate jdbc;

    public MachineCredentialFilter(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith(request.getContextPath() + "/api/v1/machine/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        SecurityContextHolder.clearContext();
        Matcher matcher = CREDENTIAL.matcher(request.getHeader("Authorization") == null
                ? "" : request.getHeader("Authorization"));
        if (matcher.matches()) {
            try {
                long clientId = Long.parseLong(matcher.group(1));
                String suppliedHash = sha256(matcher.group(2));
                ClientRecord client = jdbc.query("SELECT client_key, client_type, credential_sha256 "
                                + "FROM api_client WHERE id=? AND status='active' "
                                + "AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP(3))",
                        rs -> rs.next() ? new ClientRecord(rs.getString("client_key"), rs.getString("client_type"),
                                rs.getString("credential_sha256")) : null, clientId);
                if (client != null && client.credentialSha256() != null
                        && MessageDigest.isEqual(client.credentialSha256().getBytes(StandardCharsets.US_ASCII),
                        suppliedHash.getBytes(StandardCharsets.US_ASCII))) {
                    List<SimpleGrantedAuthority> authorities = jdbc.queryForList(
                            "SELECT p.permission_key FROM api_client_permission cp "
                                    + "JOIN sys_permission p ON p.id=cp.permission_id AND p.status='active' "
                                    + "WHERE cp.client_id=? ORDER BY p.permission_key", String.class, clientId)
                            .stream().map(SimpleGrantedAuthority::new).toList();
                    var authentication = UsernamePasswordAuthenticationToken.authenticated(
                            new MachinePrincipal(clientId, client.clientKey(), client.clientType()), null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (NumberFormatException ignored) {
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(request, response);
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private record ClientRecord(String clientKey, String clientType, String credentialSha256) { }
}
