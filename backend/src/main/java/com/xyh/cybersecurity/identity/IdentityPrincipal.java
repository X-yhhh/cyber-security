package com.xyh.cybersecurity.identity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/** 登录主体只暴露受控身份与显式权限，不携带密码哈希到 API 响应。 */
public final class IdentityPrincipal implements UserDetails {

    private final long id;
    private final String userKey;
    private final String username;
    private final String displayName;
    private final String passwordHash;
    private final String status;
    private final List<String> roles;
    private final List<String> permissions;

    public IdentityPrincipal(long id, String userKey, String username, String displayName, String passwordHash,
                             String status, List<String> roles, List<String> permissions) {
        this.id = id;
        this.userKey = userKey;
        this.username = username;
        this.displayName = displayName;
        this.passwordHash = passwordHash == null ? "" : passwordHash;
        this.status = status;
        this.roles = List.copyOf(roles);
        this.permissions = List.copyOf(permissions);
    }

    public long id() { return id; }
    public String userKey() { return userKey; }
    public String displayName() { return displayName; }
    public List<String> roles() { return roles; }
    public List<String> permissions() { return permissions; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return permissions.stream().map(SimpleGrantedAuthority::new).toList();
    }

    @Override
    public String getPassword() { return passwordHash; }

    @Override
    public String getUsername() { return username; }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return !"locked".equals(status); }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return "active".equals(status) && !passwordHash.isBlank(); }
}
