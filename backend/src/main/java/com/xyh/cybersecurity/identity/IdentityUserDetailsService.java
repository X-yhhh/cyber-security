package com.xyh.cybersecurity.identity;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/** 从 MySQL 身份事实和角色权限模板解析人工用户主体。 */
@Service
public class IdentityUserDetailsService implements UserDetailsService {

    private final IdentityMapper identityMapper;

    public IdentityUserDetailsService(IdentityMapper identityMapper) {
        this.identityMapper = identityMapper;
    }

    @Override
    public IdentityPrincipal loadUserByUsername(String username) throws UsernameNotFoundException {
        IdentityMapper.PrincipalRow row = identityMapper.findPrincipalByUsername(username);
        if (row == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return new IdentityPrincipal(row.id(), row.userKey(), row.username(), row.displayName(), row.passwordHash(),
                row.status(), identityMapper.listUserRoles(row.id()), identityMapper.listUserPermissions(row.id()));
    }

    private List<String> loadRoles(long userId) {
        return identityMapper.listUserRoles(userId);
    }

    private List<String> loadPermissions(long userId) {
        return identityMapper.listUserPermissions(userId);
    }

}
