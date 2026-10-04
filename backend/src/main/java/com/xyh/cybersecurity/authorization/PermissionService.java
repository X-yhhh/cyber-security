package com.xyh.cybersecurity.authorization;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

/** 对角色模板派生的功能权限做显式复核；资源范围由受限 SQL 再次校验。 */
@Service
public class PermissionService {

    public void require(Authentication authentication, String permissionKey) {
        if (authentication == null || authentication.getAuthorities().stream()
                .noneMatch(authority -> permissionKey.equals(authority.getAuthority()))) {
            throw new AccessDeniedException("Permission denied");
        }
    }
}
