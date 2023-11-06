package com.zznode.dhmp.security.core;

import com.zznode.dhmp.security.core.constants.BaseConstants;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

/**
 * 获取当前请求的认证对象工具
 *
 * @author 王俊
 */
public class SecurityUtil {

    private SecurityUtil() {
    }

    private static final CustomUserDetails ANONYMOUS;

    static {
        ANONYMOUS = new CustomUserDetails(BaseConstants.ANONYMOUS_USER_NAME, "unknown", Collections.emptyList());
        ANONYMOUS.setUserId(BaseConstants.ANONYMOUS_USER_ID);
    }

    /**
     * 返回匿名用户
     */
    public static CustomUserDetails anonymousDetails() {
        return ANONYMOUS;
    }

    /**
     * 获取访问用户的userDetail对象
     *
     * @return CustomUserDetails
     */
    public static CustomUserDetails getUserDetails() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext != null && securityContext.getAuthentication() != null) {
            Object principal = securityContext.getAuthentication().getPrincipal();
            if (principal instanceof CustomUserDetails customUserDetails) {
                return customUserDetails;
            }
        }
        return ANONYMOUS;
    }


    public static void setCustomUserDetails(CustomUserDetails customUserDetails) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        if (securityContext == null) {
            return;
        }
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(customUserDetails, customUserDetails.getPassword(), AuthorityUtils.NO_AUTHORITIES);
        securityContext.setAuthentication(usernamePasswordAuthenticationToken);
    }

    public static void setCustomUserDetails(Long userId) {
        CustomUserDetails customUserDetails = new CustomUserDetails("default", "default");
        customUserDetails.setUserId(userId);
        setCustomUserDetails(customUserDetails);
    }
}
