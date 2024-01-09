package com.zznode.dhmp.security.oauth2.server.authorization.context;


import com.zznode.dhmp.security.core.CustomUserDetails;

/**
 * 正在执行登录操作的用户缓存
 *
 * @author 王俊
 * @date create in 2023/8/2
 */
public class LoginUserContextHolder {

    private static final ThreadLocal<CustomUserDetails> USER_DETAILS_CACHE = new ThreadLocal<>();

    public static void setCurrentLoginUser(CustomUserDetails user) {
        USER_DETAILS_CACHE.set(user);
    }

    public static CustomUserDetails getCurrentLoginUser() {
        return USER_DETAILS_CACHE.get();
    }

    public static void clear() {
        USER_DETAILS_CACHE.remove();
    }
}
