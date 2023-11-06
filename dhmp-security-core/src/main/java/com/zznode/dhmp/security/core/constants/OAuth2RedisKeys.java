package com.zznode.dhmp.security.core.constants;

/**
 * 一些key
 *
 * @author 王俊
 * @date create in 2023/8/4
 */
public class OAuth2RedisKeys {

    /**
     * 密码错误次数
     */
    public static final String PASSWORD_ERROR_COUNT_KEY = "dhmp:oauth2:account:password.error.count";

    /**
     * 已登录的用户
     */
    public static final String LOGIN_USER = "dhmp:oauth2:account:login";
}
