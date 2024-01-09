package com.zznode.dhmp.security.oauth2.server.authorization.constants;

/**
 * 错误信息码
 *
 * @author 王俊
 * @date create in 2023/8/4
 */
public interface ErrorCodes {

    String INVALID_CAPTCHA = "oauth.captcha_invalid";
    String CAPTCHA_EXPIRED = "oauth.captcha_expired";
    String ACCOUNT_LOCKED = "oauth.account_locked";
    String ACCOUNT_DISABLED = "oauth.account_disabled";
    String THIRD_PARTY_ERROR = "oauth.third_auth_error";
}
