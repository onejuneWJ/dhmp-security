package com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication;

import org.springframework.security.core.AuthenticationException;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/8/10
 */
public class ThirdAuthenticationException extends AuthenticationException {

    public ThirdAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public ThirdAuthenticationException(String msg) {
        super(msg);
    }

}
