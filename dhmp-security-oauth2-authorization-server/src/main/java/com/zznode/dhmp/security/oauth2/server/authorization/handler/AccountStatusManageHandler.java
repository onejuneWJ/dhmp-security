package com.zznode.dhmp.security.oauth2.server.authorization.handler;

import org.springframework.security.core.AuthenticationException;

/**
 * 账号状态处理
 *
 * @author 王俊
 * @date create in 2023/8/2 11:11
 */
public interface AccountStatusManageHandler {

    /**
     * 处理授权异常
     *
     * @param exception 授权异常
     * @return 新异常
     */
    AuthenticationException handle(AuthenticationException exception);
}
