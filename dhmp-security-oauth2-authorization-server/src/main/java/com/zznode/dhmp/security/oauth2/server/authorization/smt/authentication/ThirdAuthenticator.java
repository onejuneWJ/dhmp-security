package com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * 第三方认证
 *
 * @author 王俊
 * @date create in 2023/8/10
 */
public interface ThirdAuthenticator {

    /**
     * 不同的第三方认证逻辑
     *
     * @param authenticationToken authenticationToken
     * @return UsernamePasswordAuthenticationToken
     */
    UsernamePasswordAuthenticationToken authenticate(FromThirdAuthenticationToken authenticationToken) throws Exception;

    /**
     * 是否支持
     *
     * @param authenticationToken authenticationToken
     * @return true
     */
    boolean supports(FromThirdAuthenticationToken authenticationToken);
}
