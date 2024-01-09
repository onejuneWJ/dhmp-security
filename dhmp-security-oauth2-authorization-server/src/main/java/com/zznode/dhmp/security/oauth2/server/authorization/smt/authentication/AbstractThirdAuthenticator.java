package com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * 第三方认证器抽象类
 *
 * @author 王俊
 * @date create in 2023/8/10
 */
public abstract class AbstractThirdAuthenticator implements ThirdAuthenticator {
    @Override
    public UsernamePasswordAuthenticationToken authenticate(FromThirdAuthenticationToken authenticationToken) throws Exception {
        String thirdToken = authenticationToken.getThirdToken();
        String string = analysisUsername(thirdToken);
        return UsernamePasswordAuthenticationToken.unauthenticated(string, "");
    }

    /**
     * 从第三方token中解析用户名
     *
     * @param token 第三方token
     * @return 用户名
     */
    protected abstract String analysisUsername(String token);
}
