package com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/8/10
 */
public class FromThirdAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final String thirdToken;
    private final String redirectRoute;
    private final String fromSystem;

    public FromThirdAuthenticationToken(String thirdToken, String redirectRoute, String fromSystem) {
        super(thirdToken, thirdToken);
        this.thirdToken = thirdToken;
        this.redirectRoute = redirectRoute;
        this.fromSystem = fromSystem;
    }

    public String getThirdToken() {
        return thirdToken;
    }

    public String getRedirectRoute() {
        return redirectRoute;
    }

    public String getFromSystem() {
        return fromSystem;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }
}
