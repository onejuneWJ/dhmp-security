package com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication;

import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

/**
 * 第三方认证，处理{@link FromThirdAuthenticationToken}
 *
 * @author 王俊
 * @date create in 2023/8/10
 */
public class FromThirdAuthenticationProvider extends DaoAuthenticationProvider {

    private final List<ThirdAuthenticator> thirdAuthenticators;

    public FromThirdAuthenticationProvider(List<ThirdAuthenticator> thirdAuthenticators) {
        this.thirdAuthenticators = thirdAuthenticators;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // do nothing 不检查密码
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        FromThirdAuthenticationToken authenticationToken = (FromThirdAuthenticationToken) authentication;
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;
        for (ThirdAuthenticator thirdAuthenticator : thirdAuthenticators) {
            if (thirdAuthenticator.supports(authenticationToken)) {
                try {
                    usernamePasswordAuthenticationToken = thirdAuthenticator.authenticate(authenticationToken);
                } catch (Throwable e) {
                    if (e instanceof AuthenticationException authenticationException) {
                        throw authenticationException;
                    }
                    // 抛出InternalAuthenticationServiceException可直接抛至filter,否则会继续在父级ProviderManger执行认证
                    throw new InternalAuthenticationServiceException(e.getMessage(), e);
                }
                if (usernamePasswordAuthenticationToken != null) {
                    if (usernamePasswordAuthenticationToken.isAuthenticated()) {
                        return usernamePasswordAuthenticationToken;
                    }
                    break;
                }
            }
        }
        if (usernamePasswordAuthenticationToken == null) {
            throw new InternalAuthenticationServiceException("no authenticator found for system " + authenticationToken.getFromSystem());
        }

        return super.authenticate(usernamePasswordAuthenticationToken);
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return FromThirdAuthenticationToken.class.isAssignableFrom(authentication);
    }


}
