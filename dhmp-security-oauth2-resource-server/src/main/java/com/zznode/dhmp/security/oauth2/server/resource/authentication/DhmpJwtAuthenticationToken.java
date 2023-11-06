package com.zznode.dhmp.security.oauth2.server.resource.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/5/19 13:32
 */
public class DhmpJwtAuthenticationToken extends AbstractOAuth2TokenAuthenticationToken<OAuth2AccessToken> {

    private final Map<String, Object> attributes;

    public DhmpJwtAuthenticationToken(OAuth2AccessToken token, UserDetails principal,
                                      Collection<? extends GrantedAuthority> authorities,
                                      Map<String, Object> attributes) {
        super(token, principal, token, authorities);

        Assert.isTrue(token.getTokenType() == OAuth2AccessToken.TokenType.BEARER,
                "credentials must be a bearer token");
        this.attributes = Collections.unmodifiableMap(attributes);


        this.setAuthenticated(true);
        this.eraseCredentials();
    }


    @Override
    public Map<String, Object> getTokenAttributes() {
        return this.attributes;
    }


}
