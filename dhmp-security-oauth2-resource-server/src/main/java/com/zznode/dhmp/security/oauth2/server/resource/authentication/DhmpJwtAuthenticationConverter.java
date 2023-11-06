package com.zznode.dhmp.security.oauth2.server.resource.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.Map;

/**
 * 将jwt转换成 {@link Authentication}
 *
 * @author 王俊
 * @date create in 2023/5/19
 */
public class DhmpJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final Logger logger = LoggerFactory.getLogger(DhmpJwtAuthenticationConverter.class);

    private final Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private final JwtUserDetailsConverter userDetailsConverter = new JwtUserDetailsConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(),
                jwt.getIssuedAt(), jwt.getExpiresAt());
        Map<String, Object> attributes = jwt.getClaims();
        Collection<GrantedAuthority> authorities = this.jwtGrantedAuthoritiesConverter.convert(jwt);
        UserDetails user = userDetailsConverter.convert(jwt);
        return new DhmpJwtAuthenticationToken(accessToken, user, authorities, attributes);
    }

}
