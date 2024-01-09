package com.zznode.dhmp.security.oauth2.server.authorization.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zznode.dhmp.security.core.CustomUserDetails;
import com.zznode.dhmp.security.core.constants.CustomUserClaimNames;
import com.zznode.dhmp.security.core.jackson2.DhmpOAuth2Jackson2Module;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * token自定义信息,授权码模式
 *
 * @author 王俊
 * @date create in 2023/7/28 17:15
 */
@SuppressWarnings("AlibabaClassNamingShouldBeCamel")
public class CustomUserDetailsOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final Logger logger = LoggerFactory.getLogger(CustomUserDetailsOAuth2TokenCustomizer.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    public CustomUserDetailsOAuth2TokenCustomizer() {
        this.objectMapper.registerModule(new DhmpOAuth2Jackson2Module());
    }

    @Override
    public void customize(JwtEncodingContext context) {
        AuthorizationGrantType authorizationGrantType = context.getAuthorizationGrantType();
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)
                && !AuthorizationGrantType.REFRESH_TOKEN.equals(authorizationGrantType)) {
            return;
        }
        UsernamePasswordAuthenticationToken token = context.getPrincipal();
        CustomUserDetails customUserDetails = (CustomUserDetails) token.getPrincipal();
        JwtClaimsSet.Builder claims = context.getClaims();
        claims.claim(StandardClaimNames.NAME, customUserDetails.getUsername());
        try {
            String json = this.objectMapper.writeValueAsString(customUserDetails);
            claims.claim(CustomUserClaimNames.USER_DETAILS, json);
        } catch (Exception e) {
            logger.error("error to serialize user. ", e);
        }
    }
}
