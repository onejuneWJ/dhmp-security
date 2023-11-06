package com.zznode.dhmp.security.oauth2.server.resource.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zznode.dhmp.security.core.CustomUserDetails;
import com.zznode.dhmp.security.core.constants.CustomUserClaimNames;
import com.zznode.dhmp.security.core.jackson2.DhmpOAuth2Jackson2Module;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;

/**
 * 从jwt中得到CustomUserDetails
 *
 * @author 王俊
 * @date create in 2023/7/28 16:24
 */
public class JwtUserDetailsConverter implements Converter<Jwt, UserDetails> {

    private final Logger logger = LoggerFactory.getLogger(JwtUserDetailsConverter.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtUserDetailsConverter() {
        this.objectMapper.registerModules(new DhmpOAuth2Jackson2Module());
    }

    @Override
    public UserDetails convert(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaims();
        try {
            return objectMapper.readValue(String.valueOf(claims.get(CustomUserClaimNames.USER_DETAILS)), CustomUserDetails.class);
        } catch (Exception e) {
            logger.error("error reading user details from jwt", e);
            return CustomUserDetails.anonymousUser();
        }
    }

}
