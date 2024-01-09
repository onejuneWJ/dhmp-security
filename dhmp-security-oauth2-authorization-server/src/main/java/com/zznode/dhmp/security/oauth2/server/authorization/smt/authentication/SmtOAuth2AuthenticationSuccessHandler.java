package com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication;

import com.zznode.dhmp.security.oauth2.server.authorization.smt.web.SmtParameters;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * 描述
 *
 * @author 王俊
 */
public class SmtOAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(Objects.requireNonNull(authorizationCodeRequestAuthentication.getRedirectUri()))
                .queryParam(OAuth2ParameterNames.CODE, Objects.requireNonNull(authorizationCodeRequestAuthentication.getAuthorizationCode()).getTokenValue());
        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
            uriBuilder.queryParam(
                    OAuth2ParameterNames.STATE,
                    UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        }
        // 前端路由跳转参数
        String redirectRoute = request.getParameter(SmtParameters.REDIRECT_ROUTE);
        if (StringUtils.hasText(redirectRoute)) {
            uriBuilder.queryParam(SmtParameters.REDIRECT_ROUTE, redirectRoute);
        }
        String redirectUri = uriBuilder.build(true).toUriString();
        this.redirectStrategy.sendRedirect(request, response, redirectUri);
    }
}
