package com.zznode.dhmp.security.oauth2.server.authorization.smt.web;

import com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication.ThirdAuthenticationException;
import com.zznode.dhmp.security.oauth2.server.authorization.smt.web.authentication.FromThirdAuthenticationConverter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.*;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 从外部系统登录提前授权。在OAuth2AuthorizationEndpointFilter之前
 *
 * @author 王俊
 * @date create in 2023/8/10
 * @see org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter
 */
public class FromThirdAuthenticationFilter extends OncePerRequestFilter {
    /**
     * The default endpoint {@code URI} for authorization requests.
     */
    private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";
    private AuthenticationConverter authenticationConverter = new FromThirdAuthenticationConverter();
    private final AuthenticationManager authenticationManager;
    private final RequestMatcher authorizationEndpointMatcher;

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler("/login?error");

    public FromThirdAuthenticationFilter(AuthenticationManager authenticationManager) {
        this(authenticationManager, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
    }

    public FromThirdAuthenticationFilter(AuthenticationManager authenticationManager, String authorizationEndpointUri) {
        this.authenticationManager = authenticationManager;
        this.authorizationEndpointMatcher = createDefaultRequestMatcher(authorizationEndpointUri);
    }

    private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
        RequestMatcher authorizationRequestGetMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.GET.name());
        RequestMatcher authorizationRequestPostMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.POST.name());
        RequestMatcher openidScopeMatcher = request -> {
            String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
            return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
        };
        RequestMatcher responseTypeParameterMatcher = request ->
                request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;

        RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(
                authorizationRequestGetMatcher,
                new AndRequestMatcher(
                        authorizationRequestPostMatcher, responseTypeParameterMatcher, openidScopeMatcher));
        RequestMatcher authorizationConsentMatcher = new AndRequestMatcher(
                authorizationRequestPostMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));

        return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {

        // 只有是oauth2授权请求才执行此过滤器
        if (!this.authorizationEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        Authentication authentication;
        try {
            authentication = authenticationConverter.convert(request);
        } catch (Exception e) {
            logger.error("error convert request as Authentication.", e);
            // 转换异常
            authentication = null;
        }
        if (authentication == null) {
            // 如果为空，表明不是第三方登录，直接执行后面的过滤器
            filterChain.doFilter(request, response);
            return;
        }
        // 不要问为什么两个try分开，filterChain.doFilter(request, response);这句话不能被try包含。
        try {
            Authentication authenticationResult = this.authenticationManager.authenticate(authentication);
            // 正常情况authenticationResult都是认证通过的，没通过都抛出异常了
            if (authenticationResult.isAuthenticated()) {
                // 第三方认证成功，保存认证信息。
                successfulAuthentication(request, response, filterChain, authenticationResult);
                filterChain.doFilter(request, response);
                return;
            }
        } catch (AuthenticationException e) {
            logger.error("failed to authenticate from third party", e);
            unsuccessfulAuthentication(request, response, new ThirdAuthenticationException("第三方认证失败", e));
            return;
        }
        //让后续过滤器处理
        filterChain.doFilter(request, response);
    }


    public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "AuthenticationConverter cannot be null");
        this.authenticationConverter = authenticationConverter;
    }

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authResult);
        this.securityContextHolderStrategy.setContext(context);
        this.securityContextRepository.saveContext(context, request, response);
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        this.securityContextHolderStrategy.clearContext();
        this.failureHandler.onAuthenticationFailure(request, response, failed);
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
    }

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
    }
}
