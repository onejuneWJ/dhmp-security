package com.zznode.dhmp.security.oauth2.server.authorization.smt.configures;

import com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication.FromThirdAuthenticationProvider;
import com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication.ThirdAuthenticator;
import com.zznode.dhmp.security.oauth2.server.authorization.smt.web.FromThirdAuthenticationFilter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.ArrayList;
import java.util.Collection;

/**
 * 第三方登录配置
 *
 * @author 王俊
 * @date create in 2023/8/10
 */
public final class FromThirdLoginConfigurer<B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<FromThirdLoginConfigurer<B>, B> {

    private FromThirdAuthenticationProvider authenticationProvider;

    private AuthenticationConverter authenticationConverter;


    public FromThirdLoginConfigurer() {
    }


    public FromThirdLoginConfigurer<B> authenticationConverter(AuthenticationConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
        return this;
    }

    @Override
    public void init(B http) throws Exception {
        super.init(http);

        FromThirdAuthenticationProvider provider = getAuthenticationProvider(http);
        provider.setUserDetailsService(getUserDetailsService(http));
        // 用户不存在的异常，不用转换成用户名或密码错误。
        // 直接抛出用户不存在异常，表明第三方系统的用户在本系统不存在
        provider.setHideUserNotFoundExceptions(false);
        http.authenticationProvider(postProcess(provider));
    }

    private FromThirdAuthenticationProvider getAuthenticationProvider(B http) {
        if (this.authenticationProvider == null) {
            Collection<ThirdAuthenticator> thirdAuthenticators = getApplicationContext(http).getBeansOfType(ThirdAuthenticator.class).values();

            this.authenticationProvider = new FromThirdAuthenticationProvider(new ArrayList<>(thirdAuthenticators));
        }
        return this.authenticationProvider;
    }

    private UserDetailsService getUserDetailsService(B http) {
        UserDetailsService userDetailsService = http.getSharedObject(UserDetailsService.class);
        if (userDetailsService != null) {
            return userDetailsService;
        }
        return getApplicationContext(http).getBean(UserDetailsService.class);
    }

    private ApplicationContext getApplicationContext(B http) {
        return http.getSharedObject(ApplicationContext.class);
    }


    @Override
    public void configure(B http) throws Exception {

        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        AuthorizationServerSettings authorizationServerSettings = getAuthorizationServerSettings(http);
        FromThirdAuthenticationFilter authFilter = new FromThirdAuthenticationFilter(authenticationManager,
                authorizationServerSettings.getAuthorizationEndpoint());

        if (this.authenticationConverter != null) {
            authFilter.setAuthenticationConverter(this.authenticationConverter);
        }
        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
        if (securityContextRepository != null) {
            authFilter.setSecurityContextRepository(securityContextRepository);
        }
        SecurityContextHolderStrategy securityContextHolderStrategy = http.getSharedObject(SecurityContextHolderStrategy.class);
        if (securityContextHolderStrategy != null) {
            authFilter.setSecurityContextHolderStrategy(securityContextHolderStrategy);
        }

        FromThirdAuthenticationFilter filter = postProcess(authFilter);
        http.addFilterBefore(filter, OAuth2AuthorizationEndpointFilter.class);

    }

    private AuthorizationServerSettings getAuthorizationServerSettings(B httpSecurity) {
        AuthorizationServerSettings authorizationServerSettings = httpSecurity.getSharedObject(AuthorizationServerSettings.class);
        if (authorizationServerSettings == null) {
            authorizationServerSettings = getApplicationContext(httpSecurity).getBean(AuthorizationServerSettings.class);
            httpSecurity.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
        }
        return authorizationServerSettings;
    }

}
