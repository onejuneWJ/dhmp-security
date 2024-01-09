package com.zznode.dhmp.security.oauth2.server.authorization.smt;

import com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication.SmtOAuth2AuthenticationSuccessHandler;
import com.zznode.dhmp.security.oauth2.server.authorization.smt.configures.FromThirdLoginConfigurer;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;

/**
 * 描述
 *
 * @author 王俊
 */
@Configuration(proxyBeanMethods = false)
public class SmtConfiguration {

    public static void applyDefaultSmt(HttpSecurity http) throws Exception {
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(authorization -> authorization
                        .authorizationResponseHandler(new SmtOAuth2AuthenticationSuccessHandler())
                );
        // 第三方嵌入静默登录、4A票据登录
        http.with(new FromThirdLoginConfigurer<>(), Customizer.withDefaults());
    }
}
