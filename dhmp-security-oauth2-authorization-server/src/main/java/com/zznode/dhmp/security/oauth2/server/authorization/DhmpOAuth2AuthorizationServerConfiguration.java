package com.zznode.dhmp.security.oauth2.server.authorization;

import com.zznode.dhmp.security.oauth2.server.authorization.configurer.DhmpFormLoginConfigurer;
import com.zznode.dhmp.security.oauth2.server.authorization.smt.SmtConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Set;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 描述
 *
 * @author 王俊
 */
@Configuration(proxyBeanMethods = false)
public class DhmpOAuth2AuthorizationServerConfiguration {


    private static final String[] PERMIT_PATHS = new String[]{"/error", "/login/**", "/webjars/**",
            "/css/**", "/js/**", "/img/**", "/favicon.ico"};

    public static void applyDefaultSecurityLogin(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(PERMIT_PATHS).permitAll()
                        .anyRequest().authenticated()
                )
                .cors(withDefaults())
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(withDefaults());

        http.with(new DhmpFormLoginConfigurer<>(), dhmpFormLoginConfigurer -> {
            dhmpFormLoginConfigurer.loginPage("/login")
                    .permitAll();
        });

    }

    public static void applyDefaultOauth2Security(HttpSecurity http) throws Exception {

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(withDefaults());
        http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));
        http.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"), createRequestMatcher()));

        SmtConfiguration.applyDefaultSmt(http);

    }

    private static RequestMatcher createRequestMatcher() {
        MediaTypeRequestMatcher requestMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        requestMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
        return requestMatcher;
    }
}
