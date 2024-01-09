package com.zznode.dhmp.security.oauth2.server.authorization.configurer;

import com.zznode.dhmp.security.oauth2.server.authorization.filter.ExUsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
import static org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;

/**
 * 重写{@link org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer formLoginConfigurer},
 * 替换默认的{@link org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter UsernamePasswordAuthenticationFilter}
 *
 * @author 王俊
 * @date create in 2023/8/8
 * @see org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer
 * @see ExUsernamePasswordAuthenticationFilter
 */
public final class DhmpFormLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, DhmpFormLoginConfigurer<H>, ExUsernamePasswordAuthenticationFilter> {

    public DhmpFormLoginConfigurer() {
        super(new ExUsernamePasswordAuthenticationFilter(), null);
        usernameParameter(SPRING_SECURITY_FORM_USERNAME_KEY);
        passwordParameter(SPRING_SECURITY_FORM_PASSWORD_KEY);
        passwordEncrypt(true);
        usernameEncrypt(true);
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);
    }

    /**
     * @see org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer#loginPage(String)
     */
    @Override
    public DhmpFormLoginConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, HttpMethod.POST.name());
    }

    public DhmpFormLoginConfigurer<H> usernameParameter(String usernameParameter) {
        getAuthenticationFilter().setUsernameParameter(usernameParameter);
        return this;
    }

    public DhmpFormLoginConfigurer<H> passwordParameter(String passwordParameter) {
        getAuthenticationFilter().setPasswordParameter(passwordParameter);
        return this;
    }

    public DhmpFormLoginConfigurer<H> passwordEncrypt(boolean passwordEncrypt) {
        getAuthenticationFilter().setNeedDecryptPassword(passwordEncrypt);
        return this;
    }

    public DhmpFormLoginConfigurer<H> usernameEncrypt(boolean usernameEncrypt) {
        getAuthenticationFilter().setNeedDecryptUsername(usernameEncrypt);
        return this;
    }
}
