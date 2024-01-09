package com.zznode.dhmp.security.oauth2.server.authorization.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;

/**
 * 自定义登录失败处理器
 * <p>账号管控
 *
 * @author 王俊
 * @date create in 2023/8/2 9:59
 */
public class AccountAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {


    private final AccountStatusManageHandler accountStatusManageHandler;

    public AccountAuthenticationFailureHandler(AccountStatusManageHandler accountStatusManageHandler) {
        this.accountStatusManageHandler = accountStatusManageHandler;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        try {
            AuthenticationException newException = this.accountStatusManageHandler.handle(exception);
            super.onAuthenticationFailure(request, response, newException);
        } catch (Throwable t) {
            logger.error("error occurred while handling account status", t);
            super.onAuthenticationFailure(request, response, exception);
        }
    }

}
