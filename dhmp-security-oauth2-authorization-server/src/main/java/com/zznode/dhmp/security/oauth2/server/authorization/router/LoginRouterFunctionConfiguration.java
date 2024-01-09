package com.zznode.dhmp.security.oauth2.server.authorization.router;

import com.zznode.dhmp.data.exception.ExceptionResponse;
import com.zznode.dhmp.security.oauth2.server.authorization.service.LoginService;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * 登录相关接口的RouterFunction
 *
 * @author 王俊
 */

public class LoginRouterFunctionConfiguration {

    public static RouterFunction<ServerResponse> loginRouter(LoginService loginService) {
        return RouterFunctions
                .route()
                .GET("/login", loginService::toLogin)
                .GET("/login/captcha", loginService::createCaptcha)
                .GET("/login/verify-captcha", loginService::verifyCaptcha)
                .onError(Exception.class, (throwable, request) -> {
                    String message = throwable.getMessage();
                    ExceptionResponse exceptionResponse = new ExceptionResponse(message);
                    return ServerResponse.ok().body(exceptionResponse);
                })
                .build();
    }
}
