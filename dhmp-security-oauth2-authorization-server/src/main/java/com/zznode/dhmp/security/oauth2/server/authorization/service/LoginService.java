package com.zznode.dhmp.security.oauth2.server.authorization.service;

import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * 登录页面相关
 *
 * @author 王俊
 * @date create in 2023/7/31 16:15
 */
public interface LoginService {
    /**
     * 登录页面
     *
     * @param request 请求
     * @return 登录页面
     */
    ServerResponse toLogin(ServerRequest request);

    /**
     * 生成验证码
     */
    ServerResponse createCaptcha(ServerRequest request);

    ServerResponse verifyCaptcha(ServerRequest request);
}
