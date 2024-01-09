package com.zznode.dhmp.security.oauth2.server.authorization.smt.web;

/**
 * 第三方认证相关参数
 * <p>避免与oauth2的的参数冲突，采用驼峰命名
 *
 * @author 王俊
 * @date create in 2023/8/11
 */
public class SmtParameters {
    /**
     * 第三方携带过来的token
     */
    public static final String THIRD_TOKEN = "thirdToken";
    /**
     * 第三方系统标识。 4A、RMS、ZCP。。。
     */
    public static final String FROM_SYSTEM = "fromSystem";
    /**
     * 授权成功后前端跳转的路由。如：/、/home、/sys/user
     */
    public static final String REDIRECT_ROUTE = "redirectRoute";
}
