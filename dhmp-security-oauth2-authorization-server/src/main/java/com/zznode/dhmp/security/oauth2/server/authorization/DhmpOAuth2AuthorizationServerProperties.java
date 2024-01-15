package com.zznode.dhmp.security.oauth2.server.authorization;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.time.Duration;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/7/27 16:00
 */
//@ConfigurationProperties("dhmp.oauth2.authorizationserver")
public class DhmpOAuth2AuthorizationServerProperties {

    /**
     * 登录地址，未授权访问会跳转至登录地址。
     */
    private String loginUrl = "/login";

    /**
     * 登录页面模板.
     */
    private String loginTemplate = "login";

    /**
     * 登录成功跳转地址
     */
    private String defaultRedirectUrl = "/";

    /**
     * 登录时用户名的参数名称,如果没有自定义登录页面模板的时候,请不要修改此配置
     */
    private String usernameParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;

    /**
     * 登录时密码的参数名称,如果没有自定义登录页面模板的时候,请不要修改此配置
     */
    private String passwordParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;

    /**
     * 前端登录时是否加密传输用户名
     */
    private Boolean usernameEncrypt = true;

    /**
     * 前端登录时是否加密传输密码
     */
    private Boolean passwordEncrypt = true;

    private String publicKey;

    private Captcha captcha = new Captcha();

    private AccountManagement accountManagement = new AccountManagement();

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getLoginTemplate() {
        return loginTemplate;
    }

    public void setLoginTemplate(String loginTemplate) {
        this.loginTemplate = loginTemplate;
    }

    public String getDefaultRedirectUrl() {
        return defaultRedirectUrl;
    }

    public void setDefaultRedirectUrl(String defaultRedirectUrl) {
        this.defaultRedirectUrl = defaultRedirectUrl;
    }

    public String getUsernameParameter() {
        return usernameParameter;
    }

    public void setUsernameParameter(String usernameParameter) {
        this.usernameParameter = usernameParameter;
    }

    public String getPasswordParameter() {
        return passwordParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        this.passwordParameter = passwordParameter;
    }

    public Boolean getUsernameEncrypt() {
        return usernameEncrypt;
    }

    public void setUsernameEncrypt(Boolean usernameEncrypt) {
        this.usernameEncrypt = usernameEncrypt;
    }

    public Boolean getPasswordEncrypt() {
        return passwordEncrypt;
    }

    public void setPasswordEncrypt(Boolean passwordEncrypt) {
        this.passwordEncrypt = passwordEncrypt;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public Captcha getCaptcha() {
        return captcha;
    }

    public void setCaptcha(Captcha captcha) {
        this.captcha = captcha;
    }

    public AccountManagement getAccountManagement() {
        return accountManagement;
    }

    public void setAccountManagement(AccountManagement accountManagement) {
        this.accountManagement = accountManagement;
    }

    public static class Captcha {

        /**
         * 验证码字符的个数
         */
        private Integer codeCount = 4;

        private Boolean dev = false;

        public Integer getCodeCount() {
            return codeCount;
        }

        public void setCodeCount(Integer codeCount) {
            this.codeCount = codeCount;
        }

        public Boolean getDev() {
            return dev;
        }

        public void setDev(Boolean dev) {
            this.dev = dev;
        }
    }

    public static class AccountManagement {
        /**
         * 是否开启账号管控
         */
        private Boolean enabled = false;
        /**
         * 允许密码输入错误次数, 达到这个数字，账号将被锁定
         */
        private Integer passwordAllowErrorCount = 5;
        /**
         * 账号被禁用超过这个次数则被停用, 如果设置-1，则不禁用。默认不禁用
         */
        private Integer accountDisableOverLockCount = -1;

        /**
         * 账号自动解除锁定时间间隔
         * <p>值使用 8640000ms、8640s、1440m(分钟)、24h、1d(1天)、
         */
        private Duration accountAutoUnlockDuration = Duration.ofDays(1);

        /**
         * 账号管控服务地址
         */
        private String iamServerAddr = "http://localhost:8100";

        public Boolean getEnabled() {
            return enabled;
        }

        public void setEnabled(Boolean enabled) {
            this.enabled = enabled;
        }

        public Integer getPasswordAllowErrorCount() {
            return passwordAllowErrorCount;
        }

        public void setPasswordAllowErrorCount(Integer passwordAllowErrorCount) {
            this.passwordAllowErrorCount = passwordAllowErrorCount;
        }

        public Integer getAccountDisableOverLockCount() {
            return accountDisableOverLockCount;
        }

        public void setAccountDisableOverLockCount(Integer accountDisableOverLockCount) {
            this.accountDisableOverLockCount = accountDisableOverLockCount;
        }

        public Duration getAccountAutoUnlockDuration() {
            return accountAutoUnlockDuration;
        }

        public void setAccountAutoUnlockDuration(Duration accountAutoUnlockDuration) {
            this.accountAutoUnlockDuration = accountAutoUnlockDuration;
        }

        public String getIamServerAddr() {
            return iamServerAddr;
        }

        public void setIamServerAddr(String iamServerAddr) {
            this.iamServerAddr = iamServerAddr;
        }
    }
}
