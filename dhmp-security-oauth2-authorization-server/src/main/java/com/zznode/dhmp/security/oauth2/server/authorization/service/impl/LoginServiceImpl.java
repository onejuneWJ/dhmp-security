package com.zznode.dhmp.security.oauth2.server.authorization.service.impl;

import cn.hutool.captcha.CaptchaUtil;
import cn.hutool.captcha.ICaptcha;
import cn.hutool.core.codec.Base64;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.AsymmetricAlgorithm;
import com.zznode.dhmp.context.annotation.ProvinceComponent;
import com.zznode.dhmp.core.constant.BaseConstants;
import com.zznode.dhmp.core.exception.CommonException;
import com.zznode.dhmp.core.message.DhmpMessageSource;
import com.zznode.dhmp.security.oauth2.server.authorization.DhmpOAuth2AuthorizationServerProperties;
import com.zznode.dhmp.security.oauth2.server.authorization.constants.AuthAttributes;
import com.zznode.dhmp.security.oauth2.server.authorization.constants.ErrorCodes;
import com.zznode.dhmp.security.oauth2.server.authorization.service.LoginService;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.web.servlet.function.RenderingResponse;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import java.security.KeyPair;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/7/31
 */
@ProvinceComponent
public class LoginServiceImpl implements LoginService, MessageSourceAware {

    private final Logger logger = LoggerFactory.getLogger(LoginServiceImpl.class);

    private MessageSourceAccessor messages = DhmpMessageSource.getAccessor();

    private final DhmpOAuth2AuthorizationServerProperties properties;

    public LoginServiceImpl(DhmpOAuth2AuthorizationServerProperties properties) {
        this.properties = properties;
    }

    @Override
    public ServerResponse toLogin(ServerRequest request) {
        HttpServletRequest httpServletRequest = request.servletRequest();
        setTemplateAttributes(httpServletRequest, httpServletRequest.getSession());
        return RenderingResponse
                .create(properties.getLoginTemplate())
                .build();
    }

    protected void setTemplateAttributes(HttpServletRequest request, HttpSession httpSession) {
        Object exception = request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        if (exception == null) {
            exception = httpSession.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        }
        if (exception != null) {
            String exceptionMessage = determineExceptionMessage(exception);
            request.setAttribute(AuthAttributes.ERROR_MESSAGE, exceptionMessage);
        }
        request.setAttribute(AuthAttributes.USERNAME_ENCRYPT, properties.getUsernameEncrypt());
        request.setAttribute(AuthAttributes.PASSWORD_ENCRYPT, properties.getPasswordEncrypt());
        KeyPair keyPair = SecureUtil.generateKeyPair(AsymmetricAlgorithm.RSA_ECB_PKCS1.getValue());
        String publicKey = Base64.encode(keyPair.getPublic().getEncoded());
        String privateKey = Base64.encode(keyPair.getPrivate().getEncoded());
        request.setAttribute(AuthAttributes.PUBLIC_KEY, publicKey);
        httpSession.setAttribute(AuthAttributes.PUBLIC_KEY, publicKey);
        httpSession.setAttribute(AuthAttributes.PRIVATE_KEY, privateKey);
    }

    protected String determineExceptionMessage(Object exception) {

        if (exception instanceof AuthenticationException e) {
            if (e instanceof InternalAuthenticationServiceException) {
                return this.messages.getMessage(BaseConstants.ErrorCode.ERROR);
            }
            return e.getMessage();
        } else {
            return this.messages.getMessage(BaseConstants.ErrorCode.ERROR);
        }

    }

    @Override
    public ServerResponse createCaptcha(ServerRequest request) {

        return ServerResponse
                .status(HttpStatus.OK)
                .build((servletRequest, response) -> {
                    HttpSession session = servletRequest.getSession();
                    response.setDateHeader("Expires", 0L);
                    response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
                    response.addHeader("Cache-Control", "post-check=0, pre-check=0");
                    response.setHeader("Pragma", "no-cache");
                    response.setContentType("image/jpeg");

                    try (ServletOutputStream out = response.getOutputStream()) {
                        ICaptcha captcha = CaptchaUtil.createShearCaptcha(100, 46, properties.getCaptcha().getCodeCount(), 4);
                        captcha.createCode();
                        String code = captcha.getCode();
                        session.setAttribute(AuthAttributes.CAPTCHA, code);
                        session.setMaxInactiveInterval(300);
                        captcha.write(out);
                        out.flush();
                    } catch (Exception e) {
                        logger.info("create captcha fail: {}", e.getMessage());
                    }
                    return null;
                });

    }

    @Override
    public ServerResponse verifyCaptcha(ServerRequest request) {

        HttpSession session = request.servletRequest().getSession();
        // 验证码参数
        String code = request.param("code").orElse("");
        // 获取存在的验证码
        String captcha = (String) session.getAttribute(AuthAttributes.CAPTCHA);
        if (captcha == null) {
            // session中不存在，表明验证码过期了
            throw new CommonException(this.messages.getMessage(ErrorCodes.CAPTCHA_EXPIRED));
        }
        if (!code.equalsIgnoreCase(captcha)) {
            throw new CommonException(this.messages.getMessage(ErrorCodes.INVALID_CAPTCHA));
        }
        return ServerResponse.ok().build();
    }


    @Override
    public void setMessageSource(@NonNull MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }
}
