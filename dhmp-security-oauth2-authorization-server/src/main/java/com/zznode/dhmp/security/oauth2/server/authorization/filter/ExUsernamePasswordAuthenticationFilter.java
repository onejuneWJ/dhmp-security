package com.zznode.dhmp.security.oauth2.server.authorization.filter;

import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import com.zznode.dhmp.security.oauth2.server.authorization.constants.AuthAttributes;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

/**
 * 重写{@link UsernamePasswordAuthenticationFilter}
 *
 * @author 王俊
 * @date create in 2023/8/8
 */
public class ExUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    /**
     * 否需要解密用户名
     */
    private boolean needDecryptUsername = true;
    /***
     * 是否需要解密密码
     */
    private boolean needDecryptPassword = true;

    public void setNeedDecryptUsername(boolean needDecryptUsername) {
        this.needDecryptUsername = needDecryptUsername;
    }

    public void setNeedDecryptPassword(boolean needDecryptPassword) {
        this.needDecryptPassword = needDecryptPassword;
    }


    @Override
    protected String obtainUsername(HttpServletRequest request) {
        String obtainUsername = super.obtainUsername(request);
        if (needDecryptUsername && StringUtils.hasText(obtainUsername)) {
            return decryptStr(request, obtainUsername);
//            return AesUtil.decryptData(obtainUsername);
        }
        return obtainUsername;
    }

    @Override
    protected String obtainPassword(HttpServletRequest request) {
        String obtainPassword = super.obtainPassword(request);
        if (needDecryptPassword && StringUtils.hasText(obtainPassword)) {
            return decryptStr(request, obtainPassword);
        }
        return obtainPassword;
    }

    private String decryptStr(HttpServletRequest request, String str) {

        String privateKey = (String) request.getSession().getAttribute(AuthAttributes.PRIVATE_KEY);
        String publicKey = (String) request.getSession().getAttribute(AuthAttributes.PUBLIC_KEY);
        String decryptStr;
        try {
            decryptStr = SecureUtil.rsa(privateKey, publicKey).decryptStr(str, KeyType.PrivateKey);
        } catch (Exception e) {
            throw new InternalAuthenticationServiceException("error decrypt str", e);
        }
        return decryptStr;
    }
}
