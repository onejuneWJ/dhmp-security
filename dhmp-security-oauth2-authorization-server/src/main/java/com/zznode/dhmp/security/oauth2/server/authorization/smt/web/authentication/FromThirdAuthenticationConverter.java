package com.zznode.dhmp.security.oauth2.server.authorization.smt.web.authentication;

import com.zznode.dhmp.security.oauth2.server.authorization.smt.authentication.FromThirdAuthenticationToken;
import com.zznode.dhmp.security.oauth2.server.authorization.smt.web.SmtParameters;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * 从请求中提取第三方认证相关参数，组装成{@link FromThirdAuthenticationToken}用于认证。
 *
 * @author 王俊
 * @date create in 2023/8/10
 */
public class FromThirdAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = getQueryParameters(request);
        // redirectRoute 可选
        String redirectRoute = parameters.getFirst(SmtParameters.REDIRECT_ROUTE);
        if (StringUtils.hasText(redirectRoute) && parameters.get(SmtParameters.REDIRECT_ROUTE).size() != 1) {
            return null;
        }
        // thirdToken 必填
        String thirdToken = parameters.getFirst(SmtParameters.THIRD_TOKEN);
        if (!StringUtils.hasText(thirdToken) || parameters.get(SmtParameters.THIRD_TOKEN).size() != 1) {
            // 有且只能有一个
            return null;
        }
        // fromSystem 必填
        String fromSystem = parameters.getFirst(SmtParameters.FROM_SYSTEM);
        if (!StringUtils.hasText(fromSystem) || parameters.get(SmtParameters.FROM_SYSTEM).size() != 1) {
            // 有且只能有一个
            return null;
        }
        return new FromThirdAuthenticationToken(thirdToken, redirectRoute, fromSystem);
    }

    private MultiValueMap<String, String> getQueryParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameterMap.forEach((key, values) -> {
            String queryString = StringUtils.hasText(request.getQueryString()) ? request.getQueryString() : "";
            if (queryString.contains(key)) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }
}
