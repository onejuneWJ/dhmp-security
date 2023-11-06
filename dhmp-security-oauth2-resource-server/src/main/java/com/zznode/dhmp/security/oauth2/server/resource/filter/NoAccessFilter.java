package com.zznode.dhmp.security.oauth2.server.resource.filter;

import com.zznode.dhmp.core.constant.InternalRequestHeaders;
import com.zznode.dhmp.core.exception.CommonException;
import jakarta.servlet.*;

import java.io.IOException;

/**
 * 禁止直接通过端口访问,必须通过gateway访问,或者内部调用
 *
 * @author 王俊
 * @date create in 2023/8/22
 */
public class NoAccessFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        Object gw = request.getAttribute(InternalRequestHeaders.INTERNAL_TOKEN);
        if(gw == null){
            throw new CommonException("禁止访问");
        }
        chain.doFilter(request, response);
    }
}
