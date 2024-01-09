package com.zznode.dhmp.security.oauth2.server.authorization.filter;

import com.zznode.dhmp.security.oauth2.server.authorization.context.LoginUserContextHolder;
import jakarta.servlet.*;

import java.io.IOException;

/**
 * 执行完之后清除程序中的ThreadLocal等数据,避免内存泄露
 *
 * @author 王俊
 * @date create in 2023/8/2 16:31
 */
public class ClearResourceFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        try {
            filterChain.doFilter(servletRequest, servletResponse);
        } finally {
            doClear();
        }
    }

    /**
     * 执行一些清理操作
     */
    private void doClear() {

        LoginUserContextHolder.clear();
    }

}
