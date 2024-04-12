package com.zznode.dhmp.security.oauth2.server.resource.authentication;

import com.zznode.dhmp.core.constant.InternalRequestHeaders;
import com.zznode.dhmp.security.oauth2.server.resource.annotation.Permission;
import com.zznode.dhmp.security.oauth2.server.resource.annotation.Permission.PermissionLevel;
import com.zznode.dhmp.web.client.InternalTokenManager;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.servlet.handler.MatchableHandlerMapping;

import java.util.function.Supplier;

/**
 * 接口权限认证检查
 *
 * @author 王俊
 * @date create in 2023/8/22
 * @see Permission
 */
public class PermissionAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final Log logger = LogFactory.getLog(PermissionAuthorizationManager.class);

    private final HandlerMappingIntrospector handlerMappingIntrospector;
    private final InternalTokenManager internalTokenManager;
    /**
     *
     */
    private final AuthorizationManager<RequestAuthorizationContext> delegate = new AuthenticatedAuthorizationManager<>();

    public PermissionAuthorizationManager(HandlerMappingIntrospector handlerMappingIntrospector, InternalTokenManager internalTokenManager) {
        this.handlerMappingIntrospector = handlerMappingIntrospector;
        this.internalTokenManager = internalTokenManager;
    }


    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext requestAuthorizationContext) {
        HttpServletRequest request = requestAuthorizationContext.getRequest();
        try {
            MatchableHandlerMapping mapping = handlerMappingIntrospector.getMatchableHandlerMapping(request);
            if (mapping == null) {
                return delegate.check(authentication, requestAuthorizationContext);
            }
            HandlerExecutionChain handlerExecutionChain = mapping.getHandler(request);
            if (handlerExecutionChain != null) {
                Object handler = handlerExecutionChain.getHandler();
                if (handler instanceof HandlerMethod handlerMethod) {
                    Permission permission = handlerMethod.getMethodAnnotation(Permission.class);
                    if (permission == null) {
                        permission = handlerMethod.getBeanType().getAnnotation(Permission.class);
                    }
                    if (permission != null) {
                        PermissionLevel level = permission.level();
                        return checkPermission(level, authentication, requestAuthorizationContext);
                    }
                }
            }
            // 没有找到对应的接口映射。
            // 同时又因为进入此方法的filter排名过后，排除使用filter作为请求端点的可能
            // (例如/oauth2/token之类的，直接在filter拦截了进行处理，但是那些filter排名都靠前)
            // 理应返回404
        } catch (Exception e) {
            logger.error("error occurred while ", e);
//            return new AuthorizationDecision(false);
        }
        // 如果没有找到映射、或者controller方法没用Permission注解标记等，使用默认的
        return delegate.check(authentication, requestAuthorizationContext);
    }

    protected AuthorizationDecision checkPermission(PermissionLevel level, Supplier<Authentication> authentication, RequestAuthorizationContext requestAuthorizationContext) {
        HttpServletRequest request = requestAuthorizationContext.getRequest();
        if (PermissionLevel.PUBLIC.equals(level)) {
            // 公共接口，可匿名访问
            return new AuthorizationDecision(true);
        }
        if (PermissionLevel.INTERNAL.equals(level)) {
            // 内部调用可以不用授权, 但是得判定是否从feign或者restTemplate调用
            // 检查InternalToken
            String internalRequestToken = request.getHeader(InternalRequestHeaders.INTERNAL_TOKEN);
            if (internalRequestToken != null && internalTokenManager.validate(internalRequestToken)) {
                return new AuthorizationDecision(true);
            }
        }
        // security check
        return delegate.check(authentication, requestAuthorizationContext);
    }

}
