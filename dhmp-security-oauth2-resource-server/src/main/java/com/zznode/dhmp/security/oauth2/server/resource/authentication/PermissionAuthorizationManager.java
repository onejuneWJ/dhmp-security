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


    /**
     * 检查用户请求的授权。
     *
     * @param authentication              提供当前认证信息的供应商。
     * @param requestAuthorizationContext 请求授权的上下文，包含请求等信息。
     * @return AuthorizationDecision 返回授权决策，决定是否允许访问。
     */
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext requestAuthorizationContext) {
        HttpServletRequest request = requestAuthorizationContext.getRequest();
        try {
            // 尝试获取与请求匹配的处理器映射。
            MatchableHandlerMapping mapping = handlerMappingIntrospector.getMatchableHandlerMapping(request);
            if (mapping == null) {
                // 如果没有找到匹配的处理器映射，委托给下一个授权检查器进行检查。
                return delegate.check(authentication, requestAuthorizationContext);
            }
            // 获取请求对应的处理器执行链。
            HandlerExecutionChain handlerExecutionChain = mapping.getHandler(request);
            if (handlerExecutionChain == null) {
                logger.info("No handler found for request: " + request.getRequestURI());
                // 没有找到对应的处理器，理论上应该返回404或进行其他处理
                return new AuthorizationDecision(false);
            }
            // 获取实际的处理器对象。
            Object handler = handlerExecutionChain.getHandler();
            if (handler instanceof HandlerMethod handlerMethod) {
                // 尝试从处理器方法获取Permission注解。
                Permission permission = handlerMethod.getMethodAnnotation(Permission.class);
                if (permission == null) {
                    // 如果方法上没有，则尝试从处理器类上获取Permission注解。
                    permission = handlerMethod.getBeanType().getAnnotation(Permission.class);
                }
                if (permission != null) {
                    // 如果找到了Permission注解，则根据注解的level进行权限检查。
                    PermissionLevel level = permission.level();
                    return checkPermission(level, authentication, requestAuthorizationContext);
                }
                else {
                    logger.info("Permission annotation not found on handler: " + handlerMethod.getBean().getClass().getName());
                    // 没有找到Permission注解，记录日志并进行相应处理
                }
            }
            else {
                // 处理器不是HandlerMethod的实例，记录日志并进行相应处理
                logger.info("Handler is not an instance of HandlerMethod for request: " + request.getRequestURI());
            }
        } catch (Exception e) {
            // 处理检查过程中出现的异常。
            logger.error("Error occurred while checking authorization", e);
            // 根据异常类型或信息进行更详细的处理，这里仅为示例
        }
        // 如果没有找到映射或者没有通过权限检查，使用默认的授权决策。
        return delegate.check(authentication, requestAuthorizationContext);
    }


    protected AuthorizationDecision checkPermission(PermissionLevel level, Supplier<Authentication> authentication, RequestAuthorizationContext requestAuthorizationContext) {
        HttpServletRequest request = requestAuthorizationContext.getRequest();
        try {
            if (PermissionLevel.PUBLIC.equals(level)) {
                return decidePublicPermission();
            }
            if (PermissionLevel.INTERNAL.equals(level)) {
                return decideInternalPermission(request);
            }
            // 处理其他PermissionLevel，确保逻辑完整
            return decideOtherPermissions(authentication, requestAuthorizationContext);
        } catch (Exception e) {
            // 优化异常处理
            logger.error("Permission check failed", e);
            // 根据实际需求，下面可以返回一个拒绝访问的AuthorizationDecision或抛出自定义异常
            return new AuthorizationDecision(false);
        }
    }

    private AuthorizationDecision decidePublicPermission() {
        return new AuthorizationDecision(true);
    }

    private AuthorizationDecision decideInternalPermission(HttpServletRequest request) {
        String internalRequestToken = request.getHeader(InternalRequestHeaders.INTERNAL_TOKEN);
        if (internalRequestToken != null && internalTokenManager.validate(internalRequestToken)) {
            logger.info("Internal token validation successful");
            return new AuthorizationDecision(true);
        }
        else {
            logger.warn("Internal token validation failed");
            // 在这里处理验证失败的逻辑，例如记录日志、计数器等
        }
        return new AuthorizationDecision(false);
    }

    private AuthorizationDecision decideOtherPermissions(Supplier<Authentication> authentication, RequestAuthorizationContext requestAuthorizationContext) {
        // 这里委托给delegate进行安全检查
        return delegate.check(authentication, requestAuthorizationContext);
    }
}
