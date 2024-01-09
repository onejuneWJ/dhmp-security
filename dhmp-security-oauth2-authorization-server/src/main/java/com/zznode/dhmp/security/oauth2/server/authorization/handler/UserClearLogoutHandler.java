package com.zznode.dhmp.security.oauth2.server.authorization.handler;

import com.zznode.dhmp.security.core.CustomUserDetails;
import com.zznode.dhmp.security.core.constants.OAuth2RedisKeys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * 处理用户信息，登出处理器
 * <p>登出后，删除redis用户缓存
 * <p>
 *
 * @author 王俊
 * @date create in 2023/8/8
 */
public class UserClearLogoutHandler implements LogoutHandler {

    private final RedisTemplate<Object, Object> redisTemplate;

    public UserClearLogoutHandler(RedisTemplate<Object, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof CustomUserDetails customUserDetails) {
            String username = customUserDetails.getUsername();
            HashOperations<Object, Object, Object> hashOperations = redisTemplate.opsForHash();
            hashOperations.delete(OAuth2RedisKeys.LOGIN_USER, username);
        }
    }
}
