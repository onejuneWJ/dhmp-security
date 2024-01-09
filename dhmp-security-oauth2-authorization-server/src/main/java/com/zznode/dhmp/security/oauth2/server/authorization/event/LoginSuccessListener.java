package com.zznode.dhmp.security.oauth2.server.authorization.event;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zznode.dhmp.security.core.CustomUserDetails;
import com.zznode.dhmp.security.core.jackson2.DhmpOAuth2Jackson2Module;
import com.zznode.dhmp.security.oauth2.server.authorization.service.UserAccountManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;

import static com.zznode.dhmp.security.core.constants.OAuth2RedisKeys.LOGIN_USER;
import static com.zznode.dhmp.security.core.constants.OAuth2RedisKeys.PASSWORD_ERROR_COUNT_KEY;


/**
 * 登录成功监听，
 *
 * @author 王俊
 * @date create in 2023/8/4
 */
public class LoginSuccessListener implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {

    private final Logger logger = LoggerFactory.getLogger(LoginSuccessListener.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final RedisTemplate<Object, Object> redisTemplate;

    private final UserAccountManager userAccountManager;


    public LoginSuccessListener(RedisTemplate<Object, Object> redisTemplate, UserAccountManager userAccountManager) {
        this.redisTemplate = redisTemplate;
        this.userAccountManager = userAccountManager;
        this.objectMapper.registerModule(new DhmpOAuth2Jackson2Module());
    }

    @Override
    public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) event.getAuthentication();
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        saveUserLoginRecord(customUserDetails);
        resetLoginState(customUserDetails);
    }

    protected void saveUserLoginRecord(CustomUserDetails customUserDetails) {
        userAccountManager.loginRecord(customUserDetails.getUserId());
        try {
            String userDetailsString = this.objectMapper.writeValueAsString(customUserDetails);
            redisTemplate.opsForHash().put(LOGIN_USER, customUserDetails.getUsername(), userDetailsString);
        } catch (Exception e) {
            logger.error("error serialize.", e);
        }
    }

    protected void resetLoginState(CustomUserDetails customUserDetails) {
        String username = customUserDetails.getUsername();
        // 清空密码输入错误次数(如果开启了账号管控)
        redisTemplate.delete(PASSWORD_ERROR_COUNT_KEY + ":" + username);
    }
}
