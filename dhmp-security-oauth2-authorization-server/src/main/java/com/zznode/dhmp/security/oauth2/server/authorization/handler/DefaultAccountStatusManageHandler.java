package com.zznode.dhmp.security.oauth2.server.authorization.handler;

import com.zznode.dhmp.core.message.DhmpMessageSource;
import com.zznode.dhmp.security.core.CustomUserDetails;
import com.zznode.dhmp.security.oauth2.server.authorization.DhmpOAuth2AuthorizationServerProperties;
import com.zznode.dhmp.security.oauth2.server.authorization.constants.ErrorCodes;
import com.zznode.dhmp.security.oauth2.server.authorization.context.LoginUserContextHolder;
import com.zznode.dhmp.security.oauth2.server.authorization.service.UserAccountManager;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;

import static com.zznode.dhmp.security.core.constants.OAuth2RedisKeys.PASSWORD_ERROR_COUNT_KEY;


/**
 * 账号管控默认实现
 *
 * @author 王俊
 * @date create in 2023/8/2 11:23
 */
public class DefaultAccountStatusManageHandler implements AccountStatusManageHandler, MessageSourceAware {

    private final DhmpOAuth2AuthorizationServerProperties.AccountManagement accountManagement;

    private MessageSourceAccessor messages = DhmpMessageSource.getAccessor();

    private final UserAccountManager userAccountManager;

    private final RedisTemplate<Object, Object> redisTemplate;


    public DefaultAccountStatusManageHandler(DhmpOAuth2AuthorizationServerProperties.AccountManagement accountManagement,
                                             UserAccountManager userAccountManager,
                                             RedisTemplate<Object, Object> redisTemplate) {
        this.accountManagement = accountManagement;
        this.userAccountManager = userAccountManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public AuthenticationException handle(AuthenticationException exception) {
        CustomUserDetails userDetails = LoginUserContextHolder.getCurrentLoginUser();
        if (exception instanceof BadCredentialsException badCredentialsException) {
            return handleBadCredentialsException(userDetails, badCredentialsException);
        }
        return exception;
    }

    protected AuthenticationException handleBadCredentialsException(CustomUserDetails userDetails, BadCredentialsException exception) {
        String username = userDetails.getUsername();
        Long userId = userDetails.getUserId();
        // 用户ID存在，则用户存在
        boolean userExists = userId != null;
        ValueOperations<Object, Object> valueOperations = redisTemplate.opsForValue();
        String passwordErrorCountKey = passwordErrorCountKey(username);
        // 检查密码输入错误次数,超过错误次数锁定账号
        Long errorCount = valueOperations
                .increment(passwordErrorCountKey);
        if (errorCount != null && errorCount >= accountManagement.getPasswordAllowErrorCount()) {
            if (!userExists) {
                // 如果用户不存在,不执行锁定和禁用
                redisTemplate.expire(passwordErrorCountKey, accountManagement.getAccountAutoUnlockDuration());
                return exception;
            }
            Integer lockedCount = userAccountManager.lockAccount(userId);
            // todo 到时间自动接触锁定
            // 重置密码输入错误次数
            redisTemplate.delete(passwordErrorCountKey);
            // 检查锁定次数
            int accountDisableOverLockCount = accountManagement.getAccountDisableOverLockCount();
            if (accountDisableOverLockCount > 0 && lockedCount >= accountDisableOverLockCount) {
                // 锁定次数过多, 将禁用账号
                userAccountManager.disableAccount(userId);
                return new DisabledException(
                        this.messages.getMessage(ErrorCodes.ACCOUNT_DISABLED, "账号被锁定次数过多, 账号已被禁用")
                );
            }

            return new LockedException(
                    this.messages.getMessage(ErrorCodes.ACCOUNT_LOCKED, "密码输入次数过多, 账号已被锁定")
            );
        }
        return exception;
    }

    protected String passwordErrorCountKey(String username) {
        return PASSWORD_ERROR_COUNT_KEY + ":" + username;
    }

    @Override
    public void setMessageSource(@NonNull MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

}
