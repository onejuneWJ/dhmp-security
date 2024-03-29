package com.zznode.dhmp.security.oauth2.server.authorization.service.impl;


import com.zznode.dhmp.core.message.DhmpMessageSource;
import com.zznode.dhmp.security.core.CustomUserDetails;
import com.zznode.dhmp.security.oauth2.server.authorization.context.LoginUserContextHolder;
import com.zznode.dhmp.security.oauth2.server.authorization.domain.IamUser;
import com.zznode.dhmp.security.oauth2.server.authorization.service.UserAccountManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.ArrayList;
import java.util.List;

/**
 * 用户
 *
 * @author 王俊
 * @date create in 2023/4/27
 */
public class CustomUserDetailsManager implements UserDetailsManager, MessageSourceAware {

    private final Logger logger = LoggerFactory.getLogger(CustomUserDetailsManager.class);

    private MessageSourceAccessor messages = DhmpMessageSource.getAccessor();

    private final UserAccountManager userAccountManager;

    public CustomUserDetailsManager(UserAccountManager userAccountManager) {
        this.userAccountManager = userAccountManager;
    }


    protected List<GrantedAuthority> loadUserAuthorities(String username) {
        // todo 暂时写死
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("read"));
        authorities.add(new SimpleGrantedAuthority("write"));
        authorities.add(new SimpleGrantedAuthority("common"));
        return authorities;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 缓存正在登录的用户信息
        LoginUserContextHolder.setCurrentLoginUser(new CustomUserDetails(username));
        IamUser user = userAccountManager.getByUsername(username);
        if (user == null) {
            this.logger.debug("Query returned no results for user '" + username + "'");
            throw new UsernameNotFoundException(this.messages.getMessage("JdbcDaoImpl.notFound",
                    new Object[]{username}, "Username {0} not found"));
        }
        List<GrantedAuthority> grantedAuthorities = loadUserAuthorities(user.getUsername());
        CustomUserDetails userDetails = mapToCustomUserDetails(user, grantedAuthorities);
        // 更新完整缓存信息
        LoginUserContextHolder.setCurrentLoginUser(userDetails);
        return userDetails;
    }

    public CustomUserDetails mapToCustomUserDetails(IamUser iamUser, List<GrantedAuthority> grantedAuthorities) {
        boolean enabledFlag = !iamUser.getDisabled();
        boolean unLockedFlag = !iamUser.getLocked();
        CustomUserDetails customUserDetails = new CustomUserDetails(iamUser.getUsername(), iamUser.getPassword(),
                enabledFlag, true, true, unLockedFlag, grantedAuthorities);
        BeanUtils.copyProperties(iamUser, customUserDetails);
        return customUserDetails;
    }

    @Override
    public void createUser(UserDetails user) {

    }

    @Override
    public void updateUser(UserDetails user) {

    }

    @Override
    public void deleteUser(String username) {

    }

    @Override
    public void changePassword(String oldPassword, String newPassword) {

    }

    @Override
    public boolean userExists(String username) {

        return false;
    }

    @Override
    public void setMessageSource(@NonNull MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }
}
