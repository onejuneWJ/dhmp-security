package com.zznode.dhmp.security.oauth2.server.authorization.service.impl;


import com.zznode.dhmp.core.message.DhmpMessageSource;
import com.zznode.dhmp.security.core.CustomUserDetails;
import com.zznode.dhmp.security.oauth2.server.authorization.context.LoginUserContextHolder;
import com.zznode.dhmp.security.oauth2.server.authorization.domain.UserDTO;
import com.zznode.dhmp.security.oauth2.server.authorization.service.UserAccountManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

import java.util.List;
import java.util.stream.Collectors;

/**
 * 用户
 *
 * @author 王俊
 * @date create in 2023/4/27
 */
public class CustomUserDetailsManager implements UserDetailsManager, MessageSourceAware {

    private final Log logger = LogFactory.getLog(CustomUserDetailsManager.class);

    private MessageSourceAccessor messages = DhmpMessageSource.getAccessor();

    private final UserAccountManager userAccountManager;

    public CustomUserDetailsManager(UserAccountManager userAccountManager) {
        this.userAccountManager = userAccountManager;
    }


    protected List<GrantedAuthority> loadUserAuthorities(Long userId) {
        return userAccountManager.getUserRoles(userId).stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 缓存正在登录的用户信息
        LoginUserContextHolder.setCurrentLoginUser(new CustomUserDetails(username));
        UserDTO user = userAccountManager.getByUsername(username);
        if (user == null) {
            this.logger.debug("Query returned no results for user '" + username + "'");
            throw new UsernameNotFoundException(this.messages.getMessage("JdbcDaoImpl.notFound",
                    new Object[]{username}, "Username {0} not found"));
        }
        List<GrantedAuthority> grantedAuthorities = loadUserAuthorities(user.getUserId());
        if (grantedAuthorities.isEmpty()) {
            this.logger.debug("User '" + username + "' has no authorities and will be treated as 'not found'");
            throw new UsernameNotFoundException(this.messages.getMessage("JdbcDaoImpl.noAuthority",
                    new Object[]{username}, "User {0} has no GrantedAuthority"));
        }
        CustomUserDetails userDetails = mapToCustomUserDetails(user, grantedAuthorities);
        // 更新完整缓存信息
        LoginUserContextHolder.setCurrentLoginUser(userDetails);
        return userDetails;
    }

    public CustomUserDetails mapToCustomUserDetails(UserDTO userDTO, List<GrantedAuthority> grantedAuthorities) {
        boolean enabledFlag = !userDTO.getDisabled();
        boolean unLockedFlag = !userDTO.getLocked();
        CustomUserDetails customUserDetails = new CustomUserDetails(userDTO.getUsername(), userDTO.getPassword(),
                enabledFlag, true, true, unLockedFlag, grantedAuthorities);
        BeanUtils.copyProperties(userDTO, customUserDetails);
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
