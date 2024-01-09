package com.zznode.dhmp.security.oauth2.server.authorization.service;

import com.zznode.dhmp.security.oauth2.server.authorization.domain.IamUser;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/8/22
 */
public interface UserAccountManager {

    /**
     * 锁定账号
     *
     * @param userId 用户id
     * @return 锁定次数
     */
    Integer lockAccount(Long userId);

    /**
     * 解锁账号
     *
     * @param userId 用户id
     */
    void unlockAccount(Long userId);

    /**
     * 禁用账号
     *
     * @param userId 用户id
     */
    void disableAccount(Long userId);

    /**
     * 根据用户名查询用户
     *
     * @param username 用户名
     * @return 用户
     */
    IamUser getByUsername(String username);

    /**
     * 登录记录
     *
     * @param userId 账号id
     */
    void loginRecord(Long userId);
}
