package com.zznode.dhmp.security.oauth2.server.authorization.service.impl;


import com.zznode.dhmp.security.oauth2.server.authorization.domain.IamUser;
import com.zznode.dhmp.security.oauth2.server.authorization.service.UserAccountManager;
import org.springframework.web.client.RestClient;

/**
 * 默认远程调用iam服务
 *
 * @author 王俊
 * @date create in 2023/8/22
 */

public class DefaultUserAccountManager implements UserAccountManager {

    private final RestClient restClient;

    private String iamAddr;

    public DefaultUserAccountManager(RestClient restClient) {
        this.restClient = restClient;
    }

    public void setIamAddr(String iamAddr) {
        this.iamAddr = iamAddr;
    }

    @Override
    public Integer lockAccount(Long userId) {
        return restClient.post()
                .uri(iamAddr, uriBuilder -> uriBuilder.path("/v1/users/account/lock/{userId}").build(userId))
                .retrieve()
                .body(Integer.class);
    }

    @Override
    public void unlockAccount(Long userId) {
        restClient.post()
                .uri(iamAddr, uriBuilder -> uriBuilder.path("/v1/users/account/unlock/{userId}").build(userId))
                .retrieve();
    }

    @Override
    public void disableAccount(Long userId) {
        restClient.post()
                .uri(iamAddr, uriBuilder -> uriBuilder.path("/v1/users/account/disable/{userId}").build(userId))
                .retrieve();
    }

    @Override
    public IamUser getByUsername(String username) {
        return restClient.get()
                .uri(iamAddr, uriBuilder -> uriBuilder
                        .path("/v1/users/internal/by-username")
                        .queryParam("username", username)
                        .build()
                )
                .retrieve()
                .body(IamUser.class);
    }

    @Override
    public void loginRecord(Long userId) {

    }
}
