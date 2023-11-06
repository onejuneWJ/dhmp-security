package com.zznode.dhmp.security.core.jackson2;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.zznode.dhmp.security.core.CustomUserDetails;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/8/7
 */
public class DhmpOAuth2Jackson2Module extends SimpleModule {

    @Override
    public void setupModule(SetupContext context) {
        context.setMixInAnnotations(CustomUserDetails.class, CustomUserDetailsMixin.class);
    }
}
