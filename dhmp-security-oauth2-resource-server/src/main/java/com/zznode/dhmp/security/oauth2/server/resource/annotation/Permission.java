package com.zznode.dhmp.security.oauth2.server.resource.annotation;

import org.springframework.core.annotation.AliasFor;

import java.lang.annotation.*;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/8/22
 */
@Target({ElementType.TYPE, ElementType.ANNOTATION_TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Permission {

    @AliasFor(attribute = "level")
    PermissionLevel value() default PermissionLevel.SECURITY;

    @AliasFor(attribute = "value")
    PermissionLevel level() default PermissionLevel.SECURITY;

    enum PermissionLevel {
        /**
         * 内部调用
         */
        INTERNAL,
        /**
         * 公共
         */
        PUBLIC,
        /**
         * 需要授权
         */
        SECURITY
    }
}
