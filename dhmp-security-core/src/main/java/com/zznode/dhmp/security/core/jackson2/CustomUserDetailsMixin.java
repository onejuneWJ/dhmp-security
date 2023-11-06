package com.zznode.dhmp.security.core.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/8/7
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonDeserialize(using = CustomUserDetailsDeserializer.class)
@JsonInclude(value = JsonInclude.Include.NON_NULL)
@JsonAutoDetect()
@JsonIgnoreProperties(ignoreUnknown = true)
class CustomUserDetailsMixin {
}
