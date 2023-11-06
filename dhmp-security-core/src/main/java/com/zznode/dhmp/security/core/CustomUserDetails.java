package com.zznode.dhmp.security.core;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.zznode.dhmp.security.core.constants.BaseConstants;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Date;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/6/13 11:22
 */
public class CustomUserDetails extends User {

    private Long userId;
    /**
     * 所属地市
     */
    private String placeCode;
    /**
     * 用户类型(家客、集客)
     */
    private Integer userType;
    /**
     * 用户级别，1：全省用户，2：地市用户
     */
    private Integer userLevel;
    private String email;
    private String phone;
    private Integer gender;
    private String realName;
    private String avatar;

    private Date lastPasswordUpdatedDate;
    private Date lastLockedDate;
    private Date lastDisabledDate;
    private Date lastLoginDate;
    /**
     * 是否管理员用户
     */
    private Integer adminFlag;

    public CustomUserDetails(String username) {
        this(username, "");
    }

    public CustomUserDetails(String username, String password) {
        this(username, password, AuthorityUtils.NO_AUTHORITIES);
    }

    public CustomUserDetails(String username, String password, boolean enabled, boolean accountNonExpired,
                             boolean credentialsNonExpired, boolean accountNonLocked,
                             Collection<? extends GrantedAuthority> authorities) {

        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }


    public static CustomUserDetails anonymousUser(){
        return new CustomUserDetails(BaseConstants.ANONYMOUS_USER_NAME);
    }

    @JsonIgnore
    public boolean isAdmin() {
        return adminFlag != null && adminFlag == 1;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getPlaceCode() {
        return placeCode;
    }

    public void setPlaceCode(String placeCode) {
        this.placeCode = placeCode;
    }

    public Integer getUserType() {
        return userType;
    }

    public void setUserType(Integer userType) {
        this.userType = userType;
    }

    public Integer getUserLevel() {
        return userLevel;
    }

    public void setUserLevel(Integer userLevel) {
        this.userLevel = userLevel;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public Integer getGender() {
        return gender;
    }

    public void setGender(Integer gender) {
        this.gender = gender;
    }

    public String getRealName() {
        return realName;
    }

    public void setRealName(String realName) {
        this.realName = realName;
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }

    public Date getLastPasswordUpdatedDate() {
        return lastPasswordUpdatedDate;
    }

    public void setLastPasswordUpdatedDate(Date lastPasswordUpdatedDate) {
        this.lastPasswordUpdatedDate = lastPasswordUpdatedDate;
    }

    public Date getLastLockedDate() {
        return lastLockedDate;
    }

    public void setLastLockedDate(Date lastLockedDate) {
        this.lastLockedDate = lastLockedDate;
    }

    public Date getLastDisabledDate() {
        return lastDisabledDate;
    }

    public void setLastDisabledDate(Date lastDisabledDate) {
        this.lastDisabledDate = lastDisabledDate;
    }

    public Date getLastLoginDate() {
        return lastLoginDate;
    }

    public void setLastLoginDate(Date lastLoginDate) {
        this.lastLoginDate = lastLoginDate;
    }

    public Integer getAdminFlag() {
        return adminFlag;
    }

    public void setAdminFlag(Integer adminFlag) {
        this.adminFlag = adminFlag;
    }

    public String simpleUserInfo() {
        return "CustomUserDetails{" +
                "userId=" + userId +
                ", username=" + getUsername();
    }
}
