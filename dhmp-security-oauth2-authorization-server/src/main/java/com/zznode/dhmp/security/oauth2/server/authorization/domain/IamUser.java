package com.zznode.dhmp.security.oauth2.server.authorization.domain;


import java.util.Date;

/**
 * 描述
 *
 * @author 王俊
 * @date create in 2023/8/17
 */
public class IamUser {

    public static final String DEFAULT_USER_TABLE_NAME = "iam_user";

    public static final String COL_USER_ID = "id";
    public static final String COL_USERNAME = "username";
    public static final String COL_PASSWORD = "password";
    public static final String COL_LOCKED_FLAG = "locked_flag";
    public static final String COL_DISABLED_FLAG = "disabled_flag";
    public static final String COL_LAST_LOCKED_DATE = "last_locked_date";
    public static final String COL_LAST_LOGIN_DATE = "last_login_date";
    public static final String COL_LAST_DISABLED_DATE = "last_disabled_date";
    public static final String COL_LICKED_COUNT = "locked_count";

    private Long userId;
    private String username;
    private String password;
    private Integer adminFlag;
    private String email;
    private String phone;
    private Integer gender;
    private String realName;
    private Integer userType;
    private Integer userLevel;
    private String placeCode;
    private Boolean locked;

    private Boolean disabled;

    private Date lastPasswordUpdatedDate;

    private Date lastLockedDate;

    private Date lastDisabledDate;

    private Integer lockedCount;

    private Date lastLoginDate;

    public Integer getStatus() {
        if (getLocked()) {
            return 1;
        } else if (getDisabled()) {
            return 2;
        }
        return 0;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Integer getAdminFlag() {
        return adminFlag;
    }

    public void setAdminFlag(Integer adminFlag) {
        this.adminFlag = adminFlag;
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

    public String getPlaceCode() {
        return placeCode;
    }

    public void setPlaceCode(String placeCode) {
        this.placeCode = placeCode;
    }

    public Boolean getLocked() {
        return locked;
    }

    public void setLocked(Boolean locked) {
        this.locked = locked;
    }

    public Boolean getDisabled() {
        return disabled;
    }

    public void setDisabled(Boolean disabled) {
        this.disabled = disabled;
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

    public Integer getLockedCount() {
        return lockedCount;
    }

    public void setLockedCount(Integer lockedCount) {
        this.lockedCount = lockedCount;
    }

    public Date getLastLoginDate() {
        return lastLoginDate;
    }

    public void setLastLoginDate(Date lastLoginDate) {
        this.lastLoginDate = lastLoginDate;
    }
}
