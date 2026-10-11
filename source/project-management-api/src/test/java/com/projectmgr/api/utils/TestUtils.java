package com.projectmgr.api.utils;

import com.projectmgr.api.jwt.BaseJwt;

public final class TestUtils {

    private TestUtils() {
    }

    public static BaseJwt superAdminJwt() {
        BaseJwt jwt = new BaseJwt();
        jwt.setIsSuperAdmin(true);
        return jwt;
    }

    public static BaseJwt superAdminJwt(long accountId) {
        BaseJwt jwt = new BaseJwt();
        jwt.setAccountId(accountId);
        jwt.setIsSuperAdmin(true);
        return jwt;
    }

    public static BaseJwt notSuperAdminJwt() {
        BaseJwt jwt = new BaseJwt();
        jwt.setIsSuperAdmin(false);
        return jwt;
    }

    public static BaseJwt jwtWithRole(Integer role) {
        BaseJwt jwt = new BaseJwt();
        jwt.setRole(role);
        return jwt;
    }
}
