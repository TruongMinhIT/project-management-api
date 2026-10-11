package com.projectmgr.api.constant;

public class SecurityConstant {
    public static final String GRANT_TYPE_PASSWORD = "password";
    public static final String GRANT_TYPE_PASSWORD_MFA = "password_mfa";
    public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

    public static final String PARAMETER_USERNAME = "username";
    public static final String PARAMETER_PASSWORD = "password";
    public static final String PARAMETER_OTP = "otp";

    public static final String CLAIM_AUTHORITIES = "authorities";
    public static final String CLAIM_USER_NAME = "user_name";
    public static final String CLAIM_USER_ID = "user_id";
    public static final String CLAIM_ROLE = "role";
    public static final String CLAIM_GRANT_TYPE = "grant_type";
    public static final String CLAIM_VERSION = "version";
    public static final String CLAIM_ADDITIONAL_INFO = "additional_info";
    public static final String CLAIM_JTI = "jti";
    public static final String CLAIM_CLIENT_ID = "client_id";
    public static final String CLAIM_TOKEN_TYPE = "token_type";

    public static final String TOKEN_TYPE_REFRESH = "refresh";
    public static final String JWT_HEADER_TYPE = "JWT";

    public static final String TOKEN_FORCE_EXPIRED_MESSAGE = "Token has been force expired (version mismatch)";
}
