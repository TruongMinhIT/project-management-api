package com.projectmgr.api.config;

import com.projectmgr.api.constant.DatabaseConstant;
import com.projectmgr.api.dto.AccountForTokenDto;
import com.projectmgr.api.utils.ZipUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.projectmgr.api.constant.SecurityConstant.*;

@Component
public class CustomTokenEnhancer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private static final String DELIM = "|";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Value("${jwt.version}")
    private Integer currentVersion;

    @Override
    public void customize(JwtEncodingContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return;
        }
        context.getJwsHeader().algorithm(MacAlgorithm.HS256).type(JWT_HEADER_TYPE);
        context.getClaims().claim(CLAIM_VERSION, currentVersion).claim(CLAIM_CLIENT_ID, context.getRegisteredClient().getClientId());

        String grantType = context.getAuthorizationGrantType().getValue();
        if (!CustomTokenGranter.GRANT_TYPES.contains(grantType)) {
            return;
        }
        String username = context.getPrincipal().getName();
        AccountForTokenDto account = getAccountByUsername(username);
        if (account == null) {
            return;
        }
        context.getClaims()
                .claim(CLAIM_USER_NAME, username)
                .claim(CLAIM_AUTHORITIES, authorityNames(context.getPrincipal().getAuthorities()));
        getAdditionalInfo(grantType, account, username).forEach(context.getClaims()::claim);
    }

    /**
     * The claims each grant type adds. A grant with its own claims gets its own method here.
     */
    private Map<String, Object> getAdditionalInfo(String grantType, AccountForTokenDto account, String username) {
        switch (grantType) {
            case GRANT_TYPE_PASSWORD:
                return getAdditionalInfoForAccount(account, username, GRANT_TYPE_PASSWORD);
            case GRANT_TYPE_PASSWORD_MFA:
                return getAdditionalInfoForAccount(account, username, GRANT_TYPE_PASSWORD_MFA);
            default:
                return Map.of();
        }
    }

    private static Map<String, Object> getAdditionalInfoForAccount(AccountForTokenDto a, String username, String grantType) {
        Long restaurantId = -1L;
        String kind = a.getRole() + ""; // token kind
        Long deviceId = -1L;
        String permission = "<>";
        Integer role = a.getRole();
        Integer tabletKind = -1;
        Long orderId = -1L;
        String tenantId = "<>";

        Map<String, Object> additionalInfo = new LinkedHashMap<>();
        additionalInfo.put(CLAIM_USER_ID, a.getId());
        additionalInfo.put(CLAIM_ROLE, a.getRole());
        additionalInfo.put(CLAIM_GRANT_TYPE, grantType);
        additionalInfo.put(CLAIM_ADDITIONAL_INFO, ZipUtils.zipString(a.getId() + DELIM
                + restaurantId + DELIM
                + kind + DELIM
                + permission + DELIM
                + deviceId + DELIM
                + role + DELIM
                + username + DELIM
                + tabletKind + DELIM
                + orderId + DELIM
                + a.getIsSuperAdmin() + DELIM
                + tenantId));
        return additionalInfo;
    }

    private static List<String> authorityNames(Collection<? extends GrantedAuthority> authorities) {
        return List.copyOf(AuthorityUtils.authorityListToSet(authorities));
    }

    private AccountForTokenDto getAccountByUsername(String username) {
        String sql = """
                SELECT id, role, username, email, full_name, is_super_admin
                FROM %saccount
                WHERE username = ? AND status = 1
                LIMIT 1
                """.formatted(DatabaseConstant.PREFIX_TABLE);
        List<AccountForTokenDto> rows = jdbcTemplate.query(
                sql, new BeanPropertyRowMapper<>(AccountForTokenDto.class), username);
        return rows.isEmpty() ? null : rows.get(0);
    }
}
