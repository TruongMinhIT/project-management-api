package com.projectmgr.api.config;

import com.projectmgr.api.constant.BaseConstant;
import com.projectmgr.api.constant.SecurityConstant;
import com.projectmgr.api.dto.AccountForTokenDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Real signing and verification: {@link JwtGenerator} + {@link CustomTokenEnhancer} sign, {@link JwtConfig#jwtDecoder}
 * verifies, {@link SecurityConfig#jwtAuthenticationConverter} turns the token into authorities.
 */
@ExtendWith(MockitoExtension.class)
class JwtTokenTest {
    private static final String SIGNING_KEY = "0123456789abcdef0123456789abcdef";
    private static final String USERNAME = "admin";
    private static final Long USER_ID = 9001L;
    private static final AuthorizationServerContext SERVER_CONTEXT = mock(AuthorizationServerContext.class);
    private static final RegisteredClient CLIENT = RegisteredClient.withId("abc_client")
            .clientId("abc_client")
            .clientSecret("{noop}abc123")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD))
            .authorizationGrantType(new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD_MFA))
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .build();

    @Mock
    private JdbcTemplate jdbcTemplate;

    private CustomTokenEnhancer tokenEnhancer;

    @BeforeEach
    void setUp() {
        tokenEnhancer = new CustomTokenEnhancer();
        ReflectionTestUtils.setField(tokenEnhancer, "jdbcTemplate", jdbcTemplate);
        ReflectionTestUtils.setField(tokenEnhancer, "currentVersion", 1);
    }

    @Test
    void passwordTokenCarriesTheAccountClaimsAndAuthoritiesForHasRole() {
        stubAccount();

        Jwt jwt = decoder(1).decode(issue(SecurityConstant.GRANT_TYPE_PASSWORD, "ROLE_ACC_V", "ROLE_ACC_D"));
        AbstractAuthenticationToken authentication = SecurityConfig.jwtAuthenticationConverter().convert(jwt);

        assertThat(jwt.getHeaders()).containsEntry("alg", "HS256").containsEntry("typ", SecurityConstant.JWT_HEADER_TYPE);
        assertThat(authentication.getName()).isEqualTo(USERNAME);
        assertThat(AuthorityUtils.authorityListToSet(authentication.getAuthorities()))
                .containsExactlyInAnyOrder("ROLE_ACC_V", "ROLE_ACC_D");
        assertThat(jwt.getClaims())
                .containsEntry(SecurityConstant.CLAIM_VERSION, 1L)
                .containsEntry(SecurityConstant.CLAIM_CLIENT_ID, "abc_client")
                .containsEntry(SecurityConstant.CLAIM_USER_ID, USER_ID)
                .containsEntry(SecurityConstant.CLAIM_ROLE, 1L)
                .containsEntry(SecurityConstant.CLAIM_GRANT_TYPE, SecurityConstant.GRANT_TYPE_PASSWORD)
                .containsKey(SecurityConstant.CLAIM_ADDITIONAL_INFO);
    }

    @Test
    void passwordMfaTokenNamesItsOwnGrantType() {
        stubAccount();

        Jwt jwt = decoder(1).decode(issue(SecurityConstant.GRANT_TYPE_PASSWORD_MFA, "ROLE_ACC_V"));

        assertThat(jwt.getClaimAsString(SecurityConstant.CLAIM_GRANT_TYPE)).isEqualTo(SecurityConstant.GRANT_TYPE_PASSWORD_MFA);
    }

    @Test
    void clientCredentialsTokenHasVersionAndClientIdButNoUserClaims() {
        Jwt jwt = decoder(1).decode(issue(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()));

        assertThat(jwt.getClaims())
                .containsEntry(SecurityConstant.CLAIM_VERSION, 1L)
                .containsEntry(SecurityConstant.CLAIM_CLIENT_ID, "abc_client")
                .doesNotContainKeys(SecurityConstant.CLAIM_AUTHORITIES, SecurityConstant.CLAIM_USER_ID);
        verifyNoInteractions(jdbcTemplate);
    }

    @Test
    void tokenOlderThanJwtVersionIsRejected() {
        stubAccount();
        String token = issue(SecurityConstant.GRANT_TYPE_PASSWORD, "ROLE_ACC_V");

        assertThatThrownBy(() -> decoder(2).decode(token))
                .isInstanceOf(JwtValidationException.class)
                .hasMessageContaining(SecurityConstant.TOKEN_FORCE_EXPIRED_MESSAGE);
    }

    @Test
    void refreshTokenIsASignedJwtReadOnlyByTheRefreshDecoder() {
        String refreshToken = issueRefreshToken(1);
        JwtConfig config = jwtConfig(SIGNING_KEY, 1);

        Jwt jwt = config.refreshTokenDecoder(config.jwtSigningKey()).decode(refreshToken);

        assertThat(jwt.getHeaders()).containsEntry("alg", "HS256").containsEntry("typ", SecurityConstant.JWT_HEADER_TYPE);
        assertThat(jwt.getClaims())
                .containsEntry(SecurityConstant.CLAIM_TOKEN_TYPE, SecurityConstant.TOKEN_TYPE_REFRESH)
                .containsEntry(SecurityConstant.CLAIM_USER_NAME, USERNAME)
                .containsEntry(SecurityConstant.CLAIM_CLIENT_ID, "abc_client")
                .containsEntry(SecurityConstant.CLAIM_GRANT_TYPE, SecurityConstant.GRANT_TYPE_PASSWORD_MFA)
                .containsEntry(SecurityConstant.CLAIM_VERSION, 1L);
        assertThat(jwt.getClaimAsStringList("scope")).containsExactly("read");
        assertThatThrownBy(() -> decoder(1).decode(refreshToken))
                .isInstanceOf(JwtValidationException.class)
                .hasMessageContaining("cannot be used as an access token");
    }

    @Test
    void accessTokenIsNotAcceptedAsRefreshToken() {
        stubAccount();
        String accessToken = issue(SecurityConstant.GRANT_TYPE_PASSWORD, "ROLE_ACC_V");
        JwtConfig config = jwtConfig(SIGNING_KEY, 1);

        assertThatThrownBy(() -> config.refreshTokenDecoder(config.jwtSigningKey()).decode(accessToken))
                .isInstanceOf(JwtValidationException.class)
                .hasMessageContaining("Not a refresh token");
    }

    @Test
    void refreshTokenOlderThanJwtVersionIsRejected() {
        String refreshToken = issueRefreshToken(1);
        JwtConfig config = jwtConfig(SIGNING_KEY, 2);

        assertThatThrownBy(() -> config.refreshTokenDecoder(config.jwtSigningKey()).decode(refreshToken))
                .isInstanceOf(JwtValidationException.class)
                .hasMessageContaining(SecurityConstant.TOKEN_FORCE_EXPIRED_MESSAGE);
    }

    @Test
    void signingKeyShorterThan32BytesFailsAtStartup() {
        assertThatThrownBy(jwtConfig("T7PfKrPGvK", 1)::jwtSigningKey)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("at least 32 bytes");
    }

    private String issue(String grantType, String... authorities) {
        List<GrantedAuthority> granted = AuthorityUtils.createAuthorityList(authorities);
        Authentication principal = UsernamePasswordAuthenticationToken.authenticated(
                new User(USERNAME, "", granted), null, granted);
        JwtConfig config = jwtConfig(SIGNING_KEY, 1);
        JwtGenerator generator = new JwtGenerator(config.jwtEncoder(config.jwkSource(config.jwtSigningKey())));
        generator.setJwtCustomizer(tokenEnhancer);
        Jwt jwt = generator.generate(DefaultOAuth2TokenContext.builder()
                .registeredClient(CLIENT)
                .authorizationServerContext(SERVER_CONTEXT)
                .principal(principal)
                .authorizedScopes(Set.of())
                .authorizationGrantType(new AuthorizationGrantType(grantType))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build());
        assertThat(jwt).isNotNull();
        return jwt.getTokenValue();
    }

    private static String issueRefreshToken(int version) {
        AuthorizationServerConfig authorizationServerConfig = new AuthorizationServerConfig();
        ReflectionTestUtils.setField(authorizationServerConfig, "currentVersion", version);
        JwtConfig config = jwtConfig(SIGNING_KEY, version);
        List<GrantedAuthority> granted = AuthorityUtils.createAuthorityList("ROLE_ACC_V");
        OAuth2RefreshToken refreshToken = authorizationServerConfig
                .refreshTokenGenerator(config.jwtEncoder(config.jwkSource(config.jwtSigningKey())))
                .generate(DefaultOAuth2TokenContext.builder()
                        .registeredClient(CLIENT)
                        .authorizationServerContext(SERVER_CONTEXT)
                        .principal(UsernamePasswordAuthenticationToken.authenticated(new User(USERNAME, "", granted), null, granted))
                        .authorizedScopes(Set.of("read"))
                        .authorizationGrantType(new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD_MFA))
                        .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                        .build());
        assertThat(refreshToken).isNotNull();
        return refreshToken.getTokenValue();
    }

    @SuppressWarnings("unchecked")
    private void stubAccount() {
        AccountForTokenDto account = new AccountForTokenDto();
        account.setId(USER_ID);
        account.setRole(BaseConstant.ACCOUNT_ROLE_ADMIN);
        account.setUsername(USERNAME);
        account.setIsSuperAdmin(false);
        when(jdbcTemplate.query(anyString(), any(RowMapper.class), eq(USERNAME))).thenReturn(List.of(account));
    }

    private static JwtDecoder decoder(int currentVersion) {
        JwtConfig config = jwtConfig(SIGNING_KEY, currentVersion);
        return config.jwtDecoder(config.jwtSigningKey());
    }

    private static JwtConfig jwtConfig(String signingKey, int currentVersion) {
        JwtConfig config = new JwtConfig();
        ReflectionTestUtils.setField(config, "signingKey", signingKey);
        ReflectionTestUtils.setField(config, "currentVersion", currentVersion);
        return config;
    }
}
