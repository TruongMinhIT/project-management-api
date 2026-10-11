package com.projectmgr.api.config.security;

import com.projectmgr.api.config.CustomTokenGranter;
import com.projectmgr.api.constant.SecurityConstant;
import com.projectmgr.api.dto.ErrorCode;
import com.projectmgr.api.exception.BadRequestException;
import com.projectmgr.api.service.impl.UserServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomTokenGranterTest {
    private static final String USERNAME = "admin";

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserServiceImpl userService;

    @Mock
    private OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

    @Mock
    private JwtDecoder refreshTokenDecoder;

    private CustomTokenGranter granter;

    @BeforeEach
    void setUp() {
        AuthorizationServerContextHolder.setContext(mock(AuthorizationServerContext.class));
        granter = new CustomTokenGranter(authenticationManager, userService, tokenGenerator, refreshTokenDecoder);
    }

    @Test
    void clientAllowedToRefreshAlsoGetsARefreshToken() {
        when(authenticationManager.authenticate(any())).thenReturn(authenticatedUser());
        stubTokenGeneratorPerType();

        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken) granter.authenticate(
                new CustomTokenGranter.GrantToken(new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD),
                        clientPrincipal(refreshingClient()), parameters(null)));

        assertThat(result.getAccessToken().getTokenValue()).isEqualTo("access");
        assertThat(result.getRefreshToken().getTokenValue()).isEqualTo("refresh");
    }

    @Test
    void refreshReloadsTheUserAndKeepsTheLoginGrant() {
        when(refreshTokenDecoder.decode("refresh")).thenReturn(refreshJwt("abc_client"));
        when(userService.loadUserByUsername(USERNAME))
                .thenReturn(new User(USERNAME, "", AuthorityUtils.createAuthorityList("ROLE_NEW_PERMISSION")));
        stubTokenGeneratorPerType();

        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken) granter.authenticate(refreshGrant());

        assertThat(result.getRefreshToken()).isNotNull();
        ArgumentCaptor<OAuth2TokenContext> context = ArgumentCaptor.forClass(OAuth2TokenContext.class);
        verify(tokenGenerator, times(2)).generate(context.capture());
        OAuth2TokenContext accessTokenContext = context.getAllValues().get(0);
        assertThat(accessTokenContext.getAuthorizationGrantType().getValue()).isEqualTo(SecurityConstant.GRANT_TYPE_PASSWORD_MFA);
        assertThat(AuthorityUtils.authorityListToSet(accessTokenContext.<Authentication>getPrincipal().getAuthorities()))
                .containsExactly("ROLE_NEW_PERMISSION");
        verifyNoInteractions(authenticationManager);
    }

    @Test
    void refreshTokenOfAnotherClientIsInvalidGrant() {
        when(refreshTokenDecoder.decode("refresh")).thenReturn(refreshJwt("other_client"));

        assertThatThrownBy(() -> granter.authenticate(refreshGrant()))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e ->
                        assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
        verifyNoInteractions(userService, tokenGenerator);
    }

    @Test
    void rejectedRefreshTokenIsInvalidGrantWithTheValidatorMessage() {
        OAuth2Error forceExpired = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, SecurityConstant.TOKEN_FORCE_EXPIRED_MESSAGE, null);
        when(refreshTokenDecoder.decode("refresh"))
                .thenThrow(new JwtValidationException("rejected", List.of(forceExpired)));

        assertThatThrownBy(() -> granter.authenticate(refreshGrant()))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e -> {
                    assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
                    assertThat(e.getError().getDescription()).isEqualTo(SecurityConstant.TOKEN_FORCE_EXPIRED_MESSAGE);
                });
    }

    @Test
    void refreshForALockedUserIsInvalidGrant() {
        when(refreshTokenDecoder.decode("refresh")).thenReturn(refreshJwt("abc_client"));
        when(userService.loadUserByUsername(USERNAME))
                .thenReturn(new User(USERNAME, "", false, true, true, true, AuthorityUtils.NO_AUTHORITIES));

        assertThatThrownBy(() -> granter.authenticate(refreshGrant()))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e ->
                        assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
        verifyNoInteractions(tokenGenerator);
    }

    @Test
    void converterRequiresTheRefreshTokenParameter() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", SecurityConstant.GRANT_TYPE_REFRESH_TOKEN);

        assertThatThrownBy(() -> new CustomTokenGranter.Converter().convert(request))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e ->
                        assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST));
    }

    private void stubTokenGeneratorPerType() {
        when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenAnswer(invocation -> {
            OAuth2TokenContext context = invocation.getArgument(0);
            Instant now = Instant.now();
            if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return new OAuth2RefreshToken("refresh", now, now.plusSeconds(3600));
            }
            return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access", now, now.plusSeconds(60));
        });
    }

    private static CustomTokenGranter.GrantToken refreshGrant() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("refresh_token", "refresh");
        return new CustomTokenGranter.GrantToken(AuthorizationGrantType.REFRESH_TOKEN,
                clientPrincipal(refreshingClient()), parameters);
    }

    private static Jwt refreshJwt(String clientId) {
        return Jwt.withTokenValue("refresh")
                .header("alg", "HS256")
                .claim(SecurityConstant.CLAIM_TOKEN_TYPE, SecurityConstant.TOKEN_TYPE_REFRESH)
                .claim(SecurityConstant.CLAIM_USER_NAME, USERNAME)
                .claim(SecurityConstant.CLAIM_CLIENT_ID, clientId)
                .claim(SecurityConstant.CLAIM_GRANT_TYPE, SecurityConstant.GRANT_TYPE_PASSWORD_MFA)
                .build();
    }

    private static Jwt refreshJwtWithScope(String... scopes) {
        return Jwt.withTokenValue("refresh")
                .header("alg", "HS256")
                .claim(SecurityConstant.CLAIM_TOKEN_TYPE, SecurityConstant.TOKEN_TYPE_REFRESH)
                .claim(SecurityConstant.CLAIM_USER_NAME, USERNAME)
                .claim(SecurityConstant.CLAIM_CLIENT_ID, "abc_client")
                .claim(SecurityConstant.CLAIM_GRANT_TYPE, SecurityConstant.GRANT_TYPE_PASSWORD)
                .claim("scope", List.of(scopes))
                .build();
    }

    private static CustomTokenGranter.GrantToken grantWithScope(String grantType, RegisteredClient client, String scope) {
        Map<String, Object> parameters = parameters(null);
        parameters.put("scope", scope);
        return new CustomTokenGranter.GrantToken(new AuthorizationGrantType(grantType), clientPrincipal(client), parameters);
    }

    private static RegisteredClient refreshingClient() {
        return RegisteredClient.from(client()).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).build();
    }

    @AfterEach
    void tearDown() {
        AuthorizationServerContextHolder.resetContext();
        SecurityContextHolder.clearContext();
    }

    @Test
    void passwordGrantAuthenticatesWithTheAuthenticationManagerAndIssuesOnlyAnAccessToken() {
        when(authenticationManager.authenticate(any())).thenReturn(authenticatedUser());
        stubTokenGenerator();

        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken)
                granter.authenticate(grant(SecurityConstant.GRANT_TYPE_PASSWORD, null));

        assertThat(result.getAccessToken().getTokenValue()).isEqualTo("access");
        assertThat(result.getAccessToken().getScopes()).containsExactlyInAnyOrder("read", "write");
        assertThat(result.getRefreshToken()).isNull();
        ArgumentCaptor<OAuth2TokenContext> context = ArgumentCaptor.forClass(OAuth2TokenContext.class);
        verify(tokenGenerator).generate(context.capture());
        assertThat(context.getValue().getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
        assertThat(context.getValue().<Authentication>getPrincipal().getName()).isEqualTo(USERNAME);
        verifyNoInteractions(userService);
    }

    @Test
    void passwordMfaGrantVerifiesPasswordAndOtpInTheUserService() {
        when(userService.loadUserForPasswordOtp(USERNAME, "pwd", "123456"))
                .thenReturn(new User(USERNAME, "", AuthorityUtils.createAuthorityList("ROLE_ACC_V")));
        stubTokenGenerator();

        granter.authenticate(grant(SecurityConstant.GRANT_TYPE_PASSWORD_MFA, "123456"));

        ArgumentCaptor<OAuth2TokenContext> context = ArgumentCaptor.forClass(OAuth2TokenContext.class);
        verify(tokenGenerator).generate(context.capture());
        assertThat(AuthorityUtils.authorityListToSet(context.getValue().<Authentication>getPrincipal().getAuthorities()))
                .containsExactly("ROLE_ACC_V");
        verifyNoInteractions(authenticationManager);
    }

    @Test
    void passwordGrantIssuesOnlyTheRequestedScope() {
        when(authenticationManager.authenticate(any())).thenReturn(authenticatedUser());
        stubTokenGeneratorPerType();

        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken)
                granter.authenticate(grantWithScope(SecurityConstant.GRANT_TYPE_PASSWORD, client(), "read"));

        assertThat(result.getAccessToken().getScopes()).containsExactly("read");
        ArgumentCaptor<OAuth2TokenContext> context = ArgumentCaptor.forClass(OAuth2TokenContext.class);
        verify(tokenGenerator).generate(context.capture());
        assertThat(context.getValue().getAuthorizedScopes()).containsExactly("read");
    }

    @Test
    void passwordMfaGrantIssuesOnlyTheRequestedScope() {
        when(userService.loadUserForPasswordOtp(USERNAME, "pwd", "123456"))
                .thenReturn(new User(USERNAME, "", AuthorityUtils.createAuthorityList("ROLE_ACC_V")));
        stubTokenGeneratorPerType();

        Map<String, Object> parameters = parameters("123456");
        parameters.put("scope", "write");
        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken) granter.authenticate(
                new CustomTokenGranter.GrantToken(new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD_MFA),
                        clientPrincipal(client()), parameters));

        assertThat(result.getAccessToken().getScopes()).containsExactly("write");
    }

    @Test
    void scopeOutsideTheClientScopesIsInvalidScope() {
        assertThatThrownBy(() -> granter.authenticate(
                grantWithScope(SecurityConstant.GRANT_TYPE_PASSWORD, client(), "read admin")))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e ->
                        assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE));
        verifyNoInteractions(authenticationManager, userService, tokenGenerator);
    }

    @Test
    void refreshKeepsTheScopeOfTheLogin() {
        when(refreshTokenDecoder.decode("refresh")).thenReturn(refreshJwtWithScope("read"));
        when(userService.loadUserByUsername(USERNAME))
                .thenReturn(new User(USERNAME, "", AuthorityUtils.createAuthorityList("ROLE_ACC_V")));
        stubTokenGeneratorPerType();

        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken) granter.authenticate(refreshGrant());

        assertThat(result.getAccessToken().getScopes()).containsExactly("read");
    }

    @Test
    void refreshTokenWithoutScopeClaimKeepsTheScopesOfTheClient() {
        when(refreshTokenDecoder.decode("refresh")).thenReturn(refreshJwt("abc_client"));
        when(userService.loadUserByUsername(USERNAME))
                .thenReturn(new User(USERNAME, "", AuthorityUtils.createAuthorityList("ROLE_ACC_V")));
        stubTokenGeneratorPerType();

        OAuth2AccessTokenAuthenticationToken result = (OAuth2AccessTokenAuthenticationToken) granter.authenticate(refreshGrant());

        assertThat(result.getAccessToken().getScopes()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    void refreshCannotWidenTheScopeOfTheLogin() {
        when(refreshTokenDecoder.decode("refresh")).thenReturn(refreshJwtWithScope("read"));
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("refresh_token", "refresh");
        parameters.put("scope", "read write");

        assertThatThrownBy(() -> granter.authenticate(new CustomTokenGranter.GrantToken(
                AuthorizationGrantType.REFRESH_TOKEN, clientPrincipal(refreshingClient()), parameters)))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e ->
                        assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE));
        verifyNoInteractions(tokenGenerator);
    }

    @Test
    void wrongPasswordIsInvalidGrant() {
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> granter.authenticate(grant(SecurityConstant.GRANT_TYPE_PASSWORD, null)))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e -> {
                    assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
                    assertThat(e.getError().getDescription()).isEqualTo("Bad credentials");
                });
    }

    @Test
    void wrongOtpIsInvalidGrantWithTheServiceMessage() {
        when(userService.loadUserForPasswordOtp(USERNAME, "pwd", "000000"))
                .thenThrow(new BadRequestException("Verified Fail", ErrorCode.ACCOUNT_ERROR_OTP_INVALID));

        assertThatThrownBy(() -> granter.authenticate(grant(SecurityConstant.GRANT_TYPE_PASSWORD_MFA, "000000")))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e -> {
                    assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
                    assertThat(e.getError().getDescription()).isEqualTo("Verified Fail");
                });
    }

    @Test
    void clientNotAllowedTheGrantIsUnauthorizedClient() {
        RegisteredClient client = RegisteredClient.from(client())
                .authorizationGrantTypes(types -> types.remove(new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD)))
                .build();
        CustomTokenGranter.GrantToken grant = new CustomTokenGranter.GrantToken(
                new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD), clientPrincipal(client), parameters(null));

        assertThatThrownBy(() -> granter.authenticate(grant))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e ->
                        assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
        verifyNoInteractions(authenticationManager, userService);
    }

    @Test
    void converterTakesOnlyItsOwnGrantTypes() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", "client_credentials");

        assertThat(new CustomTokenGranter.Converter().convert(request)).isNull();
    }

    @Test
    void converterKeepsRequestParametersButNotTheClientSecret() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", SecurityConstant.GRANT_TYPE_PASSWORD_MFA);
        request.addParameter("username", USERNAME);
        request.addParameter("password", "pwd");
        request.addParameter("otp", "123456");
        request.addParameter("client_secret", "abc123");
        // set by the client authentication filter before the converter runs
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal(client()));

        CustomTokenGranter.GrantToken grant = (CustomTokenGranter.GrantToken) new CustomTokenGranter.Converter().convert(request);

        assertThat(grant.getGrantType().getValue()).isEqualTo(SecurityConstant.GRANT_TYPE_PASSWORD_MFA);
        assertThat(grant.parameter("otp")).isEqualTo("123456");
        assertThat(grant.getAdditionalParameters()).doesNotContainKey("client_secret");
    }

    @Test
    void converterRejectsAMissingPassword() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("grant_type", SecurityConstant.GRANT_TYPE_PASSWORD);
        request.addParameter("username", USERNAME);

        assertThatThrownBy(() -> new CustomTokenGranter.Converter().convert(request))
                .isInstanceOfSatisfying(OAuth2AuthenticationException.class, e ->
                        assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST));
    }

    private void stubTokenGenerator() {
        Instant now = Instant.now();
        when(tokenGenerator.generate(any(OAuth2TokenContext.class))).thenReturn(
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access", now, now.plusSeconds(60)));
    }

    private static Authentication authenticatedUser() {
        User user = new User(USERNAME, "", AuthorityUtils.createAuthorityList("ROLE_ACC_V"));
        return UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
    }

    private static CustomTokenGranter.GrantToken grant(String grantType, String otp) {
        return new CustomTokenGranter.GrantToken(new AuthorizationGrantType(grantType), clientPrincipal(client()), parameters(otp));
    }

    private static Map<String, Object> parameters(String otp) {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("username", USERNAME);
        parameters.put("password", "pwd");
        if (otp != null) {
            parameters.put("otp", otp);
        }
        return parameters;
    }

    private static OAuth2ClientAuthenticationToken clientPrincipal(RegisteredClient client) {
        return new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "abc123");
    }

    private static RegisteredClient client() {
        return RegisteredClient.withId("abc_client")
                .clientId("abc_client")
                .clientSecret("{noop}abc123")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD))
                .authorizationGrantType(new AuthorizationGrantType(SecurityConstant.GRANT_TYPE_PASSWORD_MFA))
                .scope("read")
                .scope("write")
                .build();
    }
}
