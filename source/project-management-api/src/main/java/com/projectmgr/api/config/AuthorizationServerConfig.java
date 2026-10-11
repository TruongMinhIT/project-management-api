package com.projectmgr.api.config;

import com.projectmgr.api.config.security.CustomOAuth2AuthEntryPoint;
import com.projectmgr.api.constant.SecurityConstant;
import com.projectmgr.api.service.impl.UserServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AccessTokenResponseAuthenticationSuccessHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

@Configuration
public class AuthorizationServerConfig {
    public static final String TOKEN_ENDPOINT = "/api/token";

    private static final List<String> RESPONSE_CLAIMS = List.of(
            SecurityConstant.CLAIM_USER_ID, SecurityConstant.CLAIM_ROLE, SecurityConstant.CLAIM_GRANT_TYPE,
            SecurityConstant.CLAIM_VERSION, SecurityConstant.CLAIM_ADDITIONAL_INFO, SecurityConstant.CLAIM_JTI);

    @Value("${jwt.version}")
    private Integer currentVersion;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CustomOAuth2AuthEntryPoint customOAuth2AuthEntryPoint;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            UserServiceImpl userService,
            OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
            @Qualifier("refreshTokenDecoder") JwtDecoder refreshTokenDecoder) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServer = OAuth2AuthorizationServerConfigurer.authorizationServer();
        AuthenticationFailureHandler errorResponseHandler = this::writeTokenError;

        http.securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, server -> server
                        .tokenGenerator(tokenGenerator)
                        .clientAuthentication(client -> client.errorResponseHandler(errorResponseHandler))
                        .tokenEndpoint(token -> token
                                .accessTokenRequestConverter(new CustomTokenGranter.Converter())
                                .authenticationProvider(new CustomTokenGranter(
                                        authenticationManager, userService, tokenGenerator, refreshTokenDecoder))
                                .accessTokenResponseHandler(accessTokenResponseHandler())
                                .errorResponseHandler(errorResponseHandler)))
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(customOAuth2AuthEntryPoint));
        return http.build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .tokenEndpoint(TOKEN_ENDPOINT)
                .build();
    }

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
            JwtEncoder jwtEncoder, OAuth2TokenCustomizer<JwtEncodingContext> tokenEnhancer) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(tokenEnhancer);
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator(jwtEncoder));
    }

    // a refresh token is a JWT too, signed with the same key and stored nowhere, as before the migration;
    // CustomTokenGranter reads it back on grant_type=refresh_token
    OAuth2TokenGenerator<OAuth2RefreshToken> refreshTokenGenerator(JwtEncoder jwtEncoder) {
        return context -> {
            if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
                return null;
            }
            Instant issuedAt = Instant.now();
            Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
            String username = context.getPrincipal().getName();
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .id(UUID.randomUUID().toString())
                    .subject(username)
                    .issuedAt(issuedAt)
                    .expiresAt(expiresAt)
                    .claim(SecurityConstant.CLAIM_TOKEN_TYPE, SecurityConstant.TOKEN_TYPE_REFRESH)
                    .claim(SecurityConstant.CLAIM_USER_NAME, username)
                    .claim(SecurityConstant.CLAIM_CLIENT_ID, context.getRegisteredClient().getClientId())
                    .claim(SecurityConstant.CLAIM_GRANT_TYPE, context.getAuthorizationGrantType().getValue())
                    .claim(SecurityConstant.CLAIM_VERSION, currentVersion)
                    .claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes())
                    .build();
            Jwt jwt = jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).type(SecurityConstant.JWT_HEADER_TYPE).build(), claims));
            return new OAuth2RefreshToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt());
        };
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    // access and refresh tokens are self-contained JWTs: nothing needs to be kept
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new NoOpAuthorizationService();
    }

    private static OAuth2AccessTokenResponseAuthenticationSuccessHandler accessTokenResponseHandler() {
        OAuth2AccessTokenResponseAuthenticationSuccessHandler handler =
                new OAuth2AccessTokenResponseAuthenticationSuccessHandler();
        handler.setAccessTokenResponseCustomizer(AuthorizationServerConfig::addClaimsToResponse);
        return handler;
    }

    private static void addClaimsToResponse(OAuth2AccessTokenAuthenticationContext context) {
        OAuth2AccessTokenAuthenticationToken authentication = context.getAuthentication();
        Map<String, Object> claims = readClaims(authentication.getAccessToken().getTokenValue());
        Map<String, Object> parameters = new HashMap<>(authentication.getAdditionalParameters());
        RESPONSE_CLAIMS.stream()
                .filter(claims::containsKey)
                .forEach(name -> parameters.put(name, claims.get(name)));
        context.getAccessTokenResponse().additionalParameters(parameters);
    }

    // the token was signed a moment ago by this server: reading it needs no verification
    private static Map<String, Object> readClaims(String tokenValue) {
        try {
            return SignedJWT.parse(tokenValue).getJWTClaimsSet().getClaims();
        } catch (ParseException e) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR, "Issued access token is not a JWT", null), e);
        }
    }

    /**
     * Token endpoint and client authentication errors in the old body:
     * {@code {"code": <http status>, "message": "...", "data": ["<oauth2 error code>", "..."]}}.
     */
    private void writeTokenError(HttpServletRequest request, HttpServletResponse response,
                                 AuthenticationException exception) throws IOException {
        OAuth2Error error = exception instanceof OAuth2AuthenticationException
                ? ((OAuth2AuthenticationException) exception).getError()
                : new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, exception.getMessage(), null);
        HttpStatus status = statusOf(error);
        String message = error.getDescription() != null ? error.getDescription() : error.getErrorCode();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", status.value());
        body.put("message", message);
        body.put("data", Arrays.asList(error.getErrorCode(), message));

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), body);
    }

    static HttpStatus statusOf(OAuth2Error error) {
        return switch (error.getErrorCode()) {
            case OAuth2ErrorCodes.INVALID_CLIENT -> HttpStatus.UNAUTHORIZED;
            case OAuth2ErrorCodes.SERVER_ERROR -> HttpStatus.INTERNAL_SERVER_ERROR;
            default -> HttpStatus.BAD_REQUEST;
        };
    }

    private static class NoOpAuthorizationService implements OAuth2AuthorizationService {

        @Override
        public void save(OAuth2Authorization authorization) {
        }

        @Override
        public void remove(OAuth2Authorization authorization) {
        }

        @Override
        public OAuth2Authorization findById(String id) {
            return null;
        }

        @Override
        public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
            return null;
        }
    }
}
