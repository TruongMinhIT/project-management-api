package com.projectmgr.api.config;

import com.projectmgr.api.constant.SecurityConstant;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
public class JwtConfig {
    public static final int MIN_SIGNING_KEY_BYTES = 32;
    private static final OAuth2Error FORCE_EXPIRED = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN, SecurityConstant.TOKEN_FORCE_EXPIRED_MESSAGE, null);

    @Value("${auth.signing.key}")
    private String signingKey;

    @Value("${jwt.version}")
    private Integer currentVersion;

    @Bean
    public SecretKey jwtSigningKey() {
        byte[] keyBytes = signingKey.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < MIN_SIGNING_KEY_BYTES) {
            throw new IllegalStateException("auth.signing.key must be at least " + MIN_SIGNING_KEY_BYTES
                    + " bytes for HS256, got " + keyBytes.length);
        }
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(SecretKey jwtSigningKey) {
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(jwtSigningKey)
                .algorithm(JWSAlgorithm.HS256)
                .build();
        return new ImmutableJWKSet<>(new JWKSet(jwk));
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    // API requests: access tokens only, a refresh token sent as bearer is rejected
    @Bean
    @Primary
    public JwtDecoder jwtDecoder(SecretKey jwtSigningKey) {
        return decoder(jwtSigningKey, tokenTypeValidator(false));
    }

    // grant_type=refresh_token: refresh tokens only
    @Bean
    public JwtDecoder refreshTokenDecoder(SecretKey jwtSigningKey) {
        return decoder(jwtSigningKey, tokenTypeValidator(true));
    }

    private JwtDecoder decoder(SecretKey jwtSigningKey, OAuth2TokenValidator<Jwt> tokenTypeValidator) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(jwtSigningKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(), versionValidator(), tokenTypeValidator));
        return decoder;
    }

    private static OAuth2TokenValidator<Jwt> tokenTypeValidator(boolean refreshToken) {
        OAuth2Error wrongType = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                refreshToken ? "Not a refresh token" : "A refresh token cannot be used as an access token", null);
        return jwt -> {
            boolean isRefreshToken = SecurityConstant.TOKEN_TYPE_REFRESH.equals(jwt.getClaimAsString(SecurityConstant.CLAIM_TOKEN_TYPE));
            return isRefreshToken == refreshToken
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(wrongType);
        };
    }

    private OAuth2TokenValidator<Jwt> versionValidator() {
        return jwt -> {
            Object version = jwt.getClaim(SecurityConstant.CLAIM_VERSION);
            boolean current = version instanceof Number && ((Number) version).intValue() >= currentVersion;
            return current ? OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(FORCE_EXPIRED);
        };
    }
}
