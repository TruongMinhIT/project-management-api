package com.projectmgr.api.config;

import com.projectmgr.api.config.security.CustomOAuth2AuthEntryPoint;
import com.projectmgr.api.constant.SecurityConstant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomOAuth2AuthEntryPoint customOAuth2AuthEntryPoint;

    private static final String[] PUBLIC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**",
            AuthorizationServerConfig.TOKEN_ENDPOINT,
            "/api/auth/**",
            "/error",
            "/v1/account/login",
            "/v1/setting/find-by-key", "/v1/setting/find-by-group", "/v1/setting/public",
            "/v1/file/download/**",
            "/actuator/health", "/actuator/health/**"
    };

    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_PATHS).permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder)
                                .jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint(customOAuth2AuthEntryPoint))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(customOAuth2AuthEntryPoint)
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler()));
        return http.build();
    }

    /**
     * The {@code authorities} claim already holds {@code ROLE_<P_CODE>}, so it maps one to one onto
     * {@code hasRole('<P_CODE>')} with no prefix added. The principal name is {@code user_name}, else {@code sub}.
     */
    static Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName(SecurityConstant.CLAIM_AUTHORITIES);
        authoritiesConverter.setAuthorityPrefix("");
        return jwt -> {
            String name = jwt.hasClaim(SecurityConstant.CLAIM_USER_NAME)
                    ? jwt.getClaimAsString(SecurityConstant.CLAIM_USER_NAME)
                    : jwt.getSubject();
            return new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt), name);
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH"));
        config.setAllowedHeaders(Arrays.asList(
                "Accept", "Origin", "Content-Type", "Depth", "User-Agent",
                "If-Modified-Since", "Cache-Control", "Authorization",
                "X-Req", "X-File-Size", "X-Requested-With", "X-File-Name", "Content-Disposition", "X-Client-Type"));
        config.setExposedHeaders(Arrays.asList("Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization", "Content-Disposition"));
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
