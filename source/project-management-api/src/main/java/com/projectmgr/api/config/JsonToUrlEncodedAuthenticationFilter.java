package com.projectmgr.api.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.web.savedrequest.Enumerator;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Lets {@code /api/token} take a JSON body: its fields become request parameters. The token endpoint is a
 * Spring Security filter, so this one must run before the security filter chain.
 */
@Component
@Order(SecurityProperties.DEFAULT_FILTER_ORDER - 1)
@Slf4j
public class JsonToUrlEncodedAuthenticationFilter extends OncePerRequestFilter {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (Objects.equals(request.getServletPath(), AuthorizationServerConfig.TOKEN_ENDPOINT) && isJson(request)) {
            Map<String, Object> jsonMap = JSON.readValue(request.getInputStream().readAllBytes(),
                    new TypeReference<Map<String, Object>>() {
                    });
            Map<String, String[]> parameters = new HashMap<>();
            jsonMap.forEach((key, value) -> {
                if (value != null) {
                    parameters.put(key, new String[]{String.valueOf(value)});
                }
            });
            filterChain.doFilter(new RequestWrapper(request, parameters), response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private static boolean isJson(HttpServletRequest request) {
        return request.getContentType() != null && request.getContentType().contains(MediaType.APPLICATION_JSON_VALUE);
    }

    private static class RequestWrapper extends HttpServletRequestWrapper {

        private final Map<String, String[]> params;

        RequestWrapper(HttpServletRequest request, Map<String, String[]> params) {
            super(request);
            this.params = params;
        }

        @Override
        public String getParameter(String name) {
            String[] values = params.get(name);
            return values != null ? values[0] : null;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return params;
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return new Enumerator<>(params.keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            return params.get(name);
        }
    }
}
