package io.github.realnribal.hsmkms.web;

import io.github.realnribal.hsmkms.config.KmsProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class ApiKeyFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyFilter.class);
    private final String apiKey;

    public ApiKeyFilter(KmsProperties properties) {
        this.apiKey = properties.apiKey();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (!path.startsWith("/api/v1/") || "/api/v1/health".equals(path)) {
            chain.doFilter(request, response);
            return;
        }
        String provided = request.getHeader("X-API-Key");
        if (provided == null || !constantTimeEquals(apiKey, provided)) {
            log.info("rejected unauthenticated request");
            String traceId = MDC.get("traceId");
            response.setStatus(401);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"code\":\"UNAUTHORIZED\",\"message\":\"Missing or invalid API key\",\"traceId\":\""
                    + (traceId == null ? "" : traceId) + "\"}");
            return;
        }
        chain.doFilter(request, response);
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] left = digest.digest(expected.getBytes(StandardCharsets.UTF_8));
            byte[] right = digest.digest(actual.getBytes(StandardCharsets.UTF_8));
            return MessageDigest.isEqual(left, right);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }
}
