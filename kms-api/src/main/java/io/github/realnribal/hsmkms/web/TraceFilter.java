package io.github.realnribal.hsmkms.web;

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
import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TraceFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TraceFilter.class);
    private static final int MAX_BODY = 2_000_000;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String incoming = request.getHeader("X-Request-Id");
        String traceId = incoming == null || incoming.isBlank() || incoming.length() > 80
                ? UUID.randomUUID().toString()
                : incoming;
        MDC.put("traceId", traceId);
        response.setHeader("X-Trace-Id", traceId);
        long started = System.nanoTime();
        try {
            if (request.getContentLength() > MAX_BODY) {
                response.setStatus(413);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"code\":\"VALIDATION\",\"message\":\"Request body is too large\",\"traceId\":\""
                        + traceId + "\"}");
                return;
            }
            chain.doFilter(request, response);
        } finally {
            long durationMs = (System.nanoTime() - started) / 1_000_000L;
            log.info("http method={} path={} status={} durationMs={}",
                    request.getMethod(), request.getRequestURI(), response.getStatus(), durationMs);
            MDC.clear();
        }
    }
}
