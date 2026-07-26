package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.RateLimitService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Rate limiting filter to prevent brute force attacks.
 * Limits requests per IP address using token bucket algorithm.
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {
    private final AuditService auditService;

    private final RateLimitService rateLimitService;

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private static final Set<String> STRICT_ENDPOINTS = Set.of(
            "/login",
            "/register",
            "/api/password/generate"
    );

    private static final Set<String> PROTECTED_ENDPOINTS = Set.of(
            "/vault/add",
            "/vault/edit",
            "/vault/delete",
            "/vault/import",
            "/vault/export"
    );

    public RateLimitingFilter(AuditService auditService,
                              RateLimitService rateLimitService) {
        this.auditService = auditService;
        this.rateLimitService = rateLimitService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String uri = request.getRequestURI();
        String method = request.getMethod();
        String ip = getClientIp(request);

        if (uri.startsWith("/error/")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Check if endpoint needs rate limiting
        boolean isStrict = STRICT_ENDPOINTS.contains(uri) && "POST".equals(method);
        boolean isProtected = PROTECTED_ENDPOINTS.contains(uri) && "POST".equals(method);

        if (!isStrict && !isProtected) {
            filterChain.doFilter(request, response);
            return;
        }

        // Check rate limit
        boolean allowed = isStrict
                ? rateLimitService.isStrictAllowed(ip)
                : rateLimitService.isAllowed(ip);

        if (allowed) {
            // Request allowed
            int remaining = rateLimitService.getRemainingRequests(ip, isStrict);
            response.addHeader("X-Rate-Limit-Remaining", String.valueOf(remaining));

            log.debug("Request allowed - IP: {}, URI: {}, Remaining: {}", ip, uri, remaining);

            filterChain.doFilter(request, response);

        } else {
            // Request blocked
            long waitSeconds = rateLimitService.getSecondsUntilReset(
                    ip, isStrict
            );

            log.warn("Rate limit exceeded - IP: {}, URI: {}, Wait: {}s", ip, uri, waitSeconds);

            // Audit log
            auditService.logAction(
                    null,
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    AuditLog.AuditStatus.FAILURE,
                    "Rate limit exceeded for IP: " + ip + " on endpoint: " + uri,
                    ip,
                    request.getHeader("User-Agent")
            );

            // Return 429
            response.setStatus(429);
            response.addHeader("X-Rate-Limit-Retry-After-Seconds", String.valueOf(waitSeconds));

            String accept = request.getHeader("Accept");
            boolean wantsHtml = accept != null && accept.contains("text/html");

            if (wantsHtml) {
                // Redirect to error page
                request.setAttribute("retryAfter", waitSeconds);

                // Use sendError instead of redirect
                response.sendError(429, "Too many requests. Please try again in " + waitSeconds + " seconds.");
            } else {
                // Return JSON for API requests
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                        "{\"error\":\"Too many requests\",\"message\":\"Please try again in %d seconds\",\"retryAfter\":%d}",
                        waitSeconds, waitSeconds
                ));
            }
        }
    }

    /**
     * Get client IP address, considering proxy headers.
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // Handle multiple IPs (take the first one)
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }
}