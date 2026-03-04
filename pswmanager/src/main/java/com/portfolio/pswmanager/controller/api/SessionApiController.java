package com.portfolio.pswmanager.controller.api;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * REST API for session management.
 */
@RestController
@RequestMapping("/api/session")
@RequiredArgsConstructor
public class SessionApiController {

    private static final Logger log = LoggerFactory.getLogger(SessionApiController.class);

    private final SessionService sessionService;
    private final AuditService auditService;

    /**
     * Refreshes the user's session to extend timeout.
     * Called by the frontend when user confirms to stay logged in.
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshSession(
            Authentication authentication,
            HttpSession session,
            HttpServletRequest request
    ) {
        try {
            User user = sessionService.getCurrentUser(authentication);

            // Reset session timeout
            session.setMaxInactiveInterval(30 * 60); // 30 minutes

            // Log session refresh
            log.debug("Session refreshed for user: {}", user.getUsername());

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_VIEW,  // Riusa questa o crea SESSION_REFRESH
                    AuditLog.AuditStatus.SUCCESS,
                    "Session refreshed",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Session refreshed successfully");
            response.put("expiresIn", 30 * 60); // seconds

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Error refreshing session", e);

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "Failed to refresh session");

            return ResponseEntity.internalServerError().body(response);
        }
    }

    /**
     * Returns the remaining session time.
     */
    @PostMapping("/check")
    public ResponseEntity<Map<String, Object>> checkSession(HttpSession session) {
        int maxInactiveInterval = session.getMaxInactiveInterval();
        long lastAccessedTime = session.getLastAccessedTime();
        long currentTime = System.currentTimeMillis();
        long elapsedTime = (currentTime - lastAccessedTime) / 1000; // seconds
        long remainingTime = maxInactiveInterval - elapsedTime;

        Map<String, Object> response = new HashMap<>();
        response.put("remainingSeconds", Math.max(0, remainingTime));
        response.put("maxInactiveInterval", maxInactiveInterval);

        return ResponseEntity.ok(response);
    }
}