package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.service.AuditService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Custom authentication failure handler.
 * Logs failed login attempts for security monitoring.
 */
@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationFailureHandler.class);

    private final AuditService auditService;

    public CustomAuthenticationFailureHandler(AuditService auditService) {
        super("/login?error=true");
        this.auditService = auditService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        @NotNull HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String username = request.getParameter("username");
        String errorMessage = exception.getMessage();

        log.warn("Failed login attempt for username: {} - Reason: {}", username, errorMessage);

        auditService.logAction(
                null,
                AuditLog.AuditAction.LOGIN_FAILURE,
                AuditLog.AuditStatus.FAILURE,
                "Username: " + username + " - " + "Failed login: " + errorMessage,
                auditService.getClientIp(request),
                auditService.getUserAgent(request)
        );

        super.onAuthenticationFailure(request, response, exception);
    }
}