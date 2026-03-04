package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.repository.UserRepository;
import com.portfolio.pswmanager.service.AuditService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Custom logout success handler.
 * Logs logout events for audit trail.
 */
@Component
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomLogoutSuccessHandler.class);

    private final AuditService auditService;
    private final UserRepository userRepository;

    public CustomLogoutSuccessHandler(AuditService auditService, UserRepository userRepository) {
        super();
        setDefaultTargetUrl("/login?logout=true");
        this.auditService = auditService;
        this.userRepository = userRepository;
    }

    @Override
    public void onLogoutSuccess(@NonNull HttpServletRequest request,
                                @NonNull HttpServletResponse response,
                                Authentication authentication)
            throws IOException, ServletException {

        if (authentication != null && authentication.getName() != null) {
            String username = authentication.getName();
            log.info("User logged out: {}", username);

            // Load user for audit
            User user = userRepository.findByUsername(username).orElse(null);

            // Audit log logout
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.LOGOUT,
                    AuditLog.AuditStatus.SUCCESS,
                    "User logged out",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );
        }

        super.onLogoutSuccess(request, response, authentication);
    }
}