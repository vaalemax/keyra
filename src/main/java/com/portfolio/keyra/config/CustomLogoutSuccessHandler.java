package com.portfolio.keyra.config;

import com.portfolio.keyra.model.AuditLog;
import com.portfolio.keyra.model.User;
import com.portfolio.keyra.repository.UserRepository;
import com.portfolio.keyra.service.AuditService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final AuditService auditService;

    private final UserRepository userRepository;

    private static final Logger log = LoggerFactory.getLogger(CustomLogoutSuccessHandler.class);


    public CustomLogoutSuccessHandler(AuditService auditService, UserRepository userRepository) {
        super();
        setDefaultTargetUrl("/login?logout=true");
        this.auditService = auditService;
        this.userRepository = userRepository;
    }

    @Override
    public void onLogoutSuccess(@NotNull HttpServletRequest request,
                                @NotNull HttpServletResponse response,
                                Authentication authentication)
            throws IOException, ServletException {

        if (authentication != null && authentication.getName() != null) {
            String username = authentication.getName();
            log.info("User logged out: {}", username);

            User user = userRepository.findByUsername(username).orElse(null);

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