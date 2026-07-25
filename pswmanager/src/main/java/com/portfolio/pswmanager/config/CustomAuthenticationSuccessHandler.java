package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.repository.UserRepository;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.EncryptionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private final AuditService auditService;

    private final EncryptionService encryptionService;

    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        String username = authentication.getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        if (user.isTwoFactorEnabled()) {
            HttpSession session = request.getSession();
            session.setAttribute("2FA_USER_ID", user.getId());
            session.setAttribute("2FA_USERNAME", user.getUsername());

            response.sendRedirect("/login/2fa");
            return;
        }

        try {
            String encryptionKey = user.getEncryptionKey();
            SecretKey aesKey = encryptionService.deriveAesKey(encryptionKey);

            HttpSession session = request.getSession();
            session.setAttribute("AES_KEY", aesKey);

            log.info("Session ID: {}", session.getId());
            log.info("Session max inactive interval: {} seconds", session.getMaxInactiveInterval());

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.LOGIN_SUCCESS,
                    AuditLog.AuditStatus.SUCCESS,
                    "Login successful",
                    getClientIp(request),
                    request.getHeader("User-Agent")
            );


            response.sendRedirect("/vault");

        } catch (Exception e) {
            log.error("Error in authentication success handler", e);

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    AuditLog.AuditStatus.FAILURE,
                    "Login error: " + e.getMessage(),
                    getClientIp(request),
                    request.getHeader("User-Agent")
            );

            response.sendRedirect("/login?error=true");
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }
}