package com.portfolio.pswmanager.config;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.repository.UserRepository;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.EncryptionService;
import jakarta.servlet.ServletException;
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
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final AuditService auditService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        String username = authentication.getName();
        log.info("=== Authentication Success Handler Started ===");
        log.info("User: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        log.info("User loaded - 2FA enabled: {}", user.isTwoFactorEnabled());

        // ✅ Check if 2FA is enabled
        if (user.isTwoFactorEnabled()) {
            log.info("2FA enabled - redirecting to verification");

            HttpSession session = request.getSession();
            session.setAttribute("2FA_USER_ID", user.getId());
            session.setAttribute("2FA_USERNAME", user.getUsername());

            response.sendRedirect("/login/2fa");
            return;
        }

        // ✅ Derive AES key
        try {
            log.info("Deriving AES key...");

            String encryptionKey = user.getEncryptionKey();
            byte[] combined = Base64.getDecoder().decode(encryptionKey);

            byte[] salt = new byte[16];
            byte[] keyBytes = new byte[32];
            System.arraycopy(combined, 0, salt, 0, 16);
            System.arraycopy(combined, 16, keyBytes, 0, 32);

            SecretKey aesKey = encryptionService.recreateKey(keyBytes);

            log.info("AES key derived successfully");

            // ✅ Store in session BEFORE redirect
            HttpSession session = request.getSession();
            session.setAttribute("AES_KEY", aesKey);

            log.info("AES key stored in session");
            log.info("Session ID: {}", session.getId());
            log.info("Session max inactive interval: {} seconds", session.getMaxInactiveInterval());

            // ✅ Verify it's saved
            Object savedKey = session.getAttribute("AES_KEY");
            log.info("Verification - AES key in session: {}", savedKey != null ? "YES" : "NO");

            // Audit log
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.LOGIN_SUCCESS,
                    AuditLog.AuditStatus.SUCCESS,
                    "Login successful",
                    getClientIp(request),
                    request.getHeader("User-Agent")
            );

            log.info("Redirecting to /vault");

            // ✅ Redirect manually
            response.sendRedirect("/vault");

            log.info("=== Authentication Success Handler Completed ===");

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