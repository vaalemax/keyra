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
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

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
        log.info("Authentication success for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));

        // ✅ Check if 2FA is enabled
        if (user.isTwoFactorEnabled()) {
            log.info("2FA enabled - redirecting to verification page");

            HttpSession session = request.getSession();
            session.setAttribute("2FA_USER_ID", user.getId());
            session.setAttribute("2FA_USERNAME", user.getUsername());

            getRedirectStrategy().sendRedirect(request, response, "/login/2fa");
            return;
        }

        // ✅ Derive and store AES key
        try {
            SecretKey aesKey = deriveAesKey(user);

            // ✅ IMPORTANTE: Chiama super PRIMA di salvare nella sessione
            super.onAuthenticationSuccess(request, response, authentication);

            // ✅ Ora salva nella sessione DOPO la migrazione
            HttpSession session = request.getSession(false);
            if (session == null) {
                log.error("Session is null after authentication");
                throw new IllegalStateException("No session available");
            }

            session.setAttribute("aesKey", aesKey);
            log.info("AES key stored in session - Session ID: {}", session.getId());

            // Audit log
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.LOGIN_SUCCESS,
                    AuditLog.AuditStatus.SUCCESS,
                    "Login successful",
                    getClientIp(request),
                    request.getHeader("User-Agent")
            );

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

    private SecretKey deriveAesKey(User user) throws Exception {
        String encryptionKey = user.getEncryptionKey();
        byte[] combined = Base64.getDecoder().decode(encryptionKey);

        byte[] salt = new byte[16];
        byte[] keyBytes = new byte[32];
        System.arraycopy(combined, 0, salt, 0, 16);
        System.arraycopy(combined, 16, keyBytes, 0, 32);

        return encryptionService.recreateKey(keyBytes);
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