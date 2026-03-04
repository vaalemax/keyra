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
import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthenticationSuccessHandler.class);

    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final AuditService auditService;

    public CustomAuthenticationSuccessHandler(
            UserRepository userRepository,
            EncryptionService encryptionService,
            AuditService auditService) {
        super("/vault");
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.auditService = auditService;
    }

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest request,
                                        @NonNull HttpServletResponse response,
                                        Authentication authentication)
            throws ServletException {

        String username = authentication.getName();
        log.info("User authenticated successfully: {}", username);

        try {
            // Load user from database
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> {
                        log.error("User not found after authentication: {}", username);
                        return new RuntimeException("User not found: " + username);
                    });

            log.debug("User entity loaded for: {}", username);

            // Get master password from request
            String masterPassword = request.getParameter("password");

            // Decode encryption key (salt + AES key)
            byte[] combined = Base64.getDecoder().decode(user.getEncryptionKey());
            byte[] salt = new byte[16];
            System.arraycopy(combined, 0, salt, 0, 16);

            log.debug("Salt extracted for user: {}", username);

            // Derive AES key
            SecretKey aesKey = encryptionService.deriveKeyFromPassword(masterPassword, salt);

            log.debug("AES key derived successfully for user: {}", username);

            // Store AES key in session
            HttpSession session = request.getSession();
            session.setAttribute("AES_KEY", aesKey);

            log.info("AES key stored in session for user: {}", username);

            // Audit log successful login
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.LOGIN_SUCCESS,
                    AuditLog.AuditStatus.SUCCESS,
                    "Successful login",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            log.info("Login completed successfully for user: {}", username);

            super.onAuthenticationSuccess(request, response, authentication);

        } catch (Exception e) {
            log.error("Error during authentication success handling for user: {}", username, e);

            // Audit log system error
            User user = userRepository.findByUsername(username).orElse(null);
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    AuditLog.AuditStatus.FAILURE,
                    "Error processing login: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            throw new ServletException("Error processing login", e);
        }
    }
}