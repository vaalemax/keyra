package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.repository.UserRepository;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.EncryptionService;
import com.portfolio.pswmanager.service.TwoFactorService;
import com.portfolio.pswmanager.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.List;

/**
 * Controller for 2FA verification during login.
 */
@Controller
@RequiredArgsConstructor
public class TwoFactorVerificationController {

    private static final Logger log = LoggerFactory.getLogger(TwoFactorVerificationController.class);

    private final UserRepository userRepository;
    private final TwoFactorService twoFactorService;
    private final UserService userService;
    private final EncryptionService encryptionService;
    private final AuditService auditService;

    /**
     * Show 2FA verification page.
     */
    @GetMapping("/login/2fa")
    public String show2FAVerification(HttpSession session, Model model) {
        Long userId = (Long) session.getAttribute("2FA_USER_ID");

        if (userId == null) {
            log.warn("2FA verification page accessed without valid session");
            return "redirect:/login";
        }

        String username = (String) session.getAttribute("2FA_USERNAME");
        log.debug("2FA verification page shown for user: {}", username);

        model.addAttribute("username", username);

        return "login/two-factor-verify";
    }

    /**
     * Verify 2FA code.
     */
    @PostMapping("/login/2fa/verify")
    public String verify2FA(
            @RequestParam String code,
            @RequestParam(required = false, defaultValue = "false") boolean useBackupCode,
            HttpSession session,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        Long userId = (Long) session.getAttribute("2FA_USER_ID");

        if (userId == null) {
            log.warn("2FA verification attempted without valid session");
            return "redirect:/login";
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException("User not found: " + userId));

        log.info("2FA verification attempt for user: {}", user.getUsername());

        boolean isValid = false;

        try {
            if (useBackupCode) {
                // Verify backup code
                log.debug("Verifying backup code for user: {}", user.getUsername());

                List<String> backupCodes = userService.getBackupCodes(user);
                isValid = twoFactorService.verifyBackupCode(code.trim(), backupCodes);

                if (isValid) {
                    // Remove used backup code
                    List<String> updatedCodes = twoFactorService.removeBackupCode(code.trim(), backupCodes);
                    userService.updateBackupCodes(user, updatedCodes);

                    log.info("Backup code verified and removed for user: {} - remaining: {}",
                            user.getUsername(), updatedCodes.size());

                    // Warn if running low on backup codes
                    if (updatedCodes.size() <= 2) {
                        session.setAttribute("warningMessage",
                                "Warning: You have only " + updatedCodes.size() + " backup codes remaining.");
                    }
                }

            } else {
                // Verify TOTP code
                log.debug("Verifying TOTP code for user: {}", user.getUsername());

                int totpCode = Integer.parseInt(code.trim());
                isValid = twoFactorService.verifyCode(user.getTwoFactorSecret(), totpCode);
            }

            if (isValid) {
                // 2FA verification successful
                log.info("2FA verification successful for user: {}", user.getUsername());

                // Derive and store AES key
                try {
                    String encryptionKey = user.getEncryptionKey();
                    byte[] combined = Base64.getDecoder().decode(encryptionKey);

                    byte[] salt = new byte[16];
                    byte[] keyBytes = new byte[32];
                    System.arraycopy(combined, 0, salt, 0, 16);
                    System.arraycopy(combined, 16, keyBytes, 0, 32);

                    SecretKey aesKey = encryptionService.recreateKey(keyBytes);
                    session.setAttribute("AES_KEY", aesKey);

                    log.debug("AES key stored in session for user: {}", user.getUsername());

                } catch (Exception e) {
                    log.error("Error deriving AES key after 2FA", e);
                    redirectAttributes.addFlashAttribute("errorMessage",
                            "An error occurred. Please try again.");
                    return "redirect:/login";
                }

                // Clean up 2FA session attributes
                session.removeAttribute("2FA_USER_ID");
                session.removeAttribute("2FA_USERNAME");

                // Audit log
                auditService.logAction(
                        user,
                        AuditLog.AuditAction.LOGIN_SUCCESS,
                        AuditLog.AuditStatus.SUCCESS,
                        "Successful login with 2FA" + (useBackupCode ? " (backup code)" : ""),
                        getClientIp(request),
                        request.getHeader("User-Agent")
                );

                return "redirect:/vault";

            } else {
                // Invalid code
                log.warn("2FA verification failed - invalid code for user: {}", user.getUsername());

                auditService.logAction(
                        user,
                        AuditLog.AuditAction.LOGIN_FAILURE,
                        AuditLog.AuditStatus.FAILURE,
                        "2FA verification failed - invalid code",
                        getClientIp(request),
                        request.getHeader("User-Agent")
                );

                redirectAttributes.addFlashAttribute("errorMessage",
                        "Invalid verification code. Please try again.");
                return "redirect:/login/2fa";
            }

        } catch (NumberFormatException e) {
            log.warn("2FA verification failed - invalid code format for user: {}", user.getUsername());
            redirectAttributes.addFlashAttribute("errorMessage", "Invalid code format");
            return "redirect:/login/2fa";

        } catch (Exception e) {
            log.error("Error during 2FA verification for user: {}", user.getUsername(), e);

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    AuditLog.AuditStatus.FAILURE,
                    "2FA verification error: " + e.getMessage(),
                    getClientIp(request),
                    request.getHeader("User-Agent")
            );

            redirectAttributes.addFlashAttribute("errorMessage",
                    "An error occurred. Please try again.");
            return "redirect:/login/2fa";
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