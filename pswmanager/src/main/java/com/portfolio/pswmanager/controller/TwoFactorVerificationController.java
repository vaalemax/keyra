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

@Controller
@RequiredArgsConstructor
public class TwoFactorVerificationController {

    private final AuditService auditService;

    private final EncryptionService encryptionService;

    private final TwoFactorService twoFactorService;

    private final UserRepository userRepository;

    private final UserService userService;

    private static final Logger log = LoggerFactory.getLogger(TwoFactorVerificationController.class);

    @GetMapping("/login/2fa")
    public String show2FAVerification(HttpSession session, Model model) {
        Long userId = (Long) session.getAttribute("2FA_USER_ID");

        if (userId == null) {
            log.warn("2FA verification page accessed without valid session");
            return "redirect:/login";
        }

        String username = (String) session.getAttribute("2FA_USERNAME");

        model.addAttribute("username", username);

        return "login/two-factor-verify";
    }

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

        boolean isValid;

        try {
            if (useBackupCode) {
                log.debug("Verifying backup code for user: {}", user.getUsername());

                List<String> backupCodes = userService.getBackupCodes(user);
                isValid = twoFactorService.verifyBackupCode(code.trim(), backupCodes, userId);

                if (isValid) {
                    List<String> updatedCodes = twoFactorService.removeBackupCode(code.trim(), backupCodes);
                    userService.updateBackupCodes(user, updatedCodes);

                    if (updatedCodes.size() <= 2) {
                        session.setAttribute("warningMessage",
                                "Warning: You have only " + updatedCodes.size() +
                                        " backup codes remaining.");
                    }
                }
            } else {
                log.debug("Verifying TOTP code for user: {}", user.getUsername());

                int totpCode = Integer.parseInt(code.trim());
                isValid = twoFactorService.verifyCode(user.getTwoFactorSecret(), totpCode);
            }

            if (isValid) {
                log.info("2FA verification successful for user: {}", user.getUsername());

                try {
                    String encryptionKey = user.getEncryptionKey();
                    byte[] combined = Base64.getDecoder().decode(encryptionKey);

                    byte[] salt = new byte[16];
                    byte[] keyBytes = new byte[32];
                    System.arraycopy(combined, 0, salt, 0, 16);
                    System.arraycopy(combined, 16, keyBytes, 0, 32);

                    SecretKey aesKey = encryptionService.recreateKey(keyBytes);
                    session.setAttribute("AES_KEY", aesKey);

                } catch (Exception e) {
                    log.error("Error deriving AES key after 2FA", e);
                    redirectAttributes.addFlashAttribute("errorMessage",
                            "An error occurred. Please try again.");
                    return "redirect:/login";
                }

                session.removeAttribute("2FA_USER_ID");
                session.removeAttribute("2FA_USERNAME");


                auditService.auditVaultSuccess(
                        AuditLog.AuditAction.LOGIN_SUCCESS,
                        "USER",
                        user,
                        userId,
                        "Successful login with 2FA" + (useBackupCode ? " (backup code)" : ""),
                        auditService.getClientIp(request),
                        auditService.getUserAgent(request)
                );

                return "redirect:/vault";

            } else {
                log.warn("2FA verification failed - invalid code for user: {}", user.getUsername());

                auditService.auditVaultFailure(
                        AuditLog.AuditAction.LOGIN_FAILURE,
                        "USER",
                        user,
                        userId,
                        "2FA verification failed - invalid code",
                        auditService.getClientIp(request),
                        auditService.getUserAgent(request)
                );

                redirectAttributes.addFlashAttribute("errorMessage",
                        "Invalid verification code. Please try again.");
                return "redirect:/login/2fa";
            }

        } catch (NumberFormatException e) {
            log.warn("2FA verification failed - invalid code format for user: {}", user.getUsername());
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Invalid code format");
            return "redirect:/login/2fa";

        } catch (Exception e) {
            log.error("Error during 2FA verification for user: {}", user.getUsername(), e);

            auditService.auditVaultFailure(
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    "USER",
                    user,
                    userId,
                    "2FA verification error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage",
                    "An error occurred. Please try again.");
            return "redirect:/login/2fa";
        }
    }
}