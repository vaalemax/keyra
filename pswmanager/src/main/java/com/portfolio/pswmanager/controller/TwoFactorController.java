package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.SessionService;
import com.portfolio.pswmanager.service.TwoFactorService;
import com.portfolio.pswmanager.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

/**
 * Controller for Two-Factor Authentication management.
 */
@Controller
@RequiredArgsConstructor
public class TwoFactorController {

    private static final Logger log = LoggerFactory.getLogger(TwoFactorController.class);

    private final TwoFactorService twoFactorService;
    private final UserService userService;
    private final SessionService sessionService;
    private final AuditService auditService;

    /**
     * Show 2FA setup page.
     */
    @GetMapping("/settings/2fa")
    public String show2FASettings(Authentication authentication, Model model) {
        User user = sessionService.getCurrentUser(authentication);

        log.debug("2FA settings page accessed by user: {}", user.getUsername());

        model.addAttribute("twoFactorEnabled", user.isTwoFactorEnabled());

        return "settings/two-factor";
    }

    /**
     * Start 2FA setup process (generate secret and QR code).
     */
    @GetMapping("/settings/2fa/setup")
    public String setup2FA(Authentication authentication, Model model) {
        User user = sessionService.getCurrentUser(authentication);

        log.info("Starting 2FA setup for user: {}", user.getUsername());

        // Generate secret
        String secret = twoFactorService.generateSecret();

        // Generate QR code URL
        String qrCodeUrl = twoFactorService.generateQrCodeUrl(user.getUsername(), secret);

        // Generate QR code image
        try {
            String qrCodeImage = twoFactorService.generateQrCodeImage(qrCodeUrl);
            model.addAttribute("qrCodeImage", qrCodeImage);
        } catch (Exception e) {
            log.error("Error generating QR code", e);
            model.addAttribute("errorMessage", "Error generating QR code");
            return "settings/two-factor";
        }

        // Generate backup codes
        List<String> backupCodes = twoFactorService.generateBackupCodes();

        model.addAttribute("secret", secret);
        model.addAttribute("backupCodes", backupCodes);
        model.addAttribute("username", user.getUsername());

        return "settings/two-factor-setup";
    }

    /**
     * Verify and enable 2FA.
     */
    @PostMapping("/settings/2fa/enable")
    public String enable2FA(
            @RequestParam String secret,
            @RequestParam String code,
            @RequestParam String backupCodes,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        User user = sessionService.getCurrentUser(authentication);

        log.info("Enabling 2FA for user: {}", user.getUsername());

        try {
            // Verify the TOTP code
            int totpCode = Integer.parseInt(code);
            boolean isValid = twoFactorService.verifyCode(secret, totpCode);

            if (!isValid) {
                log.warn("2FA setup failed - invalid TOTP code for user: {}", user.getUsername());

                auditService.logAction(
                        user,
                        AuditLog.AuditAction.SYSTEM_ERROR,
                        AuditLog.AuditStatus.FAILURE,
                        "2FA setup failed: invalid verification code",
                        auditService.getClientIp(request),
                        auditService.getUserAgent(request)
                );

                redirectAttributes.addFlashAttribute("errorMessage",
                        "Invalid verification code. Please try again.");
                return "redirect:/settings/2fa/setup";
            }

            // Parse backup codes
            List<String> backupCodesList = List.of(backupCodes.split(","));

            // Enable 2FA
            userService.enableTwoFactor(user, secret, backupCodesList);

            // Audit log
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.TWO_FA_ENABLED,  // or create 2FA_ENABLED action
                    AuditLog.AuditStatus.SUCCESS,
                    "Two-Factor Authentication enabled",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            log.info("2FA enabled successfully for user: {}", user.getUsername());

            redirectAttributes.addFlashAttribute("successMessage",
                    "Two-Factor Authentication enabled successfully!");

        } catch (NumberFormatException e) {
            log.warn("2FA setup failed - invalid code format for user: {}", user.getUsername());
            redirectAttributes.addFlashAttribute("errorMessage", "Invalid code format");
            return "redirect:/settings/2fa/setup";

        } catch (Exception e) {
            log.error("Error enabling 2FA for user: {}", user.getUsername(), e);
            redirectAttributes.addFlashAttribute("errorMessage",
                    "An error occurred. Please try again.");
            return "redirect:/settings/2fa/setup";
        }

        return "redirect:/settings/2fa";
    }

    /**
     * Disable 2FA.
     */
    @PostMapping("/settings/2fa/disable")
    public String disable2FA(
            @RequestParam String password,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        User user = sessionService.getCurrentUser(authentication);

        log.info("Disabling 2FA for user: {}", user.getUsername());

        // Verify password before disabling
        if (!userService.verifyPassword(user, password)) {
            log.warn("2FA disable failed - incorrect password for user: {}", user.getUsername());

            redirectAttributes.addFlashAttribute("errorMessage",
                    "Incorrect password");
            return "redirect:/settings/2fa";
        }

        // Disable 2FA
        userService.disableTwoFactor(user);

        // Audit log
        auditService.logAction(
                user,
                AuditLog.AuditAction.TWO_FA_DISABLED,  // or create 2FA_DISABLED action
                AuditLog.AuditStatus.SUCCESS,
                "Two-Factor Authentication disabled",
                auditService.getClientIp(request),
                auditService.getUserAgent(request)
        );

        log.info("2FA disabled successfully for user: {}", user.getUsername());

        redirectAttributes.addFlashAttribute("successMessage",
                "Two-Factor Authentication disabled");

        return "redirect:/settings/2fa";
    }
}