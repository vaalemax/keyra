package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.SessionService;
import com.portfolio.pswmanager.service.TwoFactorService;
import com.portfolio.pswmanager.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
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

@Controller
public class TwoFactorController {

    private final AuditService auditService;

    private final SessionService sessionService;

    private final TwoFactorService twoFactorService;

    private final UserService userService;

    private static final Logger log = LoggerFactory.getLogger(TwoFactorController.class);

    public TwoFactorController(AuditService auditService,
                               SessionService sessionService,
                               TwoFactorService twoFactorService,
                               UserService userService) {
        this.auditService = auditService;
        this.sessionService = sessionService;
        this.twoFactorService = twoFactorService;
        this.userService = userService;
    }

    @GetMapping("/settings/2fa")
    public String show2FASettings(Authentication authentication, Model model) {
        User user = sessionService.getCurrentUser(authentication);
        model.addAttribute("twoFactorEnabled", user.isTwoFactorEnabled());

        return "login/two-factor";
    }

    @GetMapping("/settings/2fa/setup")
    public String setup2FA(Authentication authentication, Model model) {
        User user = sessionService.getCurrentUser(authentication);

        String secret = twoFactorService.generateSecret();
        String qrCodeUrl = twoFactorService.generateQrCodeUrl(user.getUsername(), secret);

        try {
            String qrCodeImage = twoFactorService.generateQrCodeImage(qrCodeUrl);
            model.addAttribute("qrCodeImage", qrCodeImage);
        } catch (Exception e) {
            log.error("Error generating QR code", e);
            model.addAttribute("errorMessage", "Error generating QR code");
            return "login/two-factor";
        }

        List<String> backupCodes = twoFactorService.generateBackupCodes();

        model.addAttribute("secret", secret);
        model.addAttribute("backupCodes", backupCodes);
        model.addAttribute("username", user.getUsername());

        return "login/two-factor-setup";
    }

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

        try {
            int totpCode = Integer.parseInt(code);
            boolean isValid = twoFactorService.verifyCode(secret, totpCode);

            if (!isValid) {
                log.warn("2FA setup failed - invalid TOTP code for user: {}", user.getUsername());

                auditService.auditVaultFailure(
                        AuditLog.AuditAction.SYSTEM_ERROR,
                        "USER",
                        user,
                        user.getId(),
                        "2FA setup failed: invalid verification code",
                        auditService.getClientIp(request),
                        auditService.getUserAgent(request)
                );

                redirectAttributes.addFlashAttribute("errorMessage",
                        "Invalid verification code. Please try again.");
                return "redirect:/settings/2fa/setup";
            }

            List<String> backupCodesList = List.of(backupCodes.split(","));

            userService.enableTwoFactor(user, secret, backupCodesList);

            auditService.auditVaultSuccess(
                    AuditLog.AuditAction.TWO_FA_ENABLED,
                    "USER",
                    user,
                    user.getId(),
                    "Two-Factor Authentication enabled",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("successMessage",
                    "Two-Factor Authentication enabled successfully!");

        } catch (NumberFormatException e) {
            log.warn("2FA setup failed - invalid code format for user: {}", user.getUsername());
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Invalid code format");
            return "redirect:/settings/2fa/setup";

        } catch (Exception e) {
            log.error("Error enabling 2FA for user: {}", user.getUsername(), e);
            redirectAttributes.addFlashAttribute("errorMessage",
                    "An error occurred. Please try again.");
            return "redirect:/settings/2fa/setup";
        }

        return "redirect:/settings/2fa";
    }

    @PostMapping("/settings/2fa/disable")
    public String disable2FA(
            @RequestParam String password,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        User user = sessionService.getCurrentUser(authentication);

        if (!userService.verifyPassword(user, password)) {
            log.warn("2FA disable failed - incorrect password for user: {}", user.getUsername());

            redirectAttributes.addFlashAttribute("errorMessage",
                    "Incorrect password");
            return "redirect:/settings/2fa";
        }

        userService.disableTwoFactor(user);

        auditService.auditVaultSuccess(
                AuditLog.AuditAction.TWO_FA_DISABLED,
                "USER",
                user,
                user.getId(),
                "Two-Factor Authentication disabled",
                auditService.getClientIp(request),
                auditService.getUserAgent(request)
        );

        redirectAttributes.addFlashAttribute("successMessage",
                "Two-Factor Authentication disabled");

        return "redirect:/settings/2fa";
    }
}