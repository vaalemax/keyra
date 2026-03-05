package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.Credential;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.model.dto.PasswordChangeRequest;
import com.portfolio.pswmanager.repository.CredentialRepository;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.SessionService;
import com.portfolio.pswmanager.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.crypto.SecretKey;
import java.util.List;

/**
 * Controller for password change functionality.
 */
@Controller
@RequiredArgsConstructor
public class PasswordChangeController {

    private static final Logger log = LoggerFactory.getLogger(PasswordChangeController.class);

    private final UserService userService;
    private final SessionService sessionService;
    private final CredentialRepository credentialRepository;
    private final AuditService auditService;

    /**
     * Show password change page.
     */
    @GetMapping("/settings/password")
    public String showPasswordChangePage(Model model) {
        model.addAttribute("passwordChangeRequest", new PasswordChangeRequest());
        return "password-change";
    }

    /**
     * Process password change request.
     */
    @PostMapping("/settings/password")
    public String changePassword(
            @Valid @ModelAttribute PasswordChangeRequest request,
            BindingResult bindingResult,
            Authentication authentication,
            HttpSession session,
            HttpServletRequest httpRequest,
            RedirectAttributes redirectAttributes
    ) {
        User user = sessionService.getCurrentUser(authentication);

        log.info("Password change request from user: {}", user.getUsername());

        // Check for validation errors
        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldError() != null
                    ? bindingResult.getFieldError().getDefaultMessage()
                    : "Invalid input";

            log.warn("Password change validation failed for user: {} - {}",
                    user.getUsername(), errorMessage);

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    AuditLog.AuditStatus.FAILURE,
                    "Password change validation failed: " + errorMessage,
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage", errorMessage);
            return "redirect:/settings/password";
        }

        // Check if passwords match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            log.warn("Password change failed - passwords don't match for user: {}", user.getUsername());

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    AuditLog.AuditStatus.FAILURE,
                    "Password change failed: passwords don't match",
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage",
                    "New password and confirmation do not match");
            return "redirect:/settings/password";
        }

        // Check if new password is same as current
        if (request.getCurrentPassword().equals(request.getNewPassword())) {
            log.warn("Password change failed - new password same as current for user: {}",
                    user.getUsername());

            redirectAttributes.addFlashAttribute("errorMessage",
                    "New password must be different from current password");
            return "redirect:/settings/password";
        }

        try {
            // Get current AES key from session
            SecretKey currentAesKey = sessionService.getAesKeyFromSession(session);

            // Get all credentials
            List<Credential> allCredentials = credentialRepository.findByUserId(user.getId());

            log.debug("Found {} credentials to re-encrypt for user: {}",
                    allCredentials.size(), user.getUsername());

            // Change password (this will re-encrypt all credentials)
            userService.changeMasterPassword(
                    user,
                    request.getCurrentPassword(),
                    request.getNewPassword(),
                    allCredentials,
                    currentAesKey
            );

            // Audit log success
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.PASSWORD_CHANGE,
                    AuditLog.AuditStatus.SUCCESS,
                    "Master password changed successfully - " + allCredentials.size() + " credentials re-encrypted",
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            log.info("Password changed successfully for user: {}", user.getUsername());

            // Invalidate session (force re-login with new password)
            session.invalidate();

            redirectAttributes.addFlashAttribute("successMessage",
                    "Password changed successfully! Please login with your new password.");

            return "redirect:/login";

        } catch (IllegalArgumentException e) {
            log.warn("Password change failed for user: {} - {}", user.getUsername(), e.getMessage());

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.PASSWORD_CHANGE,
                    AuditLog.AuditStatus.FAILURE,
                    "Password change failed: " + e.getMessage(),
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/settings/password";

        } catch (Exception e) {
            log.error("Unexpected error during password change for user: {}", user.getUsername(), e);

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.PASSWORD_CHANGE,
                    AuditLog.AuditStatus.FAILURE,
                    "Password change error: " + e.getMessage(),
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage",
                    "An unexpected error occurred. Please try again.");
            return "redirect:/settings/password";
        }
    }
}