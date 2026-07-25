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

@Controller
@RequiredArgsConstructor
public class PasswordChangeController {

    private final AuditService auditService;

    private final CredentialRepository credentialRepository;

    private final SessionService sessionService;

    private final UserService userService;

    private static final Logger log = LoggerFactory.getLogger(PasswordChangeController.class);

    @GetMapping("/settings/password")
    public String showPasswordChangePage(Model model) {
        model.addAttribute("passwordChangeRequest", new PasswordChangeRequest());
        return "password-change";
    }

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

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldError() != null
                    ? bindingResult.getFieldError().getDefaultMessage()
                    : "Invalid input";

            log.warn("Password change validation failed for user: {} - {}",
                    user.getUsername(), errorMessage);

            auditService.auditVaultFailure(
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    "USER",
                    user,
                    user.getId(),
                    "Password change validation failed: " + errorMessage,
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage", errorMessage);
            return "redirect:/settings/password";
        }

        if (request.getCurrentPassword().equals(request.getNewPassword())) {
            log.warn("Password change failed - new password same as current for user: {}",
                    user.getUsername());

            redirectAttributes.addFlashAttribute("errorMessage",
                    "New password must be different from current password");
            return "redirect:/settings/password";
        }

        try {
            SecretKey currentAesKey = sessionService.getAesKeyFromSession(session);

            List<Credential> allCredentials = credentialRepository.findByUserId(user.getId());

            log.debug("Found {} credentials to re-encrypt for user: {}",
                    allCredentials.size(), user.getUsername());

            userService.changeMasterPassword(
                    user,
                    request.getCurrentPassword(),
                    request.getNewPassword(),
                    allCredentials,
                    currentAesKey
            );

            auditService.auditVaultSuccess(
                    AuditLog.AuditAction.PASSWORD_CHANGE,
                    "USER",
                    user,
                    user.getId(),
                    "Master password changed successfully - " + allCredentials.size() +
                            " credentials re-encrypted",
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            log.info("Password changed successfully for user: {}", user.getUsername());

            session.invalidate();

            redirectAttributes.addFlashAttribute("successMessage",
                    "Password changed successfully! Please login with your new password.");

            return "redirect:/login";

        } catch (IllegalArgumentException e) {
            log.warn("Password change failed for user: {} - {}", user.getUsername(), e.getMessage());

            auditService.auditVaultFailure(
                    AuditLog.AuditAction.PASSWORD_CHANGE,
                    "USER",
                    user,
                    user.getId(),
                    "Password change failed: " + e.getMessage(),
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            return "redirect:/settings/password";

        } catch (Exception e) {
            log.error("Unexpected error during password change for user: {}", user.getUsername(), e);

            auditService.auditVaultFailure(
                    AuditLog.AuditAction.PASSWORD_CHANGE,
                    "USER",
                    user,
                    user.getId(),
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