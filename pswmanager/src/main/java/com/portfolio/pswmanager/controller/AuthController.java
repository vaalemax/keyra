package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.dto.RegisterRequest;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AuditService auditService;

    @PostMapping("/register")
    public String registerUser(
            @Valid @ModelAttribute RegisterRequest request,
            BindingResult bindingResult,
            RedirectAttributes redirectAttributes,
            HttpServletRequest httpRequest
    ) {
        log.info("Registration request received for username: {}", request.getUsername());

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getFieldError() != null ? bindingResult.getFieldError().getDefaultMessage() : "Invalid data";

            log.warn("Registration validation failed for username: {} - Error: {}", request.getUsername(), errorMessage);

            auditService.logAction(
                    null,
                    AuditLog.AuditAction.REGISTER,
                    AuditLog.AuditStatus.FAILURE,
                    "Username: " + request.getUsername() + " - Validation error: " + errorMessage,
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage", errorMessage);
            redirectAttributes.addFlashAttribute("username", request.getUsername());
            return "redirect:/register";
        }

        try {
            userService.registerUser(request.getUsername(), request.getPassword());

            log.info("Registration successful for username: {}", request.getUsername());

            auditService.logAction(
                    null,
                    AuditLog.AuditAction.REGISTER,
                    AuditLog.AuditStatus.SUCCESS,
                    "New user registered: " + request.getUsername(),
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("successMessage","Registration completed successfully!");
            return "redirect:/login";

        } catch (IllegalArgumentException e) {
            log.warn("Registration failed for username: {} - Reason: {}", request.getUsername(), e.getMessage());

            auditService.logAction(
                    null,
                    AuditLog.AuditAction.REGISTER,
                    AuditLog.AuditStatus.FAILURE,
                    "Username: " + request.getUsername() + " - " + e.getMessage(),
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
            redirectAttributes.addFlashAttribute("username", request.getUsername());
            return "redirect:/register";

        } catch (Exception e) {
            log.error("Unexpected error during registration for username: {}", request.getUsername(), e);

            auditService.logAction(
                    null,
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    AuditLog.AuditStatus.FAILURE,
                    "Registration error for username: " + request.getUsername() + " - " + e.getMessage(),
                    auditService.getClientIp(httpRequest),
                    auditService.getUserAgent(httpRequest)
            );

            redirectAttributes.addFlashAttribute("errorMessage","Error during registration. Please try again.");
            return "redirect:/register";
        }
    }
}
