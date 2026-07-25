package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.TwoFactorVerificationResult;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.TwoFactorService;
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

@Controller
@RequiredArgsConstructor
public class TwoFactorVerificationController {

    private final AuditService auditService;

    private final TwoFactorService twoFactorService;


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

        TwoFactorVerificationResult result = twoFactorService.verify(
                userId, code, useBackupCode,
                auditService.getClientIp(request), auditService.getUserAgent(request)
        );

        return switch (result.getStatus()) {
            case SUCCESS -> {
                session.setAttribute("AES_KEY", result.getAesKey());
                session.removeAttribute("2FA_USER_ID");
                session.removeAttribute("2FA_USERNAME");
                if (result.getWarningMessage() != null) {
                    session.setAttribute("warningMessage", result.getWarningMessage());
                }
                yield "redirect:/vault";
            }
            case INVALID_CODE -> {
                redirectAttributes.addFlashAttribute("errorMessage",
                        "Invalid verification code. Please try again.");
                yield "redirect:/login/2fa";
            }
            case INVALID_FORMAT -> {
                redirectAttributes.addFlashAttribute("errorMessage",
                        "Invalid code format");
                yield "redirect:/login/2fa";
            }
            case ERROR -> {
                redirectAttributes.addFlashAttribute("errorMessage", result.getErrorMessage());
                yield "redirect:/login/2fa";
            }
        };
    }
}