package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.Credential;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.model.dto.CredentialDTO;
import com.portfolio.pswmanager.service.AuditService;
import com.portfolio.pswmanager.service.CredentialService;
import com.portfolio.pswmanager.service.EncryptionService;
import com.portfolio.pswmanager.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Controller
@RequiredArgsConstructor
public class VaultController {

    private final AuditService auditService;

    private final CredentialService credentialService;

    private final SessionService sessionService;

    private static final Logger log = LoggerFactory.getLogger(VaultController.class);

    @GetMapping("/vault")
    public String getVault(@RequestParam(required = false) String category,
                           Model model,
                           Authentication authentication,
                           HttpSession session,
                           HttpServletRequest request) {

        User user = sessionService.getCurrentUser(authentication);
        SecretKey aesKey = sessionService.getAesKeyFromSession(session);

        List<CredentialDTO> allCredentials =
                credentialService.getAllCredentialsForUser(user, aesKey);

        List<CredentialDTO> credentials =
                credentialService.getFilteredCredentialsForUser(category, allCredentials);

        long[] stats = credentialService.calculatePasswordStats(credentials);

        Map<String, Long> categoryCount = credentialService.countByCategory(allCredentials);


        credentialService.auditVaultSuccess(
                AuditLog.AuditAction.CREDENTIAL_VIEW,
                user,
                null,
                "Viewed vault - " + allCredentials.size() + " total credentials" +
                        (category != null && !category.equals("all")
                                ? " (showing " + credentials.size() + " in category: " + category + ")"
                                : ""),
                auditService.getClientIp(request),
                auditService.getUserAgent(request)
        );

        model.addAttribute("credentials", credentials);
        model.addAttribute("allCredentials", allCredentials);
        model.addAttribute("totalCount", credentials.size());
        model.addAttribute("secureCount", stats[0]);
        model.addAttribute("weakCount", stats[1]);
        model.addAttribute("selectedCategory", category != null ? category : "all");
        model.addAttribute("categoryCount", categoryCount);

        return "vault";
    }

    @PostMapping("/vault/add")
    public String addCredential(
            @Valid @ModelAttribute CredentialDTO dto,
            BindingResult bindingResult,
            Authentication authentication,
            HttpSession session,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request
    ) {
        User user = sessionService.getCurrentUser(authentication);

        if (dto.getPlainPassword() == null || dto.getPlainPassword().trim().isEmpty()) {
            bindingResult.rejectValue("plainPassword",
                    "error.plainPassword",
                    "Password is required");
        }

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .reduce((a, b) -> a + "; " + b)
                    .orElse("Invalid data");

            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.CREDENTIAL_CREATE,
                    user,
                    null,
                    "Validation error: " +errorMessage,
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage", errorMessage);
            return "redirect:/vault";
        }

        try {
            SecretKey aesKey = sessionService.getAesKeyFromSession(session);

            Credential created = credentialService.createCredential(
                    user,
                    dto.getServiceName(),
                    dto.getUsername(),
                    dto.getPlainPassword(),
                    dto.getUrl(),
                    dto.getNotes(),
                    dto.getCategory(),
                    aesKey
            );

            credentialService.auditVaultSuccess(
                    AuditLog.AuditAction.CREDENTIAL_CREATE,
                    user,
                    created.getId(),
                    "Created credential for service: "+dto.getServiceName(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("successMessage",
                    "Credential saved successfully!");

        } catch (Exception e) {

            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    user,
                    null,
                    "Error: " +e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage",
                    "Error saving credential: " + e.getMessage());
        }

        return "redirect:/vault";
    }

    @PostMapping("/vault/edit/{id}")
    public String updateCredential(
            @PathVariable Long id,
            @Valid @ModelAttribute CredentialDTO dto,
            BindingResult bindingResult,
            Authentication authentication,
            HttpSession session,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request
    ) {
        User user = sessionService.getCurrentUser(authentication);
        SecretKey aesKey = sessionService.getAesKeyFromSession(session);

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .reduce((a, b) -> a + "; " + b)
                    .orElse("Invalid data");

            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    user,
                    id,
                    "Validation error: " + errorMessage,
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage", errorMessage);
            return "redirect:/vault";
        }

        try {

            credentialService.updateCredential(id, user, dto, aesKey);

            credentialService.auditVaultSuccess(
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    user,
                    id,
                    "Updated credential for service: "+dto.getServiceName(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );


            redirectAttributes.addFlashAttribute("successMessage",
                    "Credential updated successfully!");

        } catch (IllegalArgumentException e) {
            log.warn("Edit credential failed - ID: {}, error: {}", id, e.getMessage());

            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    user,
                    id,
                    "Failed to update credential: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        } catch (Exception e) {
            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    user,
                    id,
                    "Error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        }

        return "redirect:/vault";
    }

    @PostMapping("/vault/delete/{id}")
    public String deleteCredential(
            @PathVariable Long id,
            Authentication authentication,
            RedirectAttributes redirectAttributes,
            HttpServletRequest request
    ) {
        User user = sessionService.getCurrentUser(authentication);

        try {
            credentialService.deleteCredential(id, user);

            credentialService.auditVaultSuccess(
                    AuditLog.AuditAction.CREDENTIAL_DELETE,
                    user,
                    id,
                    "Deleted credential ID: " + id,
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("successMessage",
                    "Credential deleted!");

        } catch (Exception e) {

            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.CREDENTIAL_DELETE,
                    user,
                    id,
                    "Error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage",
                    "Error during deletion");
        }

        return "redirect:/vault";
    }

    @GetMapping("/vault/export")
    public ResponseEntity<byte[]> exportVault(
            Authentication authentication,
            HttpSession session,
            HttpServletRequest request
    ) {
        try {
            User user = sessionService.getCurrentUser(authentication);
            SecretKey aesKey = sessionService.getAesKeyFromSession(session);

            List<CredentialDTO> credentials = credentialService.exportVault(user, aesKey);

            credentialService.auditVaultSuccess(
                    AuditLog.AuditAction.VAULT_EXPORT,
                    user,
                    null,
                    "Exported " + credentials.size() + " credentials",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            String encryptedData = credentialService.encryptVaultData(user, credentials, aesKey);

            String timestamp = LocalDateTime.now().format(
                    DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
            String filename = "vaultshield_backup_" + timestamp + ".encrypted";

            log.info("Vault exported successfully - {} credentials", credentials.size());

            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; " +
                            "filename=\"" + filename + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(encryptedData.getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            log.error("Error exporting vault", e);
            User user = sessionService.getCurrentUser(authentication);

            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.VAULT_EXPORT,
                    user,
                    null,
                    "Error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/vault/import")
    public String importVault(
            @RequestParam("file") MultipartFile file,
            @RequestParam(defaultValue = "false") boolean replaceExisting,
            Authentication authentication,
            HttpSession session,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes
    ) {
        try {
            User user = sessionService.getCurrentUser(authentication);
            SecretKey aesKey = sessionService.getAesKeyFromSession(session);


            int[] importCount = credentialService.importVault(user, aesKey, replaceExisting, file);

            credentialService.auditVaultSuccess(
                    AuditLog.AuditAction.VAULT_IMPORT,
                    user,
                    null,
                    "Imported " + importCount[0] + " credentials " +
                            "(skipped: " + importCount[1] + ")",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            log.info("Vault imported - imported: {}, skipped: {}", importCount[0], importCount[1]);

            redirectAttributes.addFlashAttribute("successMessage",
                    "Successfully imported " + importCount[0] + " credentials" +
                            (importCount[1] > 0 ? " (skipped " + importCount[1] + " duplicates)" : ""));

        } catch (IllegalArgumentException e) {
            log.warn("Import validation error: {}", e.getMessage());

            User user = sessionService.getCurrentUser(authentication);
            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.VAULT_IMPORT,
                    user,
                    null,
                    "Validation error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());

        } catch (Exception e) {
            log.error("Error importing vault", e);

            User user = sessionService.getCurrentUser(authentication);
            credentialService.auditVaultFailure(
                    AuditLog.AuditAction.VAULT_IMPORT,
                    user,
                    null,
                    "Error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage",
                    "Failed to import vault. Make sure the file was exported " +
                            "with the same account and password.");
        }
        return "redirect:/vault";
    }
}