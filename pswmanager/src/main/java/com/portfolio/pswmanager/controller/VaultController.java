package com.portfolio.pswmanager.controller;

import com.fasterxml.jackson.databind.SerializationFeature;
import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.Credential;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.model.dto.CredentialDTO;
import com.portfolio.pswmanager.model.dto.VaultExportDTO;
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class VaultController {
    private final CredentialService credentialService;
    private final EncryptionService encryptionService;
    private final SessionService sessionService;
    private final AuditService auditService;

    private static final Logger log = LoggerFactory.getLogger(VaultController.class);

    @GetMapping("/vault")
    public String getVault(@RequestParam(required = false) String category, Model model, Authentication authentication, HttpSession session, HttpServletRequest request) {

        log.info("=== VAULT ACCESS DEBUG ===");
        log.info("Session ID: {}", session.getId());
        log.info("Session creation time: {}", new Date(session.getCreationTime()));
        log.info("Session last accessed: {}", new Date(session.getLastAccessedTime()));
        log.info("Session attributes: {}", Collections.list(session.getAttributeNames()));

        Object aesKeyObj = session.getAttribute("aesKey");
        log.info("AES key in session: {}", aesKeyObj != null ? "PRESENT" : "NULL");
        log.info("AES key class: {}", aesKeyObj != null ? aesKeyObj.getClass().getName() : "N/A");


        log.debug("Vault page accessed by user: {}", authentication.getName());

        User user = sessionService.getCurrentUser(authentication);
        SecretKey aesKey = sessionService.getAesKeyFromSession(session);
        log.debug("Vault page accessed by user: {}", user.getUsername());

        log.info("AES key in session: {}", aesKey != null ? "PRESENT" : "NULL");

        List<CredentialDTO> allCredentials = credentialService.getAllCredentialsForUser(user, aesKey);

        List<CredentialDTO> credentials = allCredentials;
        if (category != null && !category.isEmpty() && !category.equals("all")) {
            credentials = allCredentials.stream()
                    .filter(c -> category.equals(c.getCategory()))
                    .toList();

            log.debug("Filtered credentials by category: {} - {} results", category, credentials.size());
        }

        long[] stats = credentialService.calculatePasswordStats(credentials);
        long totalCount = credentials.size();
        long secureCount = stats[0];
        long weakCount = stats[1];

        Map<String, Long> categoryCount = allCredentials.stream()
                .collect(Collectors.groupingBy(
                        c -> c.getCategory() != null ? c.getCategory() : "other",
                        Collectors.counting()
                ));

        model.addAttribute("credentials", credentials);           // Credenziali visualizzate
        model.addAttribute("allCredentials", allCredentials);    // Tutte (per il count nel dropdown)
        model.addAttribute("totalCount", totalCount);            // Totale filtrate
        model.addAttribute("secureCount", secureCount);          // Sicure filtrate
        model.addAttribute("weakCount", weakCount);              // Deboli filtrate
        model.addAttribute("selectedCategory", category != null ? category : "all");
        model.addAttribute("categoryCount", categoryCount);

        auditService.logAction(
                user,
                AuditLog.AuditAction.CREDENTIAL_VIEW,
                AuditLog.AuditStatus.SUCCESS,
                "Viewed vault - " + allCredentials.size() + " total credentials" +
                        (category != null && !category.equals("all") ? " (showing " + credentials.size() + " in category: " + category + ")" : ""),
                auditService.getClientIp(request),
                auditService.getUserAgent(request)
        );

        log.debug("Vault rendered - {} credentials loaded", credentials.size());

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
            bindingResult.rejectValue("plainPassword", "error.plainPassword", "Password is required");
        }

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .reduce((a, b) -> a + "; " + b)
                    .orElse("Invalid data");

            // Audit log failure
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_CREATE,
                    AuditLog.AuditStatus.FAILURE,
                    "Validation error: " + errorMessage,
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

            // Audit log success
            auditService.logActionWithEntity(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_CREATE,
                    AuditLog.AuditStatus.SUCCESS,
                    "CREDENTIAL",
                    created.getId(),
                    "Created credential for service: " + dto.getServiceName(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("successMessage","Credential saved successfully!");

        } catch (Exception e) {
            // Audit log failure
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_CREATE,
                    AuditLog.AuditStatus.FAILURE,
                    "Error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage","Error saving credential: " + e.getMessage());
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
            HttpServletRequest request  // Inject request
    ) {
        User user = sessionService.getCurrentUser(authentication);
        SecretKey aesKey = sessionService.getAesKeyFromSession(session);

        log.info("Edit credential request - ID: {}, user: {}", id, user.getUsername());

        if (bindingResult.hasErrors()) {
            String errorMessage = bindingResult.getAllErrors().stream()
                    .map(DefaultMessageSourceResolvable::getDefaultMessage)
                    .reduce((a, b) -> a + "; " + b)
                    .orElse("Invalid data");

            // Audit log failure
            auditService.logActionWithEntity(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    AuditLog.AuditStatus.FAILURE,
                    "CREDENTIAL",
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

            // Audit log success
            auditService.logActionWithEntity(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    AuditLog.AuditStatus.SUCCESS,
                    "CREDENTIAL",
                    id,
                    "Updated credential for service: " + dto.getServiceName(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            log.info("Credential edited successfully - ID: {}, user: {}", id, user.getUsername());
            redirectAttributes.addFlashAttribute("successMessage",
                    "Credential updated successfully!");

        } catch (IllegalArgumentException e) {
            log.warn("Edit credential failed - ID: {}, error: {}", id, e.getMessage());

            auditService.logAction(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    AuditLog.AuditStatus.FAILURE,
                    "Failed to update credential: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());
        } catch (Exception e) {
            // Audit log failure
            auditService.logActionWithEntity(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_UPDATE,
                    AuditLog.AuditStatus.FAILURE,
                    "CREDENTIAL",
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
            HttpServletRequest request  // Inject request
    ) {
        User user = sessionService.getCurrentUser(authentication);

        try {
            credentialService.deleteCredential(id, user);

            // Audit log success
            auditService.logActionWithEntity(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_DELETE,
                    AuditLog.AuditStatus.SUCCESS,
                    "CREDENTIAL",
                    id,
                    "Deleted credential ID: " + id,
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("successMessage", "Credential deleted!");

        } catch (Exception e) {
            // Audit log failure
            auditService.logActionWithEntity(
                    user,
                    AuditLog.AuditAction.CREDENTIAL_DELETE,
                    AuditLog.AuditStatus.FAILURE,
                    "CREDENTIAL",
                    id,
                    "Error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage", "Error during deletion");
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

            log.info("Exporting vault for user: {}", user.getUsername());

            // Get all credentials
            List<CredentialDTO> credentials = credentialService.getAllCredentialsForUser(user, aesKey);

            // Create export DTO
            VaultExportDTO exportData = VaultExportDTO.create(user.getUsername(), credentials);

            // Convert to JSON
            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule()); // For LocalDateTime
            mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            String json = mapper.writeValueAsString(exportData);

            log.debug("Vault JSON size: {} bytes", json.length());

            // Encrypt the JSON
            String encryptedData = encryptionService.encrypt(json, aesKey);

            // Generate filename with timestamp
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss"));
            String filename = "vaultshield_backup_" + timestamp + ".encrypted";

            // Audit log
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.VAULT_EXPORT,
                    AuditLog.AuditStatus.SUCCESS,
                    "Exported " + credentials.size() + " credentials",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            log.info("Vault exported successfully - {} credentials", credentials.size());

            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"" + filename + "\"")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(encryptedData.getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            log.error("Error exporting vault", e);

            User user = sessionService.getCurrentUser(authentication);
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.VAULT_EXPORT,
                    AuditLog.AuditStatus.FAILURE,
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

            log.info("Importing vault for user: {} - replace: {}", user.getUsername(), replaceExisting);

            // Validate file
            if (file.isEmpty()) {
                throw new IllegalArgumentException("File is empty");
            }

            if (file.getSize() > 10 * 1024 * 1024) { // 10 MB limit
                throw new IllegalArgumentException("File too large (max 10 MB)");
            }

            // Read encrypted data
            String encryptedData = new String(file.getBytes(), StandardCharsets.UTF_8);

            // ✅ Decrypt with SESSION KEY (same key used for export)
            String json = encryptionService.decrypt(encryptedData, aesKey);

            // Parse JSON
            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            VaultExportDTO importData = mapper.readValue(json, VaultExportDTO.class);

            log.debug("Import data version: {}, credential count: {}",
                    importData.getVersion(), importData.getCredentialCount());

            // Validate import data
            if (importData.getCredentials() == null || importData.getCredentials().isEmpty()) {
                throw new IllegalArgumentException("No credentials found in import file");
            }

            // If replace existing, delete all current credentials
            if (replaceExisting) {
                List<CredentialDTO> existing = credentialService.getAllCredentialsForUser(user, aesKey);
                for (CredentialDTO cred : existing) {
                    credentialService.deleteCredential(cred.getId(), user);
                }
                log.info("Deleted {} existing credentials", existing.size());
            }

            // Import credentials
            int imported = 0;
            int skipped = 0;

            for (CredentialDTO dto : importData.getCredentials()) {
                try {
                    // Check for duplicates (same service + username)
                    List<CredentialDTO> existing = credentialService.getAllCredentialsForUser(user, aesKey);
                    boolean isDuplicate = existing.stream()
                            .anyMatch(e -> e.getServiceName().equals(dto.getServiceName())
                                    && e.getUsername().equals(dto.getUsername()));

                    if (isDuplicate && !replaceExisting) {
                        log.debug("Skipping duplicate: {} - {}", dto.getServiceName(), dto.getUsername());
                        skipped++;
                        continue;
                    }

                    // Import credential
                    credentialService.createCredential(
                            user,
                            dto.getServiceName(),
                            dto.getUsername(),
                            dto.getDecryptedPassword(), // Password is already decrypted in the export
                            dto.getUrl(),
                            dto.getNotes(),
                            dto.getCategory(),
                            aesKey
                    );

                    imported++;

                } catch (Exception e) {
                    log.warn("Error importing credential: {} - {}", dto.getServiceName(), e.getMessage());
                    skipped++;
                }
            }

            // Audit log
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.VAULT_IMPORT,
                    AuditLog.AuditStatus.SUCCESS,
                    "Imported " + imported + " credentials (skipped: " + skipped + ")",
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            log.info("Vault imported - imported: {}, skipped: {}", imported, skipped);

            redirectAttributes.addFlashAttribute("successMessage",
                    "Successfully imported " + imported + " credentials" +
                            (skipped > 0 ? " (skipped " + skipped + " duplicates)" : ""));

        } catch (IllegalArgumentException e) {
            log.warn("Import validation error: {}", e.getMessage());

            User user = sessionService.getCurrentUser(authentication);
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.VAULT_IMPORT,
                    AuditLog.AuditStatus.FAILURE,
                    "Validation error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage", e.getMessage());

        } catch (Exception e) {
            log.error("Error importing vault", e);

            User user = sessionService.getCurrentUser(authentication);
            auditService.logAction(
                    user,
                    AuditLog.AuditAction.VAULT_IMPORT,
                    AuditLog.AuditStatus.FAILURE,
                    "Error: " + e.getMessage(),
                    auditService.getClientIp(request),
                    auditService.getUserAgent(request)
            );

            redirectAttributes.addFlashAttribute("errorMessage",
                    "Failed to import vault. Make sure the file was exported with the same account and password.");
        }

        return "redirect:/vault";
    }
}