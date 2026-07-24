package com.portfolio.pswmanager.service;

import com.portfolio.pswmanager.mapper.CredentialMapper;
import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.Credential;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.model.dto.CredentialDTO;
import com.portfolio.pswmanager.repository.CredentialRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CredentialService {

    private final AuditService auditService;

    private final CredentialMapper credentialMapper;

    private final CredentialRepository credentialRepository;

    private final EncryptionService encryptionService;

    private final ValidationService validationService;

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    // retrieves and decrypts all the credentials belonging to a user
    @Transactional(readOnly = true)
    public List<CredentialDTO> getAllCredentialsForUser(User user, SecretKey aesKey) {

        List<Credential> credentials = credentialRepository.findByUserIdAndIsActiveTrueOrderByCreatedAtDesc(user.getId());
        log.debug("Found {} active credentials for user: {}", credentials.size(), user.getUsername());

        return credentials.stream()
                .map(cred -> {
                    try {
                        String decryptedPassword = encryptionService.decrypt(cred.getEncryptedPassword(), aesKey);
                        return credentialMapper.toDTO(cred, decryptedPassword);
                    } catch (Exception e) {
                        log.error("Error decrypting credential ID {} for user: {}",cred.getId(), user.getUsername(), e);
                        throw new RuntimeException("Error decrypting credential ID " + cred.getId(), e);
                    }
                })
                .collect(Collectors.toList());
    }

    public List<CredentialDTO> getFilteredCredentialsForUser(String category, List<CredentialDTO> allCredentials){
        if (category == null || category.isEmpty() || category.equals("all")) {
            return allCredentials;
        }
        return allCredentials.stream()
                .filter(c -> category.equals(c.getCategory()))
                .toList();
    }

    public Map<String, Long> countByCategory(List<CredentialDTO> credentials){
        return credentials.stream()
                .collect(Collectors.groupingBy(
                        c -> c.getCategory() != null ? c.getCategory() : "other",
                        Collectors.counting()
                ));
    }

    public void auditVaultView(User user, int totalCount, int filteredCount,
                               String category, String clientIp, String userAgent) {
        String message = "Viewed vault - " + totalCount + " total credentials" +
                (category != null && !category.equals("all")
                        ? " (showing " + filteredCount + " in category: " + category + ")"
                        : "");

        auditService.logAction(
                user,
                AuditLog.AuditAction.CREDENTIAL_VIEW,
                AuditLog.AuditStatus.SUCCESS,
                message,
                clientIp,
                userAgent
        );
    }

    public void auditVaultSuccess(AuditLog.AuditAction auditAction, User user, Long credentialId,
                                  String serviceName, String clientIp, String userAgent) {
        auditService.logActionWithEntity(
                user,
                auditAction,
                AuditLog.AuditStatus.SUCCESS,
                "CREDENTIAL",
                credentialId,
                "Created credential for service: " + serviceName,
                clientIp,
                userAgent
        );
    }

    public void auditVaultFailure(AuditLog.AuditAction auditAction, User user, Long credentialId,
                                  String reason, String clientIp, String userAgent){
        auditService.logActionWithEntity(
                user,
                auditAction,
                AuditLog.AuditStatus.FAILURE,
                "CREDENTIAL",
                credentialId,
                reason,
                clientIp,
                userAgent
        );
    }

    @Transactional
    public Credential createCredential(
            User user,
            String serviceName,
            String username,
            String plainPassword,
            String url,
            String notes,
            String category,
            SecretKey aesKey
    ) {
        log.info("Creating credential for user: {}, service: {}", user.getUsername(), serviceName);
        validationService.validateCredentialPassword(plainPassword);

        String encryptedPassword;
        try {
            encryptedPassword = encryptionService.encrypt(plainPassword, aesKey);
        } catch (Exception e) {
            throw new RuntimeException("Error during password encryption", e);
        }

        CredentialDTO dto = new CredentialDTO();
        dto.setServiceName(serviceName);
        dto.setUsername(username);
        dto.setUrl(url);
        dto.setNotes(notes);
        dto.setCategory(category);

        Credential credential = credentialMapper.toEntity(dto);
        credential.setUser(user);
        credential.setEncryptedPassword(encryptedPassword);

        log.info("Credential created successfully - ID: {}, user: {}, service: {}",
                credential.getId(), user.getUsername(), serviceName);

        return credentialRepository.save(credential);
    }

    @Transactional
    public void updateCredential(Long credentialId, User user, CredentialDTO dto, SecretKey aesKey){
        log.info("Updating credential ID: {} for user: {}", credentialId, user.getUsername());
        Credential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Credential not found with ID: " + credentialId)
                );

        if (!credential.getUser().getId().equals(user.getId())) {
            throw new SecurityException("Not authorized to modify this credential");
        }

        credentialMapper.updateEntityFromDTO(credential, dto);

        if (dto.getPlainPassword() != null && !dto.getPlainPassword().trim().isEmpty()) {
            validationService.validateCredentialPasswordIfPresent(dto.getPlainPassword());
            try {
                String encryptedPassword = encryptionService.encrypt(dto.getPlainPassword(), aesKey);
                credential.setEncryptedPassword(encryptedPassword);
            } catch (Exception e) {
                throw new RuntimeException("Error encrypting new password", e);
            }
        } else {
            log.debug("Password not changed for credential ID: {}", credentialId);
        }

        log.info("Credential updated successfully - ID: {}, user: {}", credentialId, user.getUsername());
        credentialRepository.save(credential);
    }

    // deletes a credential verifying that it belongs to a user
    @Transactional
    public void deleteCredential(Long credentialId, User user) {
        log.info("Deleting credential ID: {} for user: {}", credentialId, user.getUsername());
        Credential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> {
                    log.warn("Credential not found for deletion - ID: {}, user: {}",
                            credentialId, user.getUsername());
                    return new IllegalArgumentException("Credential not found with ID: " + credentialId);
                });

        // Verifica ownership
        if (!credential.getUser().getId().equals(user.getId())) {
            log.warn("Unauthorized delete attempt - credential ID: {}, user: {}, owner: {}",
                    credentialId, user.getUsername(), credential.getUser().getUsername());
            throw new SecurityException("Not authorized to delete this credential");
        }

        credential.setActive(false);
        credential.setUpdatedAt(LocalDateTime.now());
        credentialRepository.save(credential);

        log.info("Credential soft deleted successfully - ID: {}, user: {}", credentialId, user.getUsername());
    }

    // calculates passwords safety statistics
    public long[] calculatePasswordStats(List<CredentialDTO> credentials) {
        log.debug("Calculating password statistics for {} credentials", credentials.size());
        long secureCount = credentials.stream()
                .filter(c -> validationService.isPasswordSecure(c.getDecryptedPassword()))
                .count();

        long weakCount = credentials.size() - secureCount;
        log.debug("Password stats - secure: {}, weak: {}", secureCount, weakCount);

        return new long[]{secureCount, weakCount};
    }
}