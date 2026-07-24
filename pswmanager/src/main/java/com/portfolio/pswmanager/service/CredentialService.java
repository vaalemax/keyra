package com.portfolio.pswmanager.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.portfolio.pswmanager.mapper.CredentialMapper;
import com.portfolio.pswmanager.model.AuditLog;
import com.portfolio.pswmanager.model.Credential;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.model.dto.CredentialDTO;
import com.portfolio.pswmanager.model.dto.VaultExportDTO;
import com.portfolio.pswmanager.repository.CredentialRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
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

    public long[] calculatePasswordStats(List<CredentialDTO> credentials) {
        long secureCount = credentials.stream()
                .filter(c -> validationService.isPasswordSecure(c.getDecryptedPassword()))
                .count();
        long weakCount = credentials.size() - secureCount;
        return new long[]{secureCount, weakCount};
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

    @Transactional
    public void deleteCredential(Long credentialId, User user) {
        log.info("Deleting credential ID: {} for user: {}", credentialId, user.getUsername());
        Credential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> new
                IllegalArgumentException("Credential not found with ID: " + credentialId)
                );

        if (!credential.getUser().getId().equals(user.getId()))
            throw new SecurityException("Not authorized to delete this credential");

        credential.setActive(false);
        credential.setUpdatedAt(LocalDateTime.now());
        credentialRepository.save(credential);

        log.info("Credential soft deleted successfully - ID: {}, user: {}", credentialId, user.getUsername());
    }

    @Transactional
    public List<CredentialDTO> exportVault(User user, SecretKey aesKey) {
        log.info("Exporting vault for user: {}", user.getUsername());

        return this.getAllCredentialsForUser(user, aesKey);
    }

    public String encryptVaultData(User user, List<CredentialDTO> credentials, SecretKey aesKey) throws Exception {
        VaultExportDTO exportData = VaultExportDTO.create(user.getUsername(), credentials);

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        String json = mapper.writeValueAsString(exportData);

        log.debug("Vault JSON size: {} bytes", json.length());
        return encryptionService.encrypt(json, aesKey);
    }

    @Transactional
    public int[] importVault(User user, SecretKey aesKey, boolean replaceExisting,
                            MultipartFile file) throws Exception {
        log.info("Importing vault for user: {} - replace: {}", user.getUsername(), replaceExisting);

        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }

        if (file.getSize() > 10 * 1024 * 1024) {
            throw new IllegalArgumentException("File too large (max 10 MB)");
        }

        String encryptedData = new String(file.getBytes(), StandardCharsets.UTF_8);

        String json = encryptionService.decrypt(encryptedData, aesKey);

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        VaultExportDTO importData = mapper.readValue(json, VaultExportDTO.class);

        if (importData.getCredentials() == null || importData.getCredentials().isEmpty())
            throw new IllegalArgumentException("No credentials found in import file");

        if (replaceExisting) {
            List<CredentialDTO> existing = this.getAllCredentialsForUser(user, aesKey);
            for (CredentialDTO cred : existing) {
                this.deleteCredential(cred.getId(), user);
            }
            log.info("Deleted {} existing credentials", existing.size());
        }

        int imported = 0;
        int skipped = 0;

        for (CredentialDTO dto : importData.getCredentials()) {
            try {
                List<CredentialDTO> existing = this.getAllCredentialsForUser(user, aesKey);
                boolean isDuplicate = existing.stream()
                        .anyMatch(e -> e.getServiceName().equals(dto.getServiceName())
                                && e.getUsername().equals(dto.getUsername()));

                if (isDuplicate && !replaceExisting) {
                    log.debug("Skipping duplicate: {} - {}", dto.getServiceName(), dto.getUsername());
                    skipped++;
                    continue;
                }

                this.createCredential(
                        user,
                        dto.getServiceName(),
                        dto.getUsername(),
                        dto.getDecryptedPassword(),
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

        return new int[]{imported, skipped};
    }
}