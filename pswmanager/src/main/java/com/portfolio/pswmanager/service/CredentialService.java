package com.portfolio.pswmanager.service;

import com.portfolio.pswmanager.mapper.CredentialMapper;
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
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CredentialService {
    private final CredentialRepository credentialRepository;
    private final EncryptionService encryptionService;
    private final CredentialMapper credentialMapper;
    private final ValidationService validationService;

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    // retrieves and decrypts all the credentials belonging to a user
    @Transactional(readOnly = true)
    public List<CredentialDTO> getAllCredentialsForUser(User user, SecretKey aesKey) {
        log.debug("Retrieving all credentials for user: {}", user.getUsername());
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

    // creates and saves a new crypted credential
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
        log.debug("Password validation passed for service: {}", serviceName);

        // Cripta password
        String encryptedPassword;
        try {
            encryptedPassword = encryptionService.encrypt(plainPassword, aesKey);
            log.debug("Password encrypted successfully for service: {}", serviceName);
        } catch (Exception e) {
            log.error("Error encrypting password for user: {}, service: {}", user.getUsername(), serviceName, e);
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

        log.info("Credential created successfully - ID: {}, user: {}, service: {}", credential.getId(), user.getUsername(), serviceName);

        return credentialRepository.save(credential);
    }

    @Transactional
    public void updateCredential(Long credentialId, User user, CredentialDTO dto, SecretKey aesKey){
        log.info("Updating credential ID: {} for user: {}", credentialId, user.getUsername());
        Credential credential = credentialRepository.findById(credentialId)
                .orElseThrow(() -> {
                    log.warn("Credential not found - ID: {}, user: {}", credentialId, user.getUsername());
                    return new IllegalArgumentException("Credenziale non trovata con ID: " + credentialId);
                });

        if (!credential.getUser().getId().equals(user.getId())) {
            log.warn("Unauthorized update attempt - credential ID: {}, user: {}, owner: {}",
                    credentialId, user.getUsername(), credential.getUser().getUsername());
            throw new SecurityException("Not authorized to modify this credential");
        }

        credentialMapper.updateEntityFromDTO(credential, dto);
        log.debug("Base fields updated for credential ID: {}", credentialId);

        if (dto.getPlainPassword() != null && !dto.getPlainPassword().trim().isEmpty()) {
            validationService.validateCredentialPassword(dto.getPlainPassword());
            try {
                String encryptedPassword = encryptionService.encrypt(dto.getPlainPassword(), aesKey);
                credential.setEncryptedPassword(encryptedPassword);
            } catch (Exception e) {
                log.error("Error encrypting new password for credential ID: {}", credentialId, e);
                throw new RuntimeException("Error encrypting new password", e);
            }
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