package com.portfolio.pswmanager.service;

import com.portfolio.pswmanager.model.Credential;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.repository.CredentialRepository;
import com.portfolio.pswmanager.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class UserService {
    private final CredentialRepository credentialRepository;

    private final EncryptionService encryptionService;

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    private final ValidationService validationService;

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    public UserService(CredentialRepository credentialRepository,
                       EncryptionService encryptionService,
                       PasswordEncoder passwordEncoder,
                       UserRepository userRepository,
                       ValidationService validationService) {
        this.credentialRepository = credentialRepository;
        this.encryptionService = encryptionService;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.validationService = validationService;
    }

    public void registerUser(String username, String masterPassword) throws Exception {

        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("Username is already used");
        }

        List<String> errors = validationService.validateMasterPassword(masterPassword);
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(
                    "Master password requirements: " +
                            String.join(", ", errors));
        }

        String hashedPassword = passwordEncoder.encode(masterPassword);

        byte[] salt = encryptionService.generateSalt();

        SecretKey aesKey = encryptionService.deriveKeyFromPassword(masterPassword, salt);

        byte[] combined = new byte[salt.length + aesKey.getEncoded().length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(aesKey.getEncoded(), 0, combined, salt.length,
                aesKey.getEncoded().length);
        String encryptionKey = Base64.getEncoder().encodeToString(combined);

        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(hashedPassword);
        user.setEncryptionKey(encryptionKey);

        userRepository.save(user);

        log.info("User registered successfully - username: {}", username);
    }

    @Transactional
    public void changeMasterPassword(
            User user,
            String currentPassword,
            String newPassword,
            List<Credential> allCredentials,
            SecretKey currentAesKey
    ) throws Exception {
        log.info("Changing master password for user: {}", user.getUsername());

        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            log.warn("Password change failed - incorrect current password for user: {}",
                    user.getUsername());
            throw new IllegalArgumentException("Current password is incorrect");
        }

        if (currentPassword.equals(newPassword)) {
            log.warn(
                    "Password change failed - new password same as current for user: {}",
                    user.getUsername());
            throw new IllegalArgumentException(
                    "New password must be different from current password");
        }

        List<String> validationErrors = validationService.validateMasterPassword(newPassword);
        if (!validationErrors.isEmpty()) {
            log.warn("Password change failed - validation errors for user: {} - {}",
                    user.getUsername(), String.join(", ", validationErrors));
            throw new IllegalArgumentException("New password does not meet requirements: " +
                    String.join(", ", validationErrors));
        }

        byte[] newSalt = encryptionService.generateSalt();
        SecretKey newAesKey = encryptionService.deriveKeyFromPassword(newPassword, newSalt);

        log.debug("Derived new AES key for user: {}", user.getUsername());

        int reencryptedCount = 0;
        for (Credential credential : allCredentials) {
            try {
                String decryptedPassword = encryptionService.decrypt(
                        credential.getEncryptedPassword(),
                        currentAesKey
                );

                String reencryptedPassword = encryptionService.encrypt(decryptedPassword,
                        newAesKey);

                credential.setEncryptedPassword(reencryptedPassword);
                credentialRepository.save(credential);

                reencryptedCount++;

            } catch (Exception e) {
                log.error("Failed to re-encrypt credential ID: {} for user: {}",
                        credential.getId(), user.getUsername(), e);
                throw new RuntimeException(
                        "Failed to re-encrypt credentials. Password change aborted.", e);
            }
        }

        log.info("Re-encrypted {} credentials for user: {}", reencryptedCount,
                user.getUsername());

        String newPasswordHash = passwordEncoder.encode(newPassword);

        byte[] newAesKeyBytes = newAesKey.getEncoded();
        byte[] combined = new byte[newSalt.length + newAesKeyBytes.length];
        System.arraycopy(newSalt, 0, combined, 0, newSalt.length);
        System.arraycopy(newAesKeyBytes, 0, combined, newSalt.length,
                newAesKeyBytes.length);
        String encodedKey = Base64.getEncoder().encodeToString(combined);

        user.setPasswordHash(newPasswordHash);
        user.setEncryptionKey(encodedKey);
        userRepository.save(user);

        log.info("Master password changed successfully for user: {}",
                user.getUsername());
    }

    @Transactional
    public void enableTwoFactor(User user, String secret, List<String> backupCodes) {

        user.setTwoFactorEnabled(true);
        user.setTwoFactorSecret(secret);

        try {
            ObjectMapper mapper = new ObjectMapper();
            String backupCodesJson = mapper.writeValueAsString(backupCodes);
            user.setBackupCodes(backupCodesJson);
        } catch (Exception e) {
            log.error("Error storing backup codes", e);
            throw new RuntimeException("Error storing backup codes", e);
        }

        userRepository.save(user);
        log.info("2FA enabled successfully for user: {}", user.getUsername());
    }

    @Transactional
    public void disableTwoFactor(User user) {
        log.info("Disabling 2FA for user: {}", user.getUsername());

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        user.setBackupCodes(null);

        userRepository.save(user);
        log.info("2FA disabled successfully for user: {}", user.getUsername());
    }

    public List<String> getBackupCodes(User user) {
        if (user.getBackupCodes() == null) {
            return new ArrayList<>();
        }

        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(user.getBackupCodes(),
                    mapper.getTypeFactory().constructCollectionType(
                            List.class, String.class));
        } catch (Exception e) {
            log.error("Error reading backup codes", e);
            return new ArrayList<>();
        }
    }

    @Transactional
    public void updateBackupCodes(User user, List<String> updatedCodes) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String backupCodesJson = mapper.writeValueAsString(updatedCodes);
            user.setBackupCodes(backupCodesJson);
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("Error updating backup codes", e);
        }
    }

    public boolean verifyPassword(User user, String password) {
        log.debug("Verifying password for user: {}", user.getUsername());
        boolean isValid = passwordEncoder.matches(password, user.getPasswordHash());
        log.debug("Password verification result for user {}: {}",
                user.getUsername(), isValid);
        return isValid;
    }
}
