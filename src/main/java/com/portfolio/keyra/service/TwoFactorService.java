package com.portfolio.keyra.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.portfolio.keyra.model.AuditLog;
import com.portfolio.keyra.model.dto.TwoFactorVerificationResultDTO;
import com.portfolio.keyra.model.User;
import com.portfolio.keyra.repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class TwoFactorService {

    private final AuditService auditService;

    private final EncryptionService encryptionService;

    private final GoogleAuthenticator googleAuthenticator;

    private final UserRepository userRepository;

    private final UserService userService;

    private static final Logger log = LoggerFactory.getLogger(TwoFactorService.class);

    public TwoFactorService(AuditService auditService,
                            UserService userService,
                            UserRepository userRepository,
                            EncryptionService encryptionService) {
        this.auditService = auditService;
        this.googleAuthenticator = new GoogleAuthenticator();
        this.userRepository = userRepository;
        this.userService = userService;
        this.encryptionService = encryptionService;
    }

    public String generateSecret() {
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        return key.getKey();
    }

    public String generateQrCodeUrl(String username, String secret) {
        String issuer = "Keyra";
        return GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(
                issuer, username,
                new GoogleAuthenticatorKey.Builder(secret).build());
    }

    public String generateQrCodeImage(String qrCodeUrl)
            throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(
                qrCodeUrl, BarcodeFormat.QR_CODE, 300, 300);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

        byte[] imageBytes = outputStream.toByteArray();
        String base64Image = Base64.getEncoder().encodeToString(imageBytes);

        return "data:image/png;base64," + base64Image;
    }

    public List<String> generateBackupCodes() {
        List<String> codes = new ArrayList<>();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < 10; i++) {
            int code = 10000000 + random.nextInt(90000000);
            codes.add(String.valueOf(code));
        }
        return codes;
    }

    public boolean verifyCode(String secret, int code) {
        return googleAuthenticator.authorize(secret, code);
    }

    public TwoFactorVerificationResultDTO verify(Long userId,
                                                 String code,
                                                 boolean useBackupCode,
                                                 String clientIp,
                                                 String userAgent) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalStateException(
                        "User not found: " + userId));

        boolean isValid;
        String warningMessage = null;

        try {
            if (useBackupCode) {
                log.debug("Verifying backup code for user: {}", user.getUsername());

                List<String> backupCodes = userService.getBackupCodes(user);
                isValid = this.verifyBackupCode(code.trim(), backupCodes, userId);

                if (isValid) {
                    List<String> updatedCodes = this.removeBackupCode(code.trim(),
                            backupCodes);
                    userService.updateBackupCodes(user, updatedCodes);

                    if (updatedCodes.size() <= 2) {
                        warningMessage = "Warning: You have only "
                                + updatedCodes.size() + " backup codes remaining.";
                    }
                }
            } else {
                log.debug("Verifying TOTP code for user: {}", user.getUsername());
                int totpCode = Integer.parseInt(code.trim());
                isValid = this.verifyCode(user.getTwoFactorSecret(), totpCode);
            }
        } catch (NumberFormatException e) {
            log.warn("2FA verification failed - invalid code format for user: {}",
                    user.getUsername());
            return TwoFactorVerificationResultDTO.invalidFormat();
        }

        if (!isValid) {
            log.warn("2FA verification failed - invalid code for user: {}",
                    user.getUsername());
            auditService.auditVaultFailure(
                    AuditLog.AuditAction.LOGIN_FAILURE,
                    "USER",
                    user,
                    userId,
                    "2FA verification failed - invalid code",
                    clientIp,
                    userAgent
            );
            return TwoFactorVerificationResultDTO.invalidCode();
        }

        try {
            SecretKey aesKey = encryptionService.deriveAesKey(user.getEncryptionKey());

            log.info("2FA verification successful for user: {}", user.getUsername());
            auditService.auditVaultSuccess(
                    AuditLog.AuditAction.LOGIN_SUCCESS,
                    "USER",
                    user,
                    userId,
                    "Successful login with 2FA" +
                            (useBackupCode ? " (backup code)" : ""),
                    clientIp,
                    userAgent
            );

            return TwoFactorVerificationResultDTO.success(aesKey, warningMessage);

        } catch (Exception e) {
            log.error("Error deriving AES key after 2FA for user: {}",
                    user.getUsername(), e);
            auditService.auditVaultFailure(
                    AuditLog.AuditAction.SYSTEM_ERROR,
                    "USER",
                    user,
                    userId,
                    "2FA verification error: " + e.getMessage(),
                    clientIp,
                    userAgent
            );
            return TwoFactorVerificationResultDTO.error(
                    "An error occurred. Please try again.");
        }
    }

    private boolean verifyBackupCode(String providedCode, List<String> backupCodes,
                                     Long userId) {
        if (backupCodes == null || backupCodes.isEmpty()) {
            log.warn("No backup codes available");
            return false;
        }

        boolean isValid = backupCodes.contains(providedCode);
        log.debug("Backup code verification result for user ID {}: {}",
                userId, isValid);

        return isValid;
    }

    private List<String> removeBackupCode(String usedCode, List<String> backupCodes) {
        List<String> updatedCodes = new ArrayList<>(backupCodes);
        updatedCodes.remove(usedCode);
        return updatedCodes;
    }
}
