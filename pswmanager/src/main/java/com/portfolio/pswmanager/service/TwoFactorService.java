package com.portfolio.pswmanager.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Service for Two-Factor Authentication (2FA) using TOTP.
 */
@Slf4j
@Service
public class TwoFactorService {

    private final GoogleAuthenticator googleAuthenticator;

    public TwoFactorService() {
        this.googleAuthenticator = new GoogleAuthenticator();
    }

    /**
     * Generate a new TOTP secret for a user.
     */
    public String generateSecret() {
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        String secret = key.getKey();
        log.debug("Generated new TOTP secret (length: {})", secret.length());
        return secret;
    }

    public boolean verifyCode(String secret, int code) {
        log.debug("Verifying TOTP code for secret (first 4 chars): {}...", secret.substring(0, 4));
        boolean isValid = googleAuthenticator.authorize(secret, code);
        log.debug("TOTP code verification result: {}", isValid);
        return isValid;
    }

    /**
     * Generate QR code URL for Google Authenticator.
     */
    public String generateQrCodeUrl(String username, String secret) {
        String issuer = "VaultShield";
        String url = GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(issuer, username, new GoogleAuthenticatorKey.Builder(secret).build());
        log.debug("Generated QR code URL for user: {}", username);
        return url;
    }

    /**
     * Generate QR code image as Base64 string.
     */
    public String generateQrCodeImage(String qrCodeUrl) throws WriterException, IOException {
        log.debug("Generating QR code image");

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeUrl, BarcodeFormat.QR_CODE, 300, 300);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);

        byte[] imageBytes = outputStream.toByteArray();
        String base64Image = Base64.getEncoder().encodeToString(imageBytes);

        log.debug("QR code image generated (size: {} bytes)", imageBytes.length);

        return "data:image/png;base64," + base64Image;
    }

    /**
     * Generate backup codes for recovery.
     */
    public List<String> generateBackupCodes() {
        log.debug("Generating backup codes");

        List<String> codes = new ArrayList<>();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < 10; i++) {
            // Generate 8-digit code
            int code = 10000000 + random.nextInt(90000000);
            codes.add(String.valueOf(code));
        }

        log.debug("Generated {} backup codes", codes.size());
        return codes;
    }

    public boolean verifyBackupCode(String providedCode, List<String> backupCodes, Long userId) {
        if (backupCodes == null || backupCodes.isEmpty()) {
            log.warn("No backup codes available");
            return false;
        }

        boolean isValid = backupCodes.contains(providedCode);
        log.debug("Backup code verification result for user ID {}: {}",userId, isValid);

        return isValid;
    }

    public List<String> removeBackupCode(String usedCode, List<String> backupCodes) {
        List<String> updatedCodes = new ArrayList<>(backupCodes);
        updatedCodes.remove(usedCode);
        return updatedCodes;
    }
}
