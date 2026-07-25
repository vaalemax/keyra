package com.portfolio.pswmanager.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

@Service
public class EncryptionService {
    private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    /**
     * Cripta una password usando AES-256-GCM
     * @param plainPassword password in chiaro
     * @param key chiave di encryption (derivata dalla master password)
     * @return password criptata in Base64
     */
    public String encrypt(String plainPassword, SecretKey key) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            byte[] encryptedData = cipher.doFinal(plainPassword.getBytes(StandardCharsets.UTF_8));

            byte[] encryptedWithIv = new byte[GCM_IV_LENGTH + encryptedData.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, GCM_IV_LENGTH);
            System.arraycopy(encryptedData, 0, encryptedWithIv, GCM_IV_LENGTH, encryptedData.length);

            return Base64.getEncoder().encodeToString(encryptedWithIv);

        } catch (Exception e) {
            log.error("Error during password encryption", e);
            throw e;
        }
    }

    /**
     * Decode Base64
     * Estrai IV (primi 12 bytes)
     * Estrai ciphertext (resto)
     * Init cipher in DECRYPT_MODE
     * doFinal e ritorna String
     */
    public String decrypt(String encryptedPassword, SecretKey key) throws Exception {

        try {
            byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedPassword);

            // Extract IV and encrypted data
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] encryptedData = new byte[encryptedWithIv.length - GCM_IV_LENGTH];
            System.arraycopy(encryptedWithIv, 0, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(encryptedWithIv, GCM_IV_LENGTH, encryptedData, 0, encryptedData.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            byte[] decryptedData = cipher.doFinal(encryptedData);
            return new String(decryptedData, StandardCharsets.UTF_8);

        } catch (Exception e) {
            log.error("Error during password decryption", e);
            throw e;
        }
    }

    /**
     * Derives an AES key from a password using PBKDF2.
     */
    public SecretKey deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        log.debug("Deriving AES key from password using PBKDF2");

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey result = new SecretKeySpec(tmp.getEncoded(), "AES");

            log.debug("AES key derived successfully");

            return result;

        } catch (Exception e) {
            log.error("Error deriving AES key from password", e);
            throw e;
        }
    }

    /**
     * Generates a random salt for key derivation.
     */
    public byte[] generateSalt() {
        log.debug("Generating random salt (16 bytes)");

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        log.debug("Salt generated successfully");

        return salt;
    }

    /**
     * Recreate a SecretKey from raw key bytes.
     * Used when retrieving the AES key from the database.
     *
     * @param keyBytes Raw AES key bytes (32 bytes for AES-256)
     * @return SecretKey instance
     */
    public SecretKey recreateKey(byte[] keyBytes) {
        if (keyBytes.length != 32) {
            log.warn("Invalid key length: {} bytes (expected 32 for AES-256)", keyBytes.length);
            throw new IllegalArgumentException("Invalid AES key length. Expected 32 bytes for AES-256.");
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    public SecretKey deriveAesKey(String encryptionKey){
        byte[] combined = Base64.getDecoder().decode(encryptionKey);
        byte[] salt = new byte[16];
        byte[] keyBytes = new byte[32];
        System.arraycopy(combined, 0, salt, 0, 16);
        System.arraycopy(combined, 16, keyBytes, 0, 32);
        return this.recreateKey(keyBytes);
    }
}
