package com.portfolio.pswmanager.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;

import static org.assertj.core.api.Assertions.*;

/**
 * ═══════════════════════════════════════════════════════
 * INTEGRATION TEST per EncryptionService
 * ═══════════════════════════════════════════════════════
 *
 * COSA TESTA: Crittografia end-to-end con chiavi reali
 * COME: Usa il service reale con Spring context
 * PERCHÉ: Verifica che encrypt + decrypt funzionino insieme
 */
@SpringBootTest
@Transactional
@DisplayName("EncryptionService - Integration Tests")
class EncryptionServiceIntegrationTest {  // ✅ Cambia nome classe - non può chiamarsi come il service!

    @Autowired  // ✅ Inietta il service reale
    private EncryptionService encryptionService;

    private SecretKey testKey;
    private static final String TEST_PASSWORD = "TestMasterPassword123!";

    @BeforeEach
    void setUp() throws Exception {
        // Genera salt e deriva chiave AES reale
        byte[] salt = encryptionService.generateSalt();
        testKey = encryptionService.deriveKeyFromPassword(TEST_PASSWORD, salt);
    }

    @Test
    @DisplayName("Dovrebbe criptare e decriptare correttamente")
    void shouldEncryptAndDecryptSuccessfully() throws Exception {
        // GIVEN
        String original = "MySuperSecretPassword123!";

        // WHEN
        String encrypted = encryptionService.encrypt(original, testKey);
        String decrypted = encryptionService.decrypt(encrypted, testKey);

        // THEN
        assertThat(decrypted).isEqualTo(original);
        assertThat(encrypted).isNotEqualTo(original);
        assertThat(encrypted).isNotEmpty();
    }

    @Test
    @DisplayName("Password criptate dovrebbero essere diverse ogni volta (IV random)")
    void shouldProduceDifferentCiphertextsForSameInput() throws Exception {
        // GIVEN
        String original = "SamePassword123!";

        // WHEN
        String encrypted1 = encryptionService.encrypt(original, testKey);
        String encrypted2 = encryptionService.encrypt(original, testKey);

        // THEN
        assertThat(encrypted1).isNotEqualTo(encrypted2);  // IV diverso ogni volta

        // Ma entrambe decriptano correttamente
        assertThat(encryptionService.decrypt(encrypted1, testKey)).isEqualTo(original);
        assertThat(encryptionService.decrypt(encrypted2, testKey)).isEqualTo(original);
    }

    @Test
    @DisplayName("Dovrebbe fallire con chiave sbagliata")
    void shouldFailWithWrongKey() throws Exception {
        // GIVEN
        String original = "TestPassword123!";
        String encrypted = encryptionService.encrypt(original, testKey);

        // Genera una chiave diversa
        byte[] wrongSalt = encryptionService.generateSalt();
        SecretKey wrongKey = encryptionService.deriveKeyFromPassword("WrongPassword!", wrongSalt);

        // WHEN & THEN
        assertThatThrownBy(() ->
                encryptionService.decrypt(encrypted, wrongKey))
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("Dovrebbe generare salt casuali diversi")
    void shouldGenerateDifferentSalts() {
        // WHEN
        byte[] salt1 = encryptionService.generateSalt();
        byte[] salt2 = encryptionService.generateSalt();

        // THEN
        assertThat(salt1).isNotEqualTo(salt2);
        assertThat(salt1).hasSize(16);
        assertThat(salt2).hasSize(16);
    }

    @Test
    @DisplayName("PBKDF2 dovrebbe derivare la stessa chiave con stesso salt")
    void shouldDeriveSameKeyWithSameSalt() throws Exception {
        // GIVEN
        byte[] salt = encryptionService.generateSalt();

        // WHEN
        SecretKey key1 = encryptionService.deriveKeyFromPassword(TEST_PASSWORD, salt);
        SecretKey key2 = encryptionService.deriveKeyFromPassword(TEST_PASSWORD, salt);

        // THEN
        assertThat(key1.getEncoded()).isEqualTo(key2.getEncoded());
    }

    @Test
    @DisplayName("PBKDF2 dovrebbe derivare chiavi diverse con salt diversi")
    void shouldDeriveDifferentKeysWithDifferentSalts() throws Exception {
        // GIVEN
        byte[] salt1 = encryptionService.generateSalt();
        byte[] salt2 = encryptionService.generateSalt();

        // WHEN
        SecretKey key1 = encryptionService.deriveKeyFromPassword(TEST_PASSWORD, salt1);
        SecretKey key2 = encryptionService.deriveKeyFromPassword(TEST_PASSWORD, salt2);

        // THEN
        assertThat(key1.getEncoded()).isNotEqualTo(key2.getEncoded());
    }

    @Test
    @DisplayName("Dovrebbe gestire password con caratteri speciali")
    void shouldHandleSpecialCharactersInPassword() throws Exception {
        // GIVEN
        String specialPassword = "P@$$w0rd!🔐#€&*()[]{}";

        // WHEN
        String encrypted = encryptionService.encrypt(specialPassword, testKey);
        String decrypted = encryptionService.decrypt(encrypted, testKey);

        // THEN
        assertThat(decrypted).isEqualTo(specialPassword);
    }

    @Test
    @DisplayName("Dovrebbe gestire password molto lunghe")
    void shouldHandleLongPasswords() throws Exception {
        // GIVEN
        String longPassword = "a".repeat(1000);

        // WHEN
        String encrypted = encryptionService.encrypt(longPassword, testKey);
        String decrypted = encryptionService.decrypt(encrypted, testKey);

        // THEN
        assertThat(decrypted).isEqualTo(longPassword);
        assertThat(decrypted).hasSize(1000);
    }
}