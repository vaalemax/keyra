package com.portfolio.pswmanager.service;

import com.portfolio.pswmanager.model.Credential;
import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.model.dto.CredentialDTO;
import com.portfolio.pswmanager.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * ═══════════════════════════════════════════════════════
 * UNIT TEST per CredentialService
 * ═══════════════════════════════════════════════════════
 * COSA TESTA: Business logic del service in isolamento
 * COME: Usa MOCK di repository e encryption service
 * PERCHÉ: Veloce, deterministico, non richiede DB/Spring
 */
@ExtendWith(MockitoExtension.class)  // Abilita Mockito
@DisplayName("CredentialService - Unit Tests")
class CredentialServiceTest {

    // ═══════════════════════════════════════════════════════
    // SETUP
    // ═══════════════════════════════════════════════════════

    @Mock  // Crea un oggetto MOCK (finto)
    private CredentialRepository credentialRepository;

    @Mock
    private EncryptionService encryptionService;

    @InjectMocks  // Crea il service VERO e gli inietta i mock
    private CredentialService credentialService;

    // Dati di test riutilizzabili
    private User testUser;
    private SecretKey testKey;
    private Credential testCredential;

    /**
     * Eseguito PRIMA di ogni test.
     * Setup dei dati comuni.
     */
    @BeforeEach
    void setUp() {
        // User finto
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");

        // Chiave AES finta (solo per test)
        byte[] keyBytes = new byte[32]; // 256 bit
        testKey = new SecretKeySpec(keyBytes, "AES");

        // Credenziale finta
        testCredential = new Credential();
        testCredential.setId(100L);
        testCredential.setUser(testUser);
        testCredential.setServiceName("Gmail");
        testCredential.setUsername("test@gmail.com");
        testCredential.setEncryptedPassword("encrypted_password_base64");
        testCredential.setUrl("https://gmail.com");
        testCredential.setNotes("Test notes");
        testCredential.setCategory("email");
        testCredential.setCreatedAt(LocalDateTime.now());
    }

    // ═══════════════════════════════════════════════════════
    // TEST: getAllCredentialsForUser
    // ═══════════════════════════════════════════════════════

    @Test
    @DisplayName("Dovrebbe ritornare lista vuota se l'utente non ha credenziali")
    void shouldReturnEmptyListWhenUserHasNoCredentials() {
        // GIVEN (Dato che...)
        when(credentialRepository.findByUserIdAndIsActiveTrueOrderByCreatedAtDesc(testUser.getId()))
                .thenReturn(List.of());  // Repository ritorna lista vuota

        // WHEN (Quando...)
        List<CredentialDTO> result = credentialService
                .getAllCredentialsForUser(testUser, testKey);

        // THEN (Allora...)
        assertThat(result).isEmpty();
        verify(credentialRepository).findByUserIdAndIsActiveTrueOrderByCreatedAtDesc(testUser.getId());
    }

    @Test
    @DisplayName("Dovrebbe decriptare e ritornare le credenziali dell'utente")
    void shouldDecryptAndReturnUserCredentials() throws Exception {
        // GIVEN
        when(credentialRepository.findByUserIdAndIsActiveTrueOrderByCreatedAtDesc(testUser.getId()))
                .thenReturn(List.of(testCredential));

        when(encryptionService.decrypt(eq("encrypted_password_base64"), eq(testKey)))
                .thenReturn("MyPlainPassword123!");  // Decryption simulata

        // WHEN
        List<CredentialDTO> result = credentialService
                .getAllCredentialsForUser(testUser, testKey);

        // THEN
        assertThat(result).hasSize(1);

        CredentialDTO dto = result.getFirst();
        assertThat(dto.getId()).isEqualTo(100L);
        assertThat(dto.getServiceName()).isEqualTo("Gmail");
        assertThat(dto.getUsername()).isEqualTo("test@gmail.com");
        assertThat(dto.getDecryptedPassword()).isEqualTo("MyPlainPassword123!");
        assertThat(dto.getUrl()).isEqualTo("https://gmail.com");

        verify(encryptionService).decrypt("encrypted_password_base64", testKey);
    }

    @Test
    @DisplayName("Dovrebbe lanciare eccezione se la decriptazione fallisce")
    void shouldThrowExceptionWhenDecryptionFails() throws Exception {
        // GIVEN
        when(credentialRepository.findByUserIdAndIsActiveTrueOrderByCreatedAtDesc(testUser.getId()))
                .thenReturn(List.of(testCredential));

        when(encryptionService.decrypt(anyString(), any(SecretKey.class)))
                .thenThrow(new RuntimeException("Decryption error"));

        // WHEN & THEN
        assertThatThrownBy(() ->
                credentialService.getAllCredentialsForUser(testUser, testKey))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Errore decriptazione");
    }

    // ═══════════════════════════════════════════════════════
    // TEST: createCredential
    // ═══════════════════════════════════════════════════════

    @Test
    @DisplayName("Dovrebbe creare e salvare una credenziale valida")
    void shouldCreateAndSaveValidCredential() throws Exception {
        // GIVEN
        String plainPassword = "MySecurePass123!";
        String encryptedPassword = "encrypted_base64_string";

        when(encryptionService.encrypt(eq(plainPassword), eq(testKey)))
                .thenReturn(encryptedPassword);

        when(credentialRepository.save(any(Credential.class)))
                .thenAnswer(invocation -> {
                    Credential saved = invocation.getArgument(0);
                    saved.setId(200L);  // Simula ID generato dal DB
                    return saved;
                });

        // WHEN
        Credential result = credentialService.createCredential(
                testUser,
                "Netflix",
                "user@netflix.com",
                plainPassword,
                "https://netflix.com",
                "My account",
                "entertainment",
                testKey
        );

        // THEN
        assertThat(result).isNotNull();
        assertThat(result.getId()).isEqualTo(200L);
        assertThat(result.getServiceName()).isEqualTo("Netflix");
        assertThat(result.getUsername()).isEqualTo("user@netflix.com");
        assertThat(result.getEncryptedPassword()).isEqualTo(encryptedPassword);

        verify(encryptionService).encrypt(plainPassword, testKey);
        verify(credentialRepository).save(any(Credential.class));
    }

    @Test
    @DisplayName("Dovrebbe rifiutare credenziale con service name vuoto")
    void shouldRejectCredentialWithEmptyServiceName() {
        // WHEN & THEN
        assertThatThrownBy(() ->
                credentialService.createCredential(
                        testUser, "", "user", "password123", null, null, "other", testKey))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Service name è obbligatorio");

        // Verifica che il repository NON sia stato chiamato
        verify(credentialRepository, never()).save(any());
    }

    @Test
    @DisplayName("Dovrebbe rifiutare password troppo corta")
    void shouldRejectShortPassword() {
        // WHEN & THEN
        assertThatThrownBy(() ->
                credentialService.createCredential(
                        testUser, "Gmail", "user", "123", null, null, "other", testKey))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("almeno 8 caratteri");

        verify(credentialRepository, never()).save(any());
    }

    // ═══════════════════════════════════════════════════════
    // TEST: deleteCredential
    // ═══════════════════════════════════════════════════════

    @Test
    @DisplayName("Dovrebbe eliminare credenziale dell'utente proprietario")
    void shouldDeleteCredentialOwnedByUser() {
        // GIVEN
        when(credentialRepository.findById(100L))
                .thenReturn(Optional.of(testCredential));

        // WHEN
        credentialService.deleteCredential(100L, testUser);

        // THEN
        verify(credentialRepository).delete(testCredential);
    }

    @Test
    @DisplayName("Dovrebbe lanciare eccezione se credenziale non esiste")
    void shouldThrowExceptionWhenCredentialNotFound() {
        // GIVEN
        when(credentialRepository.findById(999L))
                .thenReturn(Optional.empty());

        // WHEN & THEN
        assertThatThrownBy(() ->
                credentialService.deleteCredential(999L, testUser))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non trovata");

        verify(credentialRepository, never()).delete(any());
    }

    @Test
    @DisplayName("Dovrebbe bloccare eliminazione di credenziale altrui")
    void shouldBlockDeletionOfOthersCredential() {
        // GIVEN
        User otherUser = new User();
        otherUser.setId(999L);
        otherUser.setUsername("otheruser");

        when(credentialRepository.findById(100L))
                .thenReturn(Optional.of(testCredential));

        // WHEN & THEN
        assertThatThrownBy(() ->
                credentialService.deleteCredential(100L, otherUser))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("Non autorizzato");

        verify(credentialRepository, never()).delete(any());
    }

    // ═══════════════════════════════════════════════════════
    // TEST: calculatePasswordStats
    // ═══════════════════════════════════════════════════════

    @Test
    @DisplayName("Dovrebbe calcolare correttamente le statistiche")
    void shouldCalculatePasswordStats() {
        CredentialDTO dto1 = new CredentialDTO();
        CredentialDTO dto2 = new CredentialDTO();
        CredentialDTO dto3 = new CredentialDTO();

        dto1.setServiceName("Gmail");
        dto2.setServiceName("Netflix");
        dto3.setServiceName("GitHub");
        dto1.setUsername("user");
        dto2.setUsername("user");
        dto3.setUsername("user");
        dto1.setDecryptedPassword("short");
        dto2.setDecryptedPassword("VeryLongPassword123!");
        dto3.setDecryptedPassword("AnotherSecurePass!");
        dto1.setCategory("email");
        dto2.setCategory("other");
        dto3.setCategory("work");

        // GIVEN"
        List<CredentialDTO> credentials = List.of(dto1, dto2, dto3);

        // WHEN
        long[] stats = credentialService.calculatePasswordStats(credentials);

        // THEN
        assertThat(stats[0]).isEqualTo(2);  // secureCount (>= 12 char)
        assertThat(stats[1]).isEqualTo(1);  // weakCount
    }
}