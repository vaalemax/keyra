package com.portfolio.pswmanager.controller;

import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.repository.CredentialRepository;
import com.portfolio.pswmanager.repository.UserRepository;
import com.portfolio.pswmanager.service.EncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

import javax.crypto.SecretKey;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * ═══════════════════════════════════════════════════════
 * INTEGRATION TEST per VaultController
 * ═══════════════════════════════════════════════════════
 *
 * COSA TESTA: Endpoint HTTP completi con Spring context
 * COME: Usa MockMvc per simulare richieste HTTP
 * PERCHÉ: Verifica che tutto funzioni insieme (controller + service + repository)
 */
@SpringBootTest
@AutoConfigureMockMvc
@Transactional  // Rollback automatico dopo ogni test
@DisplayName("VaultController - Integration Tests")
class VaultControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EncryptionService encryptionService;

    private User testUser;
    private SecretKey testKey;

    @BeforeEach
    void setUp() throws Exception {
        // Crea utente di test nel DB
        testUser = new User();
        testUser.setUsername("integrationtest");

        String masterPassword = "TestPassword123!";
        testUser.setPasswordHash(passwordEncoder.encode(masterPassword));

        byte[] salt = encryptionService.generateSalt();
        SecretKey aesKey = encryptionService.deriveKeyFromPassword(masterPassword, salt);

        byte[] combined = new byte[salt.length + aesKey.getEncoded().length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(aesKey.getEncoded(), 0, combined, salt.length, aesKey.getEncoded().length);
        testUser.setEncryptionKey(java.util.Base64.getEncoder().encodeToString(combined));

        testUser = userRepository.save(testUser);
        testKey = aesKey;
    }

    @Test
    @DisplayName("GET /vault - dovrebbe mostrare pagina vault per utente autenticato")
    void shouldShowVaultPageForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/vault")
                        .with(user(testUser.getUsername()))  // Simula utente loggato
                        .sessionAttr("AES_KEY", testKey))    // Simula chiave in session
                .andExpect(status().isOk())
                .andExpect(view().name("vault"))
                .andExpect(model().attributeExists("credentials"))
                .andExpect(model().attributeExists("secureCount"))
                .andExpect(model().attributeExists("weakCount"));
    }

    @Test
    @DisplayName("GET /vault - dovrebbe redirigere a login se non autenticato")
    void shouldRedirectToLoginWhenNotAuthenticated() throws Exception {
        mockMvc.perform(get("/vault"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login"));
    }

    @Test
    @DisplayName("POST /vault/add - dovrebbe creare nuova credenziale")
    void shouldCreateNewCredential() throws Exception {
        mockMvc.perform(post("/vault/add")
                        .with(user(testUser.getUsername()))
                        .with(csrf())  // Token CSRF obbligatorio
                        .sessionAttr("AES_KEY", testKey)
                        .param("serviceName", "TestService")
                        .param("username", "testuser")
                        .param("password", "TestPassword123!")
                        .param("url", "https://test.com")
                        .param("category", "work"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/vault"))
                .andExpect(flash().attributeExists("successMessage"));

        // Verifica che sia stata salvata nel DB
        long count = credentialRepository.findActiveByUserId(testUser.getId()).size();
        org.assertj.core.api.Assertions.assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("POST /vault/add - dovrebbe rifiutare password corta")
    void shouldRejectShortPassword() throws Exception {
        mockMvc.perform(post("/vault/add")
                        .with(user(testUser.getUsername()))
                        .with(csrf())
                        .sessionAttr("AES_KEY", testKey)
                        .param("serviceName", "TestService")
                        .param("username", "testuser")
                        .param("password", "short")  // Troppo corta
                        .param("category", "other"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/vault"))
                .andExpect(flash().attributeExists("errorMessage"));
    }
}