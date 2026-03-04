package com.portfolio.pswmanager.mapper;

import com.portfolio.pswmanager.model.Credential;
import com.portfolio.pswmanager.model.dto.CredentialDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Mapper per conversioni tra Credential entity e CredentialDTO.
 * Pattern: Evita codice ripetitivo e centralizza la logica di mapping.
 */
@Component
public class CredentialMapper {
    private static final Logger log = LoggerFactory.getLogger(CredentialMapper.class);

    /**
     * Converte Entity → DTO (con password decriptata).
     *
     * @param credential Entity dal DB
     * @param decryptedPassword Password in chiaro (già decriptata)
     * @return DTO per il frontend
     */
    public CredentialDTO toDTO(Credential credential, String decryptedPassword) {
        if (credential == null) {
            log.warn("Attempted to convert null Credential to DTO");
            return null;
        }
        log.trace("Converting Credential entity to DTO - ID: {}", credential.getId());

        CredentialDTO dto = new CredentialDTO();
        dto.setId(credential.getId());
        dto.setServiceName(credential.getServiceName());
        dto.setUsername(credential.getUsername());
        dto.setDecryptedPassword(decryptedPassword);
        dto.setUrl(credential.getUrl());
        dto.setNotes(credential.getNotes());
        dto.setCategory(credential.getCategory() != null ? credential.getCategory() : "other");
        dto.setCreatedAt(credential.getCreatedAt());
        dto.setUpdatedAt(credential.getUpdatedAt());

        return dto;
    }

    /**
     * Aggiorna Entity esistente con dati da DTO.
     * NON aggiorna: id, user, encryptedPassword, createdAt
     * (questi vengono gestiti separatamente dal service)
     *
     * @param credential Entity esistente da aggiornare
     * @param dto DTO con i nuovi dati
     */
    public void updateEntityFromDTO(Credential credential, CredentialDTO dto) {
        if (credential == null || dto == null) {
            log.warn("Attempted to update entity from DTO with null values - credential: {}, dto: {}", credential != null, dto != null);
            return;
        }
        log.debug("Updating Credential entity from DTO - ID: {}", credential.getId());

        credential.setServiceName(dto.getServiceName());
        credential.setUsername(dto.getUsername());
        credential.setUrl(dto.getUrl());
        credential.setNotes(dto.getNotes());
        credential.setCategory(dto.getCategory());
        credential.setUpdatedAt(LocalDateTime.now());

        // NOTE: encryptedPassword viene gestito separatamente dal service
        // perché richiede la chiave AES
    }

    /**
     * Crea nuova Entity da DTO (per insert).
     * NON imposta: id, user, encryptedPassword, createdAt
     * (questi vengono impostati dal service)
     *
     * @param dto DTO con i dati
     * @return Nuova entity (da completare nel service)
     */
    public Credential toEntity(CredentialDTO dto) {
        if (dto == null) {
            log.warn("Attempted to convert null DTO to Credential entity");
            return null;
        }
        log.debug("Converting DTO to new Credential entity - service: {}", dto.getServiceName());

        Credential credential = new Credential();
        credential.setServiceName(dto.getServiceName());
        credential.setUsername(dto.getUsername());
        credential.setUrl(dto.getUrl());
        credential.setNotes(dto.getNotes());
        credential.setCategory(dto.getCategory());

        return credential;
    }
}