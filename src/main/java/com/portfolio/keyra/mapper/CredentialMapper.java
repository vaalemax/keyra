package com.portfolio.keyra.mapper;

import com.portfolio.keyra.model.Credential;
import com.portfolio.keyra.model.dto.CredentialDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class CredentialMapper {

    private static final Logger log = LoggerFactory.getLogger(CredentialMapper.class);

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

    public void updateEntityFromDTO(Credential credential, CredentialDTO dto) {
        if (credential == null || dto == null) {
            return;
        }

        credential.setServiceName(dto.getServiceName());
        credential.setUsername(dto.getUsername());
        credential.setUrl(dto.getUrl());
        credential.setNotes(dto.getNotes());
        credential.setCategory(dto.getCategory());
        credential.setUpdatedAt(LocalDateTime.now());
    }

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