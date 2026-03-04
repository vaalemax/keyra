package com.portfolio.pswmanager.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * DTO for vault export/import.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class VaultExportDTO {

    private String version;                // Export format version
    private LocalDateTime exportedAt;      // Export timestamp
    private String username;               // User who exported
    private int credentialCount;           // Number of credentials
    private List<CredentialDTO> credentials;

    /**
     * Factory method to create export DTO.
     */
    public static VaultExportDTO create(String username, List<CredentialDTO> credentials) {
        VaultExportDTO dto = new VaultExportDTO();
        dto.setVersion("1.0");
        dto.setExportedAt(LocalDateTime.now());
        dto.setUsername(username);
        dto.setCredentialCount(credentials.size());
        dto.setCredentials(credentials);
        return dto;
    }
}