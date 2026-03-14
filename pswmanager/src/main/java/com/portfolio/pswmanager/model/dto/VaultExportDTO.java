package com.portfolio.pswmanager.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class VaultExportDTO {

    private String version;
    private LocalDateTime exportedAt;
    private String username;
    private int credentialCount;
    private List<CredentialDTO> credentials;

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