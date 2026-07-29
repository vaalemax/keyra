package com.portfolio.pswmanager.model.dto;


import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;


import java.time.LocalDateTime;

@Getter
@Setter
public class CredentialDTO{
    private Long id;

    @NotBlank(message = "Service name cannot be empty")
    @Size(min = 2, max = 100, message = "Service name needs between 2-100 characters")
    private String serviceName;

    @NotBlank(message = "Username is required")
    @Size(min = 2, max = 100, message = "Username needs between 2-100 characters")
    private String username;

    private String decryptedPassword;

    private String plainPassword;

    @Pattern(
            regexp = "^(https?://)?([a-zA-Z0-9-]+\\.)*[a-zA-Z0-9-]+(\\.[a-zA-Z]{2,})?(/.*)?$|^$",
            message = "Invalid URL"
    )
    @Size(max = 500, message = "URL cannot have over 500 characters")
    private String url;

    @Size(max = 1000, message = "Notes cannot have over 1000 characters")
    private String notes;

    @NotBlank(message = "Category is required")
    private String category = "other";

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}


