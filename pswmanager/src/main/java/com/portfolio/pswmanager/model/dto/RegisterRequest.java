package com.portfolio.pswmanager.model.dto;

import com.portfolio.pswmanager.validation.StrongMasterPassword;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(
            regexp = "^[a-zA-Z0-9_-]+$",
            message = "Username can only contain letters, numbers, hyphens and underscores"
    )
    private String username;

    @NotBlank(message = "Password is required")
    @StrongMasterPassword
    private String password;

    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;

    @AssertTrue(message = "Passwords do not match")
    private boolean isPasswordConfirmed() {
        return password == null || password.equals(confirmPassword);
    }
}