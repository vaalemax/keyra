package com.portfolio.pswmanager.model.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class PasswordChangeRequestDTO {

    @NotBlank(message = "Current password is required")
    private String currentPassword;

    @NotBlank(message = "New password is required")
    @Size(min = 8, message = "New password must be at least 8 characters")
    private String newPassword;

    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;

    @AssertTrue(message = "Passwords do not match")
    private boolean isPasswordConfirmed() {
        return newPassword == null || newPassword.equals(confirmPassword);
    }
}