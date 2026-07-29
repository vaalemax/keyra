package com.portfolio.keyra.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ValidationService {

    private static final Logger log = LoggerFactory.getLogger(ValidationService.class);

    public List<String> validateMasterPassword(String password) {
        log.debug("Validating master password (length: {} chars)",
                password != null ? password.length() : 0);

        List<String> errors = new ArrayList<>();

        if (password == null || password.isEmpty()) {
            errors.add("Password is required");
            log.debug("Master password validation failed: password is null or empty");
            return errors;
        }

        if (password.length() < 8)
            errors.add("must be at least 8 characters");
        if (!password.matches(".*[A-Z].*"))
            errors.add("must contain at least one uppercase letter");
        if (!password.matches(".*[a-z].*"))
            errors.add("must contain at least one lowercase letter");
        if (!password.matches(".*[0-9].*"))
            errors.add("must contain at least one number");
        if (!password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*"))
            errors.add("must contain at least one special character");

        if (!errors.isEmpty())
            log.debug("Master password validation failed: {}", String.join(", ", errors));

        return errors;
    }

    public boolean isPasswordSecure(String password) {
        boolean isSecure = password != null && password.length() >= 12;

        log.trace("Password security check: {} (length: {})",
                isSecure ? "SECURE" : "WEAK",
                password != null ? password.length() : 0);

        return isSecure;
    }

    public void validateCredentialPassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }
        validatePasswordComplexity(password);
    }

    public void validateCredentialPasswordIfPresent(String password) {
        if (password == null || password.trim().isEmpty()) {
            return;
        }
        validatePasswordComplexity(password);
    }

    private void validatePasswordComplexity(String password) {
        if (password.length() < 8)
            throw new IllegalArgumentException("Password must be at least 8 characters");

        if (password.length() > 256)
            throw new IllegalArgumentException("Password must not exceed 256 characters");
    }


}