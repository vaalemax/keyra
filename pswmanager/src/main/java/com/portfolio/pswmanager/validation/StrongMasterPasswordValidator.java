package com.portfolio.pswmanager.validation;

import com.portfolio.pswmanager.service.ValidationService;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

/**
 * Validator that delegates logic to ValidationService.
 */
public class StrongMasterPasswordValidator implements ConstraintValidator<StrongMasterPassword, String> {

    @Autowired
    private ValidationService validationService;

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isEmpty()) {
            return true; // @NotBlank handles nulls
        }

        List<String> errors = validationService.validateMasterPassword(password);

        if (!errors.isEmpty()) {
            // disable default message
            context.disableDefaultConstraintViolation();

            // add all errors
            String errorMessage = "Master password " + String.join(", ", errors);
            context.buildConstraintViolationWithTemplate(errorMessage).addConstraintViolation();

            return false;
        }

        return true;
    }
}