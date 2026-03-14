package com.portfolio.pswmanager.validation;

import com.portfolio.pswmanager.service.ValidationService;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class StrongMasterPasswordValidator implements ConstraintValidator<StrongMasterPassword, String> {

    @Autowired
    private ValidationService validationService;

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isEmpty()) {
            return true;
        }

        List<String> errors = validationService.validateMasterPassword(password);

        if (!errors.isEmpty()) {
            context.disableDefaultConstraintViolation();

            String errorMessage = "Master password " + String.join(", ", errors);
            context.buildConstraintViolationWithTemplate(errorMessage).addConstraintViolation();

            return false;
        }

        return true;
    }
}