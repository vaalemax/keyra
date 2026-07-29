package com.portfolio.keyra.controller.api;

import com.portfolio.keyra.model.dto.ErrorResponse;
import com.portfolio.keyra.model.dto.PasswordGenerationRequestDTO;
import com.portfolio.keyra.model.dto.PasswordGenerationResponseDTO;
import com.portfolio.keyra.service.PasswordGeneratorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/password")
public class PasswordController {

    private final PasswordGeneratorService passwordGeneratorService;

    private static final Logger log = LoggerFactory.getLogger(PasswordController.class);

    public PasswordController(PasswordGeneratorService passwordGeneratorService) {
        this.passwordGeneratorService = passwordGeneratorService;
    }

    @PostMapping("/generate")
    public ResponseEntity<?> generatePassword(@RequestBody PasswordGenerationRequestDTO request) {
        try {
            String password = passwordGeneratorService.generatePassword(
                    request.getLength(),
                    request.isUseUppercase(),
                    request.isUseLowercase(),
                    request.isUseDigits(),
                    request.isUseSymbols(),
                    request.isNoAmbiguous()
            );
            return ResponseEntity.ok(new PasswordGenerationResponseDTO(password, password.length()));
        } catch (IllegalArgumentException e) {
            log.warn("Password generation failed - validation error: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new ErrorResponse(e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during password generation", e);
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Internal server error"));
        }
    }
}