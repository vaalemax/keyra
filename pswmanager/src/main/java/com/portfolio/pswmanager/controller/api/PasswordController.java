package com.portfolio.pswmanager.controller.api;

import com.portfolio.pswmanager.model.dto.ErrorResponse;
import com.portfolio.pswmanager.model.dto.PasswordGenerationRequest;
import com.portfolio.pswmanager.model.dto.PasswordGenerationResponse;
import com.portfolio.pswmanager.service.PasswordGeneratorService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/password")
@RequiredArgsConstructor
public class PasswordController {

    private final PasswordGeneratorService passwordGeneratorService;
    private static final Logger log = LoggerFactory.getLogger(PasswordController.class);


    @PostMapping("/generate")
    public ResponseEntity<?> generatePassword(@RequestBody PasswordGenerationRequest request) {
        log.debug("Password generation request - length: {}, uppercase: {}, lowercase: {}, digits: {}, symbols: {}",
                request.getLength(), request.isUseUppercase(), request.isUseLowercase(),
                request.isUseDigits(), request.isUseSymbols());

        try {
            String password = passwordGeneratorService.generatePassword(
                    request.getLength(),
                    request.isUseUppercase(),
                    request.isUseLowercase(),
                    request.isUseDigits(),
                    request.isUseSymbols(),
                    request.isNoAmbiguous()
            );
            log.info("Password generated successfully - length: {}", password.length());

            return ResponseEntity.ok(new PasswordGenerationResponse(password, password.length()));

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