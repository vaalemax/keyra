package com.portfolio.pswmanager.model.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PasswordGenerationRequestDTO {
    @Min(value = 8, message = "Length must be at least 8")
    @Max(value = 128, message = "Length must not exceed 128")
    private int length = 16;
    private boolean useUppercase = true;
    private boolean useLowercase = true;
    private boolean useDigits = true;
    private boolean useSymbols = false;
    private boolean noAmbiguous = true;

}