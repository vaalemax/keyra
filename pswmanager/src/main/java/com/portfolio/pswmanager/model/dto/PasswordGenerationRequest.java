package com.portfolio.pswmanager.model.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PasswordGenerationRequest {
    private int length = 16;
    private boolean useUppercase = true;
    private boolean useLowercase = true;
    private boolean useDigits = true;
    private boolean useSymbols = false;
    private boolean noAmbiguous = true;

}