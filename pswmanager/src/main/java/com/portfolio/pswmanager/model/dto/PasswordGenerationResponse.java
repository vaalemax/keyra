package com.portfolio.pswmanager.model.dto;

import lombok.Getter;

@Getter
public class PasswordGenerationResponse {
    private final String password;
    private final int length;

    public PasswordGenerationResponse(String password, int length) {
        this.password = password;
        this.length = length;
    }

}