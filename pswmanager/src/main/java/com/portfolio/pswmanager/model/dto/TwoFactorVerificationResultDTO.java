package com.portfolio.pswmanager.model.dto;

import javax.crypto.SecretKey;

public class TwoFactorVerificationResultDTO {
    public enum Status { SUCCESS, INVALID_CODE, INVALID_FORMAT, ERROR }

    private final Status status;
    private final SecretKey aesKey;
    private final String warningMessage;
    private final String errorMessage;

    private TwoFactorVerificationResultDTO(Status status, SecretKey aesKey,
                                           String warningMessage, String errorMessage) {
        this.status = status;
        this.aesKey = aesKey;
        this.warningMessage = warningMessage;
        this.errorMessage = errorMessage;
    }

    public static TwoFactorVerificationResultDTO success(
            SecretKey aesKey, String warningMessage) {
        return new TwoFactorVerificationResultDTO(Status.SUCCESS,
                aesKey, warningMessage, null);
    }

    public static TwoFactorVerificationResultDTO invalidCode() {
        return new TwoFactorVerificationResultDTO(Status.INVALID_CODE,
                null, null, null);
    }

    public static TwoFactorVerificationResultDTO invalidFormat() {
        return new TwoFactorVerificationResultDTO(Status.INVALID_FORMAT,
                null, null, null);
    }

    public static TwoFactorVerificationResultDTO error(String errorMessage) {
        return new TwoFactorVerificationResultDTO(Status.ERROR,
                null, null, errorMessage);
    }

    public Status getStatus() { return status; }
    public SecretKey getAesKey() { return aesKey; }
    public String getWarningMessage() { return warningMessage; }
    public String getErrorMessage() { return errorMessage; }
}
