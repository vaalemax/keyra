package com.portfolio.pswmanager.model;

import javax.crypto.SecretKey;

public class TwoFactorVerificationResult {
    public enum Status { SUCCESS, INVALID_CODE, INVALID_FORMAT, ERROR }

    private final Status status;
    private final SecretKey aesKey;
    private final String warningMessage;
    private final String errorMessage;

    private TwoFactorVerificationResult(Status status, SecretKey aesKey,
                                        String warningMessage, String errorMessage) {
        this.status = status;
        this.aesKey = aesKey;
        this.warningMessage = warningMessage;
        this.errorMessage = errorMessage;
    }

    public static TwoFactorVerificationResult success(
            SecretKey aesKey, String warningMessage) {
        return new TwoFactorVerificationResult(Status.SUCCESS,
                aesKey, warningMessage, null);
    }

    public static TwoFactorVerificationResult invalidCode() {
        return new TwoFactorVerificationResult(Status.INVALID_CODE,
                null, null, null);
    }

    public static TwoFactorVerificationResult invalidFormat() {
        return new TwoFactorVerificationResult(Status.INVALID_FORMAT,
                null, null, null);
    }

    public static TwoFactorVerificationResult error(String errorMessage) {
        return new TwoFactorVerificationResult(Status.ERROR,
                null, null, errorMessage);
    }

    public Status getStatus() { return status; }
    public SecretKey getAesKey() { return aesKey; }
    public String getWarningMessage() { return warningMessage; }
    public String getErrorMessage() { return errorMessage; }
}
