package com.portfolio.keyra.service;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class PasswordGeneratorService {

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    private static final String AMBIGUOUS_CHARS = "Il1O0";

    private final SecureRandom secureRandom = new SecureRandom();

    public String generatePassword(int length, boolean useUppercase, boolean useLowercase,
                                   boolean useDigits, boolean useSymbols, boolean noAmbiguous) {
        validateParameters(length, useUppercase, useLowercase, useDigits, useSymbols);

        StringBuilder charset = new StringBuilder();
        List<String> requiredPools = new ArrayList<>();

        if (useUppercase) {
            String upper = noAmbiguous ? removeAmbiguous(UPPERCASE) : UPPERCASE;
            charset.append(upper);
            requiredPools.add(upper);
        }
        if (useLowercase) {
            String lower = noAmbiguous ? removeAmbiguous(LOWERCASE) : LOWERCASE;
            charset.append(lower);
            requiredPools.add(lower);
        }
        if (useDigits) {
            String digits = noAmbiguous ? removeAmbiguous(DIGITS) : DIGITS;
            charset.append(digits);
            requiredPools.add(digits);
        }
        if (useSymbols) {
            charset.append(SYMBOLS);
            requiredPools.add(SYMBOLS);
        }

        return buildPassword(length, charset.toString(), requiredPools);
    }

    private String buildPassword(int length, String charset, List<String> requiredPools) {
        List<Character> password = new ArrayList<>();

        for (String pool : requiredPools) {
            password.add(pool.charAt(secureRandom.nextInt(pool.length())));
        }

        while (password.size() < length) {
            password.add(charset.charAt(secureRandom.nextInt(charset.length())));
        }

        for (int i = password.size() - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            Collections.swap(password, i, j);
        }

        StringBuilder result = new StringBuilder(length);
        for (Character c : password) {
            result.append(c);
        }

        return result.toString();
    }

    private String removeAmbiguous(String input) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (AMBIGUOUS_CHARS.indexOf(c) == -1) {
                result.append(c);
            }
        }
        return result.toString();
    }

    private void validateParameters(
            int length,
            boolean useUppercase,
            boolean useLowercase,
            boolean useDigits,
            boolean useSymbols
    ) {
        if (length < 8) {
            throw new IllegalArgumentException("The minimum length is 8 characters");
        }
        if (length > 128) {
            throw new IllegalArgumentException("The maximum length is 128 characters");
        }
        if (!useUppercase && !useLowercase && !useDigits && !useSymbols) {
            throw new IllegalArgumentException("Select at least one character type");
        }
    }
}
