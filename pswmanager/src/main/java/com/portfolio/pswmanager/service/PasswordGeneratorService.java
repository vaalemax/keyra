package com.portfolio.pswmanager.service;

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

    /**
     * Genera una password sicura con i parametri specificati.
     *
     * @param length Lunghezza password (min 8, max 128)
     * @param useUppercase Includi maiuscole
     * @param useLowercase Includi minuscole
     * @param useDigits Includi numeri
     * @param useSymbols Includi simboli
     * @param noAmbiguous Escludi caratteri ambigui (I,l,1,O,0)
     * @return Password generata
     * @throws IllegalArgumentException se parametri non validi
     */
    public String generatePassword(int length, boolean useUppercase, boolean useLowercase, boolean useDigits, boolean useSymbols, boolean noAmbiguous) {
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

        // 1. Aggiungi un carattere da ogni pool richiesto
        for (String pool : requiredPools) {
            password.add(pool.charAt(secureRandom.nextInt(pool.length())));
        }

        // 2. Riempi il resto con caratteri casuali dal charset completo
        while (password.size() < length) {
            password.add(charset.charAt(secureRandom.nextInt(charset.length())));
        }

        // 3. Shuffle (Fisher-Yates)
        for (int i = password.size() - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            Collections.swap(password, i, j);
        }

        // 4. Converti in String
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
