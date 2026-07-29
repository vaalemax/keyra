package com.portfolio.keyra.service;

import com.portfolio.keyra.model.User;
import com.portfolio.keyra.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
public class SessionService {
    private final UserRepository userRepository;

    public SessionService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User getCurrentUser(Authentication authentication){
        String username = authentication.getName();
        return userRepository.findByUsername(username).orElseThrow(() ->
                new RuntimeException("User not found"));
    }

    public SecretKey getAesKeyFromSession(HttpSession session){
        SecretKey aesKey = (SecretKey) session.getAttribute("AES_KEY");
        if(aesKey==null)
            throw new RuntimeException("AES key not found. Try logging in again.");
        return aesKey;
    }
}
