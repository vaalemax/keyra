package com.portfolio.pswmanager.service;

import com.portfolio.pswmanager.model.User;
import com.portfolio.pswmanager.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
@RequiredArgsConstructor
public class SessionService {
    private final UserRepository userRepository;

    public User getCurrentUser(Authentication authentication){
        String username = authentication.getName();
        return userRepository.findByUsername(username).orElseThrow(() ->
                new RuntimeException("User not found"));
    }

    public SecretKey getAesKeyFromSession(HttpSession session){
        SecretKey aesKey = (SecretKey) session.getAttribute("AES_KEY");
        if(aesKey==null){
            throw new RuntimeException("AES key not found. Try logging in again.");
        }
        return aesKey;
    }
}
