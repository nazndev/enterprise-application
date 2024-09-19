package com.nazndev.abacauthservice.service;

import com.nazndev.abacauthservice.entity.User;
import com.nazndev.abacauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public User loadUserByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }

    public void changePassword(String username, String oldPassword, String newPassword) {
        User user = loadUserByUsername(username);
        if (user != null && passwordEncoder.matches(oldPassword, user.getPassword())) {
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
        } else {
            throw new IllegalArgumentException("Invalid old password");
        }
    }
}
