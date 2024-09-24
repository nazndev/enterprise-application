package com.nazndev.abacauthservice.service;

import com.nazndev.abacauthservice.entity.User;
import com.nazndev.abacauthservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public User loadUserByUsername(String username) {
        logger.debug("Loading user by username: {}", username);
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isEmpty()) {
            logger.warn("User not found for username: {}", username);
        } else {
            logger.debug("User found: {}", user.get());
            logger.debug("Encoded password: {}", user.get().getPassword());
        }
        return user.orElse(null);
    }

    public void changePassword(String username, String oldPassword, String newPassword) {
        logger.debug("Changing password for user: {}", username);
        User user = loadUserByUsername(username);
        if (user != null && passwordEncoder.matches(oldPassword, user.getPassword())) {
            logger.debug("Old password matches for user: {}", username);
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
            logger.info("Password changed successfully for user: {}", username);
        } else {
            logger.error("Invalid old password for user: {}", username);
            throw new IllegalArgumentException("Invalid old password");
        }
    }

    public List<User> getAllUsers() {
        logger.debug("Fetching all users");
        return userRepository.findAll();
    }

    public Optional<User> getUserById(Long id) {
        logger.debug("Fetching user by ID: {}", id);
        return userRepository.findById(id);
    }

    public User createUser(User user) {
        logger.debug("Creating new user: {}", user.getUsername());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User createdUser = userRepository.save(user);
        logger.info("User created successfully: {}", user.getUsername());
        return createdUser;
    }

    public User updateUser(Long id, User userDetails) {
        logger.debug("Updating user with ID: {}", id);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setUsername(userDetails.getUsername());
        user.setPassword(passwordEncoder.encode(userDetails.getPassword()));
        user.setRoles(userDetails.getRoles());
        user.setAttributes(userDetails.getAttributes());
        User updatedUser = userRepository.save(user);
        logger.info("User updated successfully: {}", user.getUsername());
        return updatedUser;
    }

    public void deleteUser(Long id) {
        logger.debug("Deleting user with ID: {}", id);
        userRepository.deleteById(id);
        logger.info("User deleted successfully with ID: {}", id);
    }
}
