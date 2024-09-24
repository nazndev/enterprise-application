package com.nazndev.abacauthservice;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class GeneratePasswordHash {

    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        // To generate a password hash
        String rawPassword = "guest";
        String encodedPassword = encoder.encode(rawPassword);
        System.out.println("Encoded password: " + encodedPassword);

        // Replace "your_stored_password_hash_here" with the actual hash from the database
        String storedPasswordHash = "$2a$10$JRTlkxCfXI1X4LgSQafKve5eQJJg6TqzGkaJfxFFTC/bhgzC6iuTa";
        boolean matches = encoder.matches(rawPassword, storedPasswordHash);
        System.out.println("Password matches: " + matches);
    }
}
