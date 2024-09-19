package com.nazndev.abacauthservice.controller;

import com.nazndev.abacauthservice.entity.User;
import com.nazndev.abacauthservice.service.UserService;
import com.nazndev.abacauthservice.util.JwtTokenUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtTokenUtil jwtTokenUtil;
    private final UserService userService;
    private final BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/token")
    public Map<String, String> generateToken(@RequestParam String username, @RequestParam String password) throws Exception {
        User user = userService.loadUserByUsername(username);
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("Invalid username or password");
        }

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", user.getRoles());

        String token = jwtTokenUtil.generateToken(claims, username);
        return Map.of("token", token);
    }

    @PostMapping("/refresh-token")
    public Map<String, String> refreshToken(@RequestParam String token) throws Exception {
        Claims claims = jwtTokenUtil.getClaimsFromToken(token);
        String refreshedToken = jwtTokenUtil.generateToken(claims, claims.getSubject());
        return Map.of("token", refreshedToken);
    }

    @PostMapping("/change-password")
    public void changePassword(@RequestParam String username, @RequestParam String oldPassword, @RequestParam String newPassword) {
        userService.changePassword(username, oldPassword, newPassword);
    }

    @PostMapping("/validate-token")
    public Map<String, Boolean> validateToken(@RequestParam String token) {
        try {
            jwtTokenUtil.getClaimsFromToken(token);
            return Map.of("isValid", true);
        } catch (Exception e) {
            return Map.of("isValid", false);
        }
    }
}
