package com.nazndev.abacauthservice.controller;

import com.nazndev.abacauthservice.dto.*;
import com.nazndev.abacauthservice.entity.User;
import com.nazndev.abacauthservice.exception.InvalidCredentialsException;
import com.nazndev.abacauthservice.service.UserService;
import com.nazndev.abacauthservice.util.JwtTokenUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final JwtTokenUtil jwtTokenUtil;
    private final UserService userService;
    private final BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/token")
    public ApiResponse<TokenResponse> generateToken(@RequestBody LoginRequest loginRequest) {
        logger.debug("Attempting to generate token for user: {}", loginRequest.getUsername());

        // Step 1: Check if user exists
        User user = userService.loadUserByUsername(loginRequest.getUsername());
        if (user == null) {
            logger.error("User not found: {}", loginRequest.getUsername());
            throw new InvalidCredentialsException("Invalid username or password");
        }

        logger.debug("User found: {}", user.getUsername());

        // Step 2: Check password
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            logger.error("Password mismatch for user: {}", loginRequest.getUsername());
            throw new InvalidCredentialsException("Invalid username or password");
        }

        logger.debug("Password matches for user: {}", loginRequest.getUsername());

        // Step 3: Generate token
        try {
            Claims claims = jwtTokenUtil.createClaims(user);
            String token = jwtTokenUtil.generateToken(claims, user.getUsername(), false);
            logger.info("Token generated successfully for user: {}", loginRequest.getUsername());
            return ApiResponse.success("Token generated successfully", new TokenResponse(token, null, jwtTokenUtil.getAccessTokenExpiration() / 1000, jwtTokenUtil.getAccessTokenExpiration(), jwtTokenUtil.getRefreshTokenExpiration()));
        } catch (Exception e) {
            logger.error("Error generating token for user: {}: {}", loginRequest.getUsername(), e.getMessage());
            throw new RuntimeException("Error generating token: " + e.getMessage(), e);
        }
    }


    @PostMapping("/refresh-token")
    public ApiResponse<TokenResponse> refreshToken(@RequestHeader("Authorization") String authHeader) {
        logger.debug("Refreshing token");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.error("Invalid or missing Authorization header");
            throw new InvalidCredentialsException("Invalid or missing Authorization header");
        }

        String token = authHeader.substring(7); // Extract the token
        try {
            Claims claims = jwtTokenUtil.getClaimsFromToken(token);
            if (jwtTokenUtil.isTokenExpired(token)) {
                logger.warn("Refresh token is expired");
                throw new InvalidCredentialsException("Refresh token is expired");
            }

            String refreshedToken = jwtTokenUtil.generateToken(claims, claims.getSubject(), false);
            long expiresIn = jwtTokenUtil.getAccessTokenExpiration() / 1000; // Convert to seconds
            logger.info("Token refreshed successfully");
            return ApiResponse.success("Token refreshed successfully", new TokenResponse(refreshedToken, null, expiresIn, jwtTokenUtil.getAccessTokenExpiration(), jwtTokenUtil.getRefreshTokenExpiration()));
        } catch (Exception e) {
            logger.error("Error refreshing token: {}", e.getMessage());
            throw new RuntimeException("Error refreshing token: " + e.getMessage(), e);
        }
    }

    @PostMapping("/change-password")
    public ApiResponse<Void> changePassword(@RequestBody ChangePasswordRequest request) {
        logger.debug("Changing password for user: {}", request.getUsername());
        User currentUser = userService.loadUserByUsername(request.getCurrentUsername());
        boolean isAdmin = currentUser.getRoles().stream().anyMatch(role -> role.getName().equals("ADMIN"));

        if (isAdmin) {
            logger.debug("Admin user changing password for user: {}", request.getUsername());
            User targetUser = userService.loadUserByUsername(request.getUsername());
            if (targetUser == null) {
                logger.error("User not found: {}", request.getUsername());
                throw new InvalidCredentialsException("User not found");
            }
            userService.changePassword(targetUser.getUsername(), request.getOldPassword(), request.getNewPassword());
        } else {
            if (!currentUser.getUsername().equals(request.getUsername())) {
                logger.error("User: {} attempting to change another user's password", request.getCurrentUsername());
                throw new InvalidCredentialsException("You can only change your own password");
            }
            userService.changePassword(currentUser.getUsername(), request.getOldPassword(), request.getNewPassword());
        }

        logger.info("Password changed successfully for user: {}", request.getUsername());
        return ApiResponse.success("Password changed successfully", null);
    }

    @PostMapping("/validate-token")
    public ApiResponse<ValidateTokenResponse> validateToken(@RequestBody ValidateTokenRequest request) {
        logger.debug("Validating token");
        String token = request.getToken();
        boolean isValid = false;
        try {
            isValid = !jwtTokenUtil.isTokenExpired(token);
            jwtTokenUtil.getClaimsFromToken(token);
            logger.info("Token validation successful");
        } catch (Exception e) {
            logger.warn("Token validation failed: {}", e.getMessage());
            isValid = false;
        }
        return ApiResponse.success("Token validation completed", new ValidateTokenResponse(isValid));
    }
}
