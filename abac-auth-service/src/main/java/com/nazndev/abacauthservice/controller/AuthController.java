    package com.nazndev.abacauthservice.controller;

    import com.nazndev.abacauthservice.dto.*;
    import com.nazndev.abacauthservice.entity.User;
    import com.nazndev.abacauthservice.exception.InvalidCredentialsException;
    import com.nazndev.abacauthservice.service.UserService;
    import com.nazndev.abacauthservice.util.JwtTokenUtil;
    import io.jsonwebtoken.Claims;
    import lombok.RequiredArgsConstructor;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.web.bind.annotation.*;

    @RestController
    @RequestMapping("/auth")
    @RequiredArgsConstructor
    public class AuthController {

        private final JwtTokenUtil jwtTokenUtil;
        private final UserService userService;
        private final BCryptPasswordEncoder passwordEncoder;

        @PostMapping("/token")
        public ApiResponse<TokenResponse> generateToken(@RequestBody LoginRequest loginRequest) {
            User user = userService.loadUserByUsername(loginRequest.getUsername());
            if (user == null || !passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
                throw new InvalidCredentialsException("Invalid username or password");
            }

            try {
                Claims claims = jwtTokenUtil.createClaims(user);
                String token = jwtTokenUtil.generateToken(claims, user.getUsername(), false); // false for access token
                return ApiResponse.success("Token generated successfully", new TokenResponse(token, null));
            } catch (Exception e) {
                throw new RuntimeException("Error generating token: " + e.getMessage(), e);
            }
        }

        @PostMapping("/refresh-token")
        public ApiResponse<TokenResponse> refreshToken(@RequestHeader("Authorization") String authHeader) {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new InvalidCredentialsException("Invalid or missing Authorization header");
            }

            String token = authHeader.substring(7); // Extract the token
            try {
                Claims claims = jwtTokenUtil.getClaimsFromToken(token);
                if (jwtTokenUtil.isTokenExpired(token)) {
                    throw new InvalidCredentialsException("Refresh token is expired");
                }

                String refreshedToken = jwtTokenUtil.generateToken(claims, claims.getSubject(), false);
                return ApiResponse.success("Token refreshed successfully", new TokenResponse(refreshedToken, null));
            } catch (Exception e) {
                throw new RuntimeException("Error refreshing token: " + e.getMessage(), e);
            }
        }

        @PostMapping("/change-password")
        public ApiResponse<Void> changePassword(@RequestBody ChangePasswordRequest request) {
            User currentUser = userService.loadUserByUsername(request.getCurrentUsername());
            boolean isAdmin = currentUser.getRoles().contains("ROLE_ADMIN");

            if (isAdmin) {
                User targetUser = userService.loadUserByUsername(request.getUsername());
                if (targetUser == null) {
                    throw new InvalidCredentialsException("User not found");
                }
                userService.changePassword(targetUser.getUsername(), request.getOldPassword(), request.getNewPassword());
            } else {
                if (!currentUser.getUsername().equals(request.getUsername())) {
                    throw new InvalidCredentialsException("You can only change your own password");
                }
                userService.changePassword(currentUser.getUsername(), request.getOldPassword(), request.getNewPassword());
            }

            return ApiResponse.success("Password changed successfully", null);
        }

        @PostMapping("/validate-token")
        public ApiResponse<ValidateTokenResponse> validateToken(@RequestBody ValidateTokenRequest request) {
            String token = request.getToken();
            boolean isValid = false;
            try {
                isValid = !jwtTokenUtil.isTokenExpired(token);
                jwtTokenUtil.getClaimsFromToken(token);
            } catch (Exception e) {
                isValid = false;
            }
            return ApiResponse.success("Token validation completed", new ValidateTokenResponse(isValid));
        }
    }
