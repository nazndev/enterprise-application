package com.nazndev.abacauthservice.dto;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;

@Data
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;

    @Value("${jwt.access-token-default-expiration}")
    private long defaultAccessTokenExpiration;

    @Value("${jwt.refresh-token-default-expiration}")
    private long defaultRefreshTokenExpiration;

    public TokenResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = defaultAccessTokenExpiration;  // Use injected expiration time
    }
}
