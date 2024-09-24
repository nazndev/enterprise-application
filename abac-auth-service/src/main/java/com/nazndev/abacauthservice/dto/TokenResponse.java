package com.nazndev.abacauthservice.dto;

import lombok.Data;

@Data
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
    private long expiresIn;
    private long defaultAccessTokenExpiration;
    private long defaultRefreshTokenExpiration;

    public TokenResponse(String accessToken, String refreshToken, long expiresIn, long defaultAccessTokenExpiration, long defaultRefreshTokenExpiration) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.defaultAccessTokenExpiration = defaultAccessTokenExpiration;
        this.defaultRefreshTokenExpiration = defaultRefreshTokenExpiration;
    }
}
