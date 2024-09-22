package com.nazndev.abacauthservice.util;

import com.nazndev.abacauthservice.entity.RSAKey;
import com.nazndev.abacauthservice.entity.User;
import com.nazndev.abacauthservice.service.RSAKeyService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtTokenUtil {

    private final RSAKeyService rsaKeyService;

    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public String generateToken(Map<String, Object> claims, String subject, boolean isRefreshToken) throws Exception {
        RSAKey rsaKey = rsaKeyService.getActiveKey()
                .orElseThrow(() -> new IllegalStateException("No active RSA key found"));

        PrivateKey privateKey = rsaKeyService.getPrivateKey(rsaKey.getPrivateKey());
        long expirationTime = isRefreshToken ? refreshTokenExpiration : accessTokenExpiration;

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public Claims getClaimsFromToken(String token) throws Exception {
        RSAKey rsaKey = rsaKeyService.getActiveKey()
                .orElseThrow(() -> new IllegalStateException("No active RSA key found"));

        PublicKey publicKey = rsaKeyService.getPublicKey(rsaKey.getPublicKey());
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Claims createClaims(User user) {
        Claims claims = Jwts.claims();
        claims.put("roles", user.getRoles());
        claims.put("username", user.getUsername());
        claims.put("permissions", user.getAttributes());
        return claims;
    }

    public boolean isTokenExpired(String token) throws Exception {
        Claims claims = getClaimsFromToken(token);
        Date expiration = claims.getExpiration();
        return expiration.before(new Date());
    }
}
