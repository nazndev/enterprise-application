package com.nazndev.abacauthservice.util;

import com.nazndev.abacauthservice.entity.RSAKey;
import com.nazndev.abacauthservice.entity.User;
import com.nazndev.abacauthservice.entity.Role;
import com.nazndev.abacauthservice.service.RSAKeyService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtTokenUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);

    private final RSAKeyService rsaKeyService;

    @Getter
    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Getter
    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public String generateToken(Map<String, Object> claims, String subject, boolean isRefreshToken) {
        try {
            logger.debug("Generating token for subject: {}", subject);
            RSAKey rsaKey = rsaKeyService.getActiveKey()
                    .orElseThrow(() -> new IllegalStateException("No active RSA key found"));

            PrivateKey privateKey = rsaKeyService.getPrivateKey(rsaKey.getPrivateKey());
            long expirationTime = isRefreshToken ? refreshTokenExpiration : accessTokenExpiration;

            // Ensure the token is generated with the active private key
            String token = Jwts.builder()
                    .setClaims(claims)
                    .setSubject(subject)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                    .signWith(privateKey, SignatureAlgorithm.RS256)
                    .compact();

            logger.debug("Token generated successfully for subject: {} with key ID: {}", subject, rsaKey.getKeyId());
            return token;
        } catch (Exception e) {
            logger.error("Error generating token for subject: {}: {}", subject, e.getMessage(), e);
            throw new RuntimeException("Error generating token: " + e.getMessage(), e);
        }
    }

    public Claims getClaimsFromToken(String token) {
        try {
            logger.debug("Getting claims from token");
            RSAKey rsaKey = rsaKeyService.getActiveKey()
                    .orElseThrow(() -> new IllegalStateException("No active RSA key found"));

            PublicKey publicKey = rsaKeyService.getPublicKey(rsaKey.getPublicKey());
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            logger.debug("Claims extracted successfully from token using key ID: {}", rsaKey.getKeyId());
            return claims;
        } catch (Exception e) {
            logger.error("Error extracting claims from token: {}", e.getMessage(), e);
            throw new RuntimeException("Error extracting claims from token: " + e.getMessage(), e);
        }
    }

    public Claims createClaims(User user) {
        try {
            logger.debug("Creating claims for user: {}", user.getUsername());
            Claims claims = Jwts.claims();

            // Add the username directly
            claims.put("username", user.getUsername());

            // Map roles to their names only to avoid deep nesting or circular references
            claims.put("roles", user.getRoles().stream().map(Role::getName).toList());

            // Flatten the attributes map to avoid potential issues during serialization
            Map<String, String> flatPermissions = user.getAttributes().entrySet().stream()
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            claims.put("permissions", flatPermissions);

            logger.debug("Claims created successfully for user: {}", user.getUsername());
            return claims;
        } catch (Exception e) {
            logger.error("Error creating claims for user: {}: {}", user.getUsername(), e.getMessage(), e);
            throw new RuntimeException("Error creating claims for user: " + e.getMessage(), e);
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            logger.debug("Checking if token is expired");
            Claims claims = getClaimsFromToken(token);
            Date expiration = claims.getExpiration();
            boolean isExpired = expiration.before(new Date());
            logger.debug("Token expired: {}", isExpired);
            return isExpired;
        } catch (Exception e) {
            logger.error("Error checking if token is expired: {}", e.getMessage(), e);
            throw new RuntimeException("Error checking if token is expired: " + e.getMessage(), e);
        }
    }
}
