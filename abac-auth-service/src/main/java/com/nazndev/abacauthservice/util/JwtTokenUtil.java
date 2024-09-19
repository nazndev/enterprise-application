package com.nazndev.abacauthservice.util;

import com.nazndev.abacauthservice.entity.RSAKey;
import com.nazndev.abacauthservice.service.RSAKeyService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtTokenUtil {

    private final RSAKeyService rsaKeyService;

    public String generateToken(Map<String, Object> claims, String subject) throws Exception {
        RSAKey rsaKey = rsaKeyService.getActiveKey()
                .orElseThrow(() -> new IllegalStateException("No active RSA key found"));

        PrivateKey privateKey = rsaKeyService.getPrivateKey(rsaKey.getPrivateKey());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours
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
}
