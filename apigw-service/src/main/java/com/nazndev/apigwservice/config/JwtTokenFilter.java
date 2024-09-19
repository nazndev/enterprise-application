package com.nazndev.apigwservice.config;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URL;
import java.text.ParseException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
public class JwtTokenFilter implements GlobalFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);

    private final RemoteJWKSet remoteJWKSet;
    private final ConfigurableJWTProcessor jwtProcessor;
    private final StringRedisTemplate redisTemplate;  // Redis template to store blacklisted tokens

    public JwtTokenFilter(@Value("${jwt.jwksUri}") String jwksUri, StringRedisTemplate redisTemplate) throws Exception {
        this.remoteJWKSet = new RemoteJWKSet(new URL(jwksUri));
        this.jwtProcessor = new DefaultJWTProcessor();
        this.jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(com.nimbusds.jose.JWSAlgorithm.RS256, remoteJWKSet));
        this.redisTemplate = redisTemplate; // Inject Redis template
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.warn("Missing or invalid Authorization header");
            return handleUnauthorized(exchange, "Missing or invalid Authorization header");
        }

        String token = authHeader.replace("Bearer ", "");

        try {
            // Check if the token is blacklisted
            if (isTokenBlacklisted(token)) {
                logger.warn("Blacklisted JWT token");
                return handleUnauthorized(exchange, "Blacklisted JWT token");
            }

            if (!validateToken(token)) {
                logger.warn("Invalid JWT token");
                return handleUnauthorized(exchange, "Invalid JWT token");
            }
        } catch (Exception e) {
            logger.error("Error during JWT validation: {}", e.getMessage());
            return handleUnauthorized(exchange, "JWT validation error");
        }

        return chain.filter(exchange);
    }

    private boolean validateToken(String token) throws Exception {
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Validate signature and token
        jwtProcessor.process(signedJWT, null);

        // Explicitly check token expiration
        if (isTokenExpired(signedJWT)) {
            logger.warn("JWT token is expired");
            return false;
        }

        // Add logic for token blacklisting (optional)
        return true;
    }

    private boolean isTokenExpired(SignedJWT signedJWT) throws ParseException {
        Date expirationDate = signedJWT.getJWTClaimsSet().getExpirationTime();
        return expirationDate != null && expirationDate.before(new Date());
    }

    private boolean isTokenBlacklisted(String token) {
        // Check Redis for the token's existence
        Boolean isBlacklisted = redisTemplate.hasKey("blacklist:" + token);
        return isBlacklisted != null && isBlacklisted;
    }

    private void blacklistToken(String token, Date expiration) {
        // Calculate token TTL based on its expiration date
        long ttl = expiration.getTime() - System.currentTimeMillis();
        if (ttl > 0) {
            // Store the token in Redis with a TTL equal to its remaining lifespan
            redisTemplate.opsForValue().set("blacklist:" + token, "true", ttl, TimeUnit.MILLISECONDS);
        }
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        logger.warn("Unauthorized access attempt: {}", message);
        return exchange.getResponse().setComplete();
    }
}
