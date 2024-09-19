package com.nazndev.abacauthservice.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor
public class RSAKeyRotationService {

    private static final Logger logger = LoggerFactory.getLogger(RSAKeyRotationService.class);
    private final RSAKeyService rsaKeyService;

    // Rotate RSA keys daily at 3 AM
    @Scheduled(cron = "0 0 3 * * ?")
    public void rotateRSAKeys() {
        try {
            rsaKeyService.generateAndStoreRSAKey();
            logger.info("RSA key pair rotated successfully.");
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to rotate RSA key pair: {}", e.getMessage(), e);
        }
    }
}
